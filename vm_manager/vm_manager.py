import os
import json
import time
import socket
import logging
import subprocess
import threading
import errno
from typing import Optional, Dict, List, Any, Callable
from dataclasses import dataclass, field
from enum import Enum

from .vm_config import VMConfig, VMArchitecture, AntiVMConfig, VMManagerConfig
from .qemu_launcher import QEMULauncher, QEMUProcess
from .snapshot import SnapshotManager

logger = logging.getLogger(__name__)


class VMState(Enum):
    STOPPED = "stopped"
    STARTING = "starting"
    RUNNING = "running"
    ANALYZING = "analyzing"
    RESTORING = "restoring"
    ERROR = "error"


@dataclass
class AnalysisResult:
    success: bool
    file_path: str
    architecture: str
    duration: float
    events: List[Dict[str, Any]] = field(default_factory=list)
    syscalls: List[Dict[str, Any]] = field(default_factory=list)
    network_activity: List[Dict[str, Any]] = field(default_factory=list)
    file_activity: List[Dict[str, Any]] = field(default_factory=list)
    process_activity: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    exit_code: Optional[int] = None


class VMManager:
    def __init__(self, config: Optional[VMManagerConfig] = None, config_path: Optional[str] = None):
        if config_path and os.path.exists(config_path):
            self.config = VMManagerConfig.from_yaml(config_path)
        elif config:
            self.config = config
        else:
            self.config = VMManagerConfig()
        
                               
        self.launcher = QEMULauncher(self.config.sockets_dir)
        self._snapshot_managers: Dict[str, SnapshotManager] = {}
        self._processes: Dict[str, QEMUProcess] = {}
        self._states: Dict[str, VMState] = {}
        
                            
        os.makedirs(self.config.images_dir, exist_ok=True)
        os.makedirs(self.config.sockets_dir, exist_ok=True)
        os.makedirs(self.config.logs_dir, exist_ok=True)
        
                            
        self._lock = threading.Lock()
        
                                               
        self._attach_existing_vms()
    
    def _attach_existing_vms(self):
        import glob
        import socket
        
        sockets_dir = self.config.sockets_dir
        
                         
        if self.config.arm64_config:
            current_pid = str(os.getpid())
            arm64_monitors = glob.glob(f"{sockets_dir}/sandbox_arm64_*_monitor.sock")
                                                                     
            arm64_monitors = [s for s in arm64_monitors if current_pid not in s]
            for monitor_sock in arm64_monitors:
                try:
                                                  
                    base = os.path.basename(monitor_sock)
                    pid = base.split('_')[2]
                    try:
                        os.kill(int(pid), 0)
                    except (OSError, ProcessLookupError):
                        continue
                    
                                        
                    agent_sock = f"{sockets_dir}/sandbox_arm64_{pid}_agent.sock"
                    serial_sock = f"{sockets_dir}/sandbox_arm64_{pid}_serial.sock"
                    
                    if os.path.exists(agent_sock):
                        try:
                            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                            sock.settimeout(2)
                            sock.connect(monitor_sock)
                            sock.close()
                        except OSError as e:
                            if getattr(e, "errno", None) != errno.EAGAIN:
                                raise
                                                            
                        from .qemu_launcher import QEMUProcess
                        process = QEMUProcess.from_existing(
                            pid=int(pid),
                            monitor_socket=monitor_sock,
                            serial_socket=serial_sock,
                            agent_socket=agent_sock
                        )
                        
                        vm_name = self.config.arm64_config.name
                        self._processes[vm_name] = process
                        self._snapshot_managers[vm_name] = SnapshotManager(monitor_sock)
                        self._states[vm_name] = VMState.RUNNING
                        logger.info(f"Attached to existing ARM64 VM (PID {pid})")
                        break
                except Exception as e:
                    logger.debug(f"Could not attach to {monitor_sock}: {e}")
        
                       
        if self.config.x64_config:
            x64_monitors = glob.glob(f"{sockets_dir}/sandbox_x64_*_monitor.sock")
                                                                     
            x64_monitors = [s for s in x64_monitors if current_pid not in s]
            for monitor_sock in x64_monitors:
                try:
                                                  
                    base = os.path.basename(monitor_sock)
                    pid = base.split('_')[2]
                    try:
                        os.kill(int(pid), 0)
                    except (OSError, ProcessLookupError):
                        continue
                    
                                        
                    agent_sock = f"{sockets_dir}/sandbox_x64_{pid}_agent.sock"
                    serial_sock = f"{sockets_dir}/sandbox_x64_{pid}_serial.sock"
                    
                    if os.path.exists(agent_sock):
                        try:
                            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                            sock.settimeout(2)
                            sock.connect(monitor_sock)
                            sock.close()
                        except OSError as e:
                            if getattr(e, "errno", None) != errno.EAGAIN:
                                raise
                        from .qemu_launcher import QEMUProcess
                        process = QEMUProcess.from_existing(
                            pid=int(pid),
                            monitor_socket=monitor_sock,
                            serial_socket=serial_sock,
                            agent_socket=agent_sock
                        )
                        
                        vm_name = self.config.x64_config.name
                        self._processes[vm_name] = process
                        self._snapshot_managers[vm_name] = SnapshotManager(monitor_sock)
                        self._states[vm_name] = VMState.RUNNING
                        logger.info(f"Attached to existing X64 VM (PID {pid})")
                        break
                except Exception as e:
                    logger.debug(f"Could not attach to {monitor_sock}: {e}")
    
    def get_vm_config(self, arch: VMArchitecture) -> Optional[VMConfig]:
        if arch == VMArchitecture.ARM64:
            return self.config.arm64_config
        elif arch == VMArchitecture.X64:
            return self.config.x64_config
        return None

    def _get_sockets(self, vm_name: str, vm_config: VMConfig) -> Dict[str, str]:
        process = self._processes.get(vm_name)
        if process and process.monitor_socket and process.serial_socket and process.agent_socket:
            return {'monitor': process.monitor_socket, 'serial': process.serial_socket, 'agent': process.agent_socket}
        return vm_config.get_socket_paths(self.config.sockets_dir)
    
    def start_vm(self, arch: VMArchitecture) -> bool:
        vm_config = self.get_vm_config(arch)
        if not vm_config:
            logger.error(f"No configuration for architecture: {arch}")
            return False
        
        vm_name = vm_config.name
        
        with self._lock:
            if vm_name in self._processes:
                if self._processes[vm_name].is_running():
                    logger.info(f"VM {vm_name} already running")
                    return True
        
        self._states[vm_name] = VMState.STARTING
        
        try:
            logger.info(f"Starting VM: {vm_name} ({arch.value})")
            
            process = self.launcher.launch(vm_config, self.config.anti_vm)
            
            with self._lock:
                self._processes[vm_name] = process
                self._snapshot_managers[vm_name] = SnapshotManager(process.monitor_socket)
            
                                     
            if self._wait_for_vm_ready(vm_name, vm_config.boot_timeout):
                self._states[vm_name] = VMState.RUNNING
                logger.info(f"VM {vm_name} is ready")
                return True
            else:
                self._states[vm_name] = VMState.ERROR
                logger.error(f"VM {vm_name} failed to become ready")
                return False
                
        except Exception as e:
            logger.error(f"Failed to start VM {vm_name}: {e}")
            self._states[vm_name] = VMState.ERROR
            return False
    
    def stop_vm(self, arch: VMArchitecture, force: bool = False):
        vm_config = self.get_vm_config(arch)
        if not vm_config:
            return
        
        vm_name = vm_config.name
        
        with self._lock:
            if vm_name in self._snapshot_managers:
                self._snapshot_managers[vm_name].close()
                del self._snapshot_managers[vm_name]
        
        self.launcher.stop(vm_name, force=force)
        
        with self._lock:
            if vm_name in self._processes:
                del self._processes[vm_name]
        
        self._states[vm_name] = VMState.STOPPED
        logger.info(f"VM {vm_name} stopped")
    
    def stop_all(self):
        for arch in VMArchitecture:
            self.stop_vm(arch, force=True)
    
    def is_running(self, arch: VMArchitecture) -> bool:
        vm_config = self.get_vm_config(arch)
        if not vm_config:
            return False
        process = self._processes.get(vm_config.name)
        if process:
            return process.is_running()
        return self.launcher.is_running(vm_config.name)
    
    def get_state(self, arch: VMArchitecture) -> VMState:
        vm_config = self.get_vm_config(arch)
        if not vm_config:
            return VMState.STOPPED
        return self._states.get(vm_config.name, VMState.STOPPED)
    
    def restore_snapshot(self, arch: VMArchitecture, snapshot_name: str = "clean") -> float:
        vm_config = self.get_vm_config(arch)
        if not vm_config:
            raise ValueError(f"No configuration for architecture: {arch}")
        
        vm_name = vm_config.name
        self._states[vm_name] = VMState.RESTORING
        
        try:
            with self._lock:
                sm = self._snapshot_managers.get(vm_name)
                if not sm:
                    raise RuntimeError(f"VM {vm_name} not running")
                
                                                         
                snapshot_exists = sm.snapshot_exists(snapshot_name) if hasattr(sm, 'snapshot_exists') else True
                
                                                     
                if not snapshot_exists:
                    logger.warning(f"Snapshot '{snapshot_name}' not found, creating initial snapshot...")
                    sm.create_snapshot(snapshot_name, "Auto-created clean state for analysis")
                    self._states[vm_name] = VMState.RUNNING
                    return 0.0                                   
                
                duration = sm.restore_snapshot(snapshot_name)
            
            self._states[vm_name] = VMState.RUNNING
            return duration
            
        except Exception as e:
            self._states[vm_name] = VMState.ERROR
            raise
    
    def create_snapshot(self, arch: VMArchitecture, snapshot_name: str, description: str = ""):
        vm_config = self.get_vm_config(arch)
        if not vm_config:
            raise ValueError(f"No configuration for architecture: {arch}")
        
        vm_name = vm_config.name
        
        with self._lock:
            sm = self._snapshot_managers.get(vm_name)
            if not sm:
                raise RuntimeError(f"VM {vm_name} not running")
            
            sm.create_snapshot(snapshot_name, description)
    
    def copy_to_guest(self, arch: VMArchitecture, local_path: str, guest_path: str) -> bool:
        vm_config = self.get_vm_config(arch)
        if not vm_config:
            return False
        
        vm_name = vm_config.name
        
        with self._lock:
            process = self._processes.get(vm_name)
            if not process:
                return False
        
        try:
                             
            with open(local_path, 'rb') as f:
                file_data = f.read()
            
                                   
            sockets = self._get_sockets(vm_name, vm_config)
            
            command = {
                'command': 'write_file',
                'path': guest_path,
                'data': file_data.hex(),                          
                'mode': 0o755
            }
            
            response = self._send_agent_command(sockets['agent'], command)
            return response.get('success', False)
            
        except Exception as e:
            logger.error(f"Failed to copy file to guest: {e}")
            return False
    
    def copy_from_guest(self, arch: VMArchitecture, guest_path: str, local_path: str) -> bool:
        vm_config = self.get_vm_config(arch)
        if not vm_config:
            return False
        
        vm_name = vm_config.name
        
        with self._lock:
            process = self._processes.get(vm_name)
            if not process:
                return False
        
        try:
            sockets = self._get_sockets(vm_name, vm_config)
            
            command = {
                'command': 'read_file',
                'path': guest_path,
            }
            
            response = self._send_agent_command(sockets['agent'], command)
            
            if response.get('success') and 'data' in response:
                file_data = bytes.fromhex(response['data'])
                with open(local_path, 'wb') as f:
                    f.write(file_data)
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to copy file from guest: {e}")
            return False
    
    def run_command(self, arch: VMArchitecture, command: str, timeout: int = 30) -> Dict[str, Any]:
        vm_config = self.get_vm_config(arch)
        if not vm_config:
            return {'error': 'No VM config'}
        
        vm_name = vm_config.name
        
        with self._lock:
            process = self._processes.get(vm_name)
            if not process:
                return {'error': 'VM not running'}
        
        try:
            sockets = self._get_sockets(vm_name, vm_config)
            
            cmd = {
                'command': 'execute',
                'cmd': command,
                'timeout': timeout
            }
            
            response = self._send_agent_command(sockets['agent'], cmd, timeout + 5)
            return response
            
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_file(self, file_path: str, arch: Optional[VMArchitecture] = None, 
                     timeout: Optional[int] = None) -> AnalysisResult:
        start_time = time.time()
        
        if not os.path.exists(file_path):
            return AnalysisResult(
                success=False,
                file_path=file_path,
                architecture="unknown",
                duration=0,
                error="File not found"
            )
        
                                  
        if arch is None:
            arch = self._detect_file_architecture(file_path)
        
        timeout = timeout or self.config.default_analysis_timeout
        
        vm_config = self.get_vm_config(arch)
        if not vm_config:
            return AnalysisResult(
                success=False,
                file_path=file_path,
                architecture=arch.value if arch else "unknown",
                duration=0,
                error=f"No VM configuration for {arch}"
            )
        
        vm_name = vm_config.name
        
        try:
                                  
            if not self.is_running(arch):
                if not self.start_vm(arch):
                    return AnalysisResult(
                        success=False,
                        file_path=file_path,
                        architecture=arch.value,
                        duration=time.time() - start_time,
                        error="Failed to start VM"
                    )
            
            self._states[vm_name] = VMState.ANALYZING
            
                                                                                   
            try:
                self.restore_snapshot(arch, vm_config.snapshot_name)
            except Exception as e:
                logger.warning(f"Snapshot restore skipped: {e}")
            
                                
            guest_path = f"/tmp/sample_{os.path.basename(file_path)}"
            if not self.copy_to_guest(arch, file_path, guest_path):
                return AnalysisResult(
                    success=False,
                    file_path=file_path,
                    architecture=arch.value,
                    duration=time.time() - start_time,
                    error="Failed to copy file to VM"
                )
            
                          
            sockets = self._get_sockets(vm_name, vm_config)
            
            analysis_cmd = {
                'command': 'analyze',
                'file_path': guest_path,
                'timeout': timeout
            }
            
                                                                      
            response = self._send_agent_command_with_retry(
                sockets['agent'], analysis_cmd, 
                timeout=timeout + 10, max_retries=3, retry_delay=2.0
            )
            
                             
            duration = time.time() - start_time
            
            if response.get('success'):
                result = AnalysisResult(
                    success=True,
                    file_path=file_path,
                    architecture=arch.value,
                    duration=duration,
                    events=response.get('events', []),
                    syscalls=response.get('syscalls', []),
                    network_activity=response.get('network', []),
                    file_activity=response.get('files', []),
                    process_activity=response.get('processes', []),
                    stdout=response.get('stdout', ''),
                    stderr=response.get('stderr', ''),
                    exit_code=response.get('exit_code')
                )
            else:
                result = AnalysisResult(
                    success=False,
                    file_path=file_path,
                    architecture=arch.value,
                    duration=duration,
                    error=response.get('error', 'Analysis failed'),
                    stdout=response.get('stdout', ''),
                    stderr=response.get('stderr', '')
                )
            
                                                                  
            try:
                self.restore_snapshot(arch, vm_config.snapshot_name)
            except Exception as e:
                logger.warning(f"Post-analysis snapshot restore skipped: {e}")
            
            self._states[vm_name] = VMState.RUNNING
            return result
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            self._states[vm_name] = VMState.ERROR
            return AnalysisResult(
                success=False,
                file_path=file_path,
                architecture=arch.value if arch else "unknown",
                duration=time.time() - start_time,
                error=str(e)
            )
    
    def _wait_for_vm_ready(self, vm_name: str, timeout: int) -> bool:
        vm_config = None
        for arch in VMArchitecture:
            cfg = self.get_vm_config(arch)
            if cfg and cfg.name == vm_name:
                vm_config = cfg
                break
        
        if not vm_config:
            return False
        
        sockets = self._get_sockets(vm_name, vm_config)
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                response = self._send_agent_command(sockets['agent'], {'command': 'ping'}, timeout=5)
                if response.get('success'):
                    return True
            except Exception:
                pass
            time.sleep(1)
        
        return False
    
    def _send_agent_command_with_retry(self, socket_path: str, command: Dict[str, Any],
                                       timeout: float = 30, max_retries: int = 3,
                                       retry_delay: float = 1.0) -> Dict[str, Any]:

        last_error = None
        
        for attempt in range(max_retries):
            result = self._send_agent_command(socket_path, command, timeout)
            
            if result.get('success'):
                return result
            
            last_error = result.get('error', 'Unknown error')
            
                                           
            if 'not found' in str(last_error).lower():
                break
            
            if attempt < max_retries - 1:
                time.sleep(retry_delay * (attempt + 1))                       
        
        return {'success': False, 'error': f'Failed after {max_retries} attempts: {last_error}'}
    
    def _send_agent_command(self, socket_path: str, command: Dict[str, Any], 
                           timeout: float = 30) -> Dict[str, Any]:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        try:
            sock.connect(socket_path)
            
                          
            data = json.dumps(command) + '\n'
            sock.send(data.encode())
            
                              
            buffer = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buffer += chunk
                if b'\n' in buffer:
                    break
            
            if buffer:
                return json.loads(buffer.decode().strip())
            
            return {'success': False, 'error': 'No response'}
            
        except socket.timeout:
            return {'success': False, 'error': 'Timeout'}
        except Exception as e:
            return {'success': False, 'error': str(e)}
        finally:
            sock.close()
    
    def _detect_file_architecture(self, file_path: str) -> VMArchitecture:
        try:
            result = subprocess.run(
                ['file', '-b', file_path],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            output = result.stdout.lower()
            
                                                      
                                        
            if ('x86-64' in output or 'x86_64' in output or 'amd64' in output) and 'elf' in output:
                logger.info(f"Detected x86-64 ELF binary, routing to X64 VM")
                return VMArchitecture.X64
            
                                                
            if ('x86' in output or 'i386' in output or 'i686' in output) and 'elf' in output:
                logger.info(f"Detected x86 ELF binary, routing to X64 VM")
                return VMArchitecture.X64
            
                                              
            if 'pe32' in output or 'pe32+' in output or 'windows' in output:
                logger.info(f"Detected Windows PE, routing to X64 VM")
                return VMArchitecture.X64
            
                                               
            
                                
            if ('aarch64' in output or 'arm64' in output) and 'elf' in output:
                logger.info(f"Detected ARM64 ELF binary, routing to ARM64 VM")
                return VMArchitecture.ARM64
            
                                                                     
            script_extensions = {
                '.py', '.pyc', '.pyw',                   
                '.js', '.mjs', '.cjs',                       
                '.sh', '.bash', '.zsh', '.fish',        
                '.pl', '.pm',                          
                '.rb',                                 
                '.php',                               
                '.lua',                               
                '.ps1', '.psm1',                             
                '.bat', '.cmd',                                             
                '.jar',                                
                '.class',                                       
            }
            
            ext = os.path.splitext(file_path)[1].lower()
            if ext in script_extensions:
                logger.info(f"Detected script/interpreted file ({ext}), routing to ARM64 VM")
                return VMArchitecture.ARM64
            
                                            
            if 'text' in output or 'script' in output or 'ascii' in output:
                logger.info(f"Detected text/script file, routing to ARM64 VM")
                return VMArchitecture.ARM64
            
                                                 
            logger.info(f"Unknown file type, defaulting to ARM64 VM")
            return VMArchitecture.ARM64
            
        except Exception as e:
            logger.warning(f"Failed to detect architecture: {e}")
            return VMArchitecture.ARM64
    
    def get_status(self) -> Dict[str, Any]:
        status = {
            'arm64': {
                'configured': self.config.arm64_config is not None,
                'running': False,
                'state': VMState.STOPPED.value
            },
            'x64': {
                'configured': self.config.x64_config is not None,
                'running': False,
                'state': VMState.STOPPED.value
            }
        }
        
        if self.config.arm64_config:
            status['arm64']['running'] = self.is_running(VMArchitecture.ARM64)
            status['arm64']['state'] = self.get_state(VMArchitecture.ARM64).value
        
        if self.config.x64_config:
            status['x64']['running'] = self.is_running(VMArchitecture.X64)
            status['x64']['state'] = self.get_state(VMArchitecture.X64).value
        
        return status
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_all()
