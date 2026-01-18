import os
import time
import logging
import threading
from enum import Enum
from typing import Optional, Dict, Any, Callable
from concurrent.futures import ThreadPoolExecutor, Future

from .vm_config import VMArchitecture, VMConfig
from .vm_manager import VMManager, VMState, AnalysisResult

logger = logging.getLogger(__name__)


class PoolVMState(Enum):
    COLD = "cold"                        
    WARMING = "warming"                  
    READY = "ready"                                               
    BUSY = "busy"                                
    RESTORING = "restoring"                     
    ERROR = "error"                      


class VMPool:
    READY_SNAPSHOT = "pool_ready"                                     
    
    def __init__(self, vm_manager: VMManager):
        self._vm_manager = vm_manager
        
                                         
        self._states: Dict[VMArchitecture, PoolVMState] = {
            VMArchitecture.ARM64: PoolVMState.COLD,
            VMArchitecture.X64: PoolVMState.COLD,
        }
        
                                                               
        self._locks: Dict[VMArchitecture, threading.Lock] = {
            VMArchitecture.ARM64: threading.Lock(),
            VMArchitecture.X64: threading.Lock(),
        }
        
                                                     
        self._ready_conditions: Dict[VMArchitecture, threading.Condition] = {
            VMArchitecture.ARM64: threading.Condition(),
            VMArchitecture.X64: threading.Condition(),
        }
        
                                   
        self._warmup_complete = False
        self._warmup_errors: Dict[VMArchitecture, Optional[str]] = {
            VMArchitecture.ARM64: None,
            VMArchitecture.X64: None,
        }
        
                                        
        self._on_warmup_complete: Optional[Callable[[Dict[VMArchitecture, bool]], None]] = None
    
    @property
    def is_ready(self) -> bool:
        """Check if at least one VM is ready"""
        return any(s == PoolVMState.READY for s in self._states.values())
    
    @property
    def warmup_complete(self) -> bool:
        """Check if warmup phase is complete"""
        return self._warmup_complete
    
    def get_state(self, arch: VMArchitecture) -> PoolVMState:
        """Get current state of a VM in the pool"""
        return self._states.get(arch, PoolVMState.COLD)
    
    def get_available_architectures(self) -> list:
        """Get list of ready architectures"""
        return [arch for arch, state in self._states.items() 
                if state == PoolVMState.READY]
    
    def warmup(self, architectures: Optional[list] = None, 
               blocking: bool = True,
               on_complete: Optional[Callable[[Dict[VMArchitecture, bool]], None]] = None) -> Dict[VMArchitecture, bool]:
        self._on_warmup_complete = on_complete
        
                                                  
        if architectures is None:
            architectures = []
            if self._vm_manager.config.arm64_config:
                if os.path.exists(self._vm_manager.config.arm64_config.image_path):
                    architectures.append(VMArchitecture.ARM64)
            if self._vm_manager.config.x64_config:
                if os.path.exists(self._vm_manager.config.x64_config.image_path):
                    architectures.append(VMArchitecture.X64)
        
        if not architectures:
            logger.warning("No VM images found for warmup")
            self._warmup_complete = True
            return {}
        
        logger.info(f"Warming up VMs: {[a.value for a in architectures]}")
        
        if blocking:
            return self._warmup_sync(architectures)
        else:
                                               
            thread = threading.Thread(
                target=self._warmup_async,
                args=(architectures,),
                daemon=True
            )
            thread.start()
            return {arch: False for arch in architectures}                       
    
    def _warmup_sync(self, architectures: list) -> Dict[VMArchitecture, bool]:
        results = {}
        
                                                    
        with ThreadPoolExecutor(max_workers=len(architectures)) as executor:
            futures: Dict[VMArchitecture, Future] = {}
            
            for arch in architectures:
                futures[arch] = executor.submit(self._warmup_single_vm, arch)
            
                                                         
            for arch, future in futures.items():
                                                              
                                        
                is_tcg = (arch == VMArchitecture.X64)
                timeout = 1800 if is_tcg else 300                                 
                
                try:
                    results[arch] = future.result(timeout=timeout)
                except Exception as e:
                    logger.error(f"Warmup failed for {arch.value}: {e}")
                    results[arch] = False
                    self._warmup_errors[arch] = str(e)
        
        self._warmup_complete = True
        
        if self._on_warmup_complete:
            self._on_warmup_complete(results)
        
                     
        ready = [a.value for a, ok in results.items() if ok]
        failed = [a.value for a, ok in results.items() if not ok]
        
        if ready:
            logger.info(f"VMs ready: {ready}")
        if failed:
            logger.warning(f"VMs failed: {failed}")
        
        return results
    
    def _warmup_async(self, architectures: list):
        try:
            results = self._warmup_sync(architectures)
        except Exception as e:
            logger.error(f"Async warmup failed: {e}")
    
    def _check_snapshot_exists(self, image_path: str, snapshot_name: str) -> bool:
        import subprocess
        try:
            result = subprocess.run(
                ['qemu-img', 'snapshot', '-l', image_path],
                capture_output=True, text=True, timeout=10
            )
            return snapshot_name in result.stdout
        except Exception:
            return False
    
    def _wait_for_agent_ready(self, vm_config, timeout: int = 30) -> bool:
        import time
        sockets = self._vm_manager._get_sockets(vm_config.name, vm_config)
        
        for i in range(timeout):
            try:
                response = self._vm_manager._send_agent_command(
                    sockets['agent'], {'command': 'ping'}, timeout=2
                )
                if response.get('success'):
                    return True
            except Exception:
                pass
            time.sleep(1)
        return False
    
    def _warmup_single_vm(self, arch: VMArchitecture) -> bool:
        vm_config = self._vm_manager.get_vm_config(arch)
        if not vm_config:
            logger.error(f"No config for {arch.value}")
            return False
        
        logger.info(f"[{arch.value}] Starting warmup...")
        self._states[arch] = PoolVMState.WARMING
        
                                                                         
        vm_already_running = False
        if vm_config.name in self._vm_manager._processes:
            if self._vm_manager._processes[vm_config.name].is_running():
                vm_already_running = True
                print(f"  [{arch.value}] VM already running - reusing!")
                logger.info(f"[{arch.value}] VM already running - checking agent")
        
                                                           
                                                                            
        has_snapshot = False
        if not vm_already_running:
            has_snapshot = self._check_snapshot_exists(vm_config.image_path, self.READY_SNAPSHOT)
        
        try:
            if vm_already_running:
                                                          
                print(f"  [{arch.value}] Waiting for agent on existing VM...")
                
                if self._wait_for_agent_ready(vm_config, timeout=30):
                    print(f"  [{arch.value}] Existing VM ready")
                    self._vm_manager._states[vm_config.name] = VMState.RUNNING
                else:
                    raise RuntimeError("Agent not responding on existing VM")
                    
            elif has_snapshot:
                                                          
                print(f"  [{arch.value}] Found snapshot - fast restore.")
                
                                                          
                import time
                start_time = time.time()
                
                process = self._vm_manager.launcher.launch(vm_config, self._vm_manager.config.anti_vm)
                with self._vm_manager._lock:
                    self._vm_manager._processes[vm_config.name] = process
                    from .snapshot import SnapshotManager
                    self._vm_manager._snapshot_managers[vm_config.name] = SnapshotManager(process.monitor_socket)
                
                                                      
                time.sleep(2)
                
                                          
                logger.info(f"[{arch.value}] Restoring snapshot.")
                self._vm_manager.restore_snapshot(arch, self.READY_SNAPSHOT)
                
                                                         
                if not self._wait_for_agent_ready(vm_config, timeout=30):
                    raise RuntimeError("Agent not ready after snapshot restore")
                
                elapsed = time.time() - start_time
                print(f"  [{arch.value}] Fast restore complete in {elapsed:.2f}s")
                self._vm_manager._states[vm_config.name] = VMState.RUNNING
                
            else:
                                      
                print(f"  [{arch.value}] No snapshot - doing full boot (slow)...")
                
                if not self._vm_manager.start_vm(arch):
                    raise RuntimeError("Failed to start VM")
                
                logger.info(f"[{arch.value}] VM started, agent ready")
                
                                                     
                logger.info(f"[{arch.value}] Creating live snapshot...")
                self._vm_manager.create_snapshot(arch, self.READY_SNAPSHOT, "Pool ready state with RAM")
                logger.info(f"[{arch.value}] Snapshot created")
            
                           
            self._states[arch] = PoolVMState.READY
            
                            
            with self._ready_conditions[arch]:
                self._ready_conditions[arch].notify_all()
            
            logger.info(f"[{arch.value}] Warmup complete - VM ready")
            return True
            
        except Exception as e:
            logger.error(f"[{arch.value}] Warmup failed: {e}")
            self._states[arch] = PoolVMState.ERROR
            self._warmup_errors[arch] = str(e)
            return False
    
    def acquire(self, arch: VMArchitecture, timeout: float = 300) -> bool                   
        with self._ready_conditions[arch]:
            start = time.time()
            while self._states[arch] not in (PoolVMState.READY, PoolVMState.ERROR):
                remaining = timeout - (time.time() - start)
                if remaining <= 0:
                    logger.warning(f"[{arch.value}] Acquire timeout waiting for ready")
                    return False
                self._ready_conditions[arch].wait(timeout=remaining)
        
        if self._states[arch] == PoolVMState.ERROR:
            logger.error(f"[{arch.value}] Cannot acquire - VM in error state")
            return False
        
                                             
        acquired = self._locks[arch].acquire(timeout=timeout)
        if not acquired:
            logger.warning(f"[{arch.value}] Acquire timeout waiting for lock")
            return False
        
        self._states[arch] = PoolVMState.BUSY
        logger.debug(f"[{arch.value}] Acquired")
        return True
    
    def release(self, arch: VMArchitecture):
        if self._states[arch] != PoolVMState.BUSY:
            logger.warning(f"[{arch.value}] Release called but VM not busy")
            return
        
        self._states[arch] = PoolVMState.RESTORING
        logger.debug(f"[{arch.value}] Releasing - restoring snapshot...")
        
        try:
                                                       
            restore_time = self._vm_manager.restore_snapshot(arch, self.READY_SNAPSHOT)
            logger.info(f"[{arch.value}] Snapshot restored in {restore_time:.2f}s")
            
                                                               
                                                                                                 
            vm_config = self._vm_manager.get_vm_config(arch)
            if vm_config:
                sockets = self._vm_manager._get_sockets(vm_config.name, vm_config)
                for i in range(10):                                   
                    try:
                        response = self._vm_manager._send_agent_command(
                            sockets['agent'], {'command': 'ping'}, timeout=2
                        )
                        if response.get('success'):
                            logger.debug(f"[{arch.value}] Agent ready after restore")
                            break
                    except Exception:
                        pass
                    time.sleep(1)
            
            self._states[arch] = PoolVMState.READY
            
        except Exception as e:
            logger.error(f"[{arch.value}] Snapshot restore failed: {e}")
                                          
            self._states[arch] = PoolVMState.COLD
            try:
                self._warmup_single_vm(arch)
            except Exception:
                self._states[arch] = PoolVMState.ERROR
        
        finally:
            self._locks[arch].release()
            
                            
            with self._ready_conditions[arch]:
                self._ready_conditions[arch].notify_all()
    
    def analyze(self, arch: VMArchitecture, file_path: str, 
                timeout: Optional[int] = None) -> AnalysisResult:
        start_time = time.time()
        
                                    
        if arch is None:
            arch = self._vm_manager._detect_file_architecture(file_path)
        
                                    
        if self._states[arch] == PoolVMState.ERROR:
            return AnalysisResult(
                success=False,
                file_path=file_path,
                architecture=arch.value,
                duration=0,
                error=f"VM pool error: {self._warmup_errors.get(arch, 'Unknown error')}"
            )
        
                    
        if not self.acquire(arch, timeout=60):
            return AnalysisResult(
                success=False,
                file_path=file_path,
                architecture=arch.value,
                duration=time.time() - start_time,
                error="Failed to acquire VM from pool"
            )
        
        try:
                          
            vm_config = self._vm_manager.get_vm_config(arch)
            timeout = timeout or self._vm_manager.config.default_analysis_timeout
            
                                
            guest_path = f"/tmp/sample_{os.path.basename(file_path)}"
            if not self._vm_manager.copy_to_guest(arch, file_path, guest_path):
                return AnalysisResult(
                    success=False,
                    file_path=file_path,
                    architecture=arch.value,
                    duration=time.time() - start_time,
                    error="Failed to copy file to VM"
                )
            
                                  
            sockets = self._vm_manager._get_sockets(vm_config.name, vm_config)
            
            analysis_cmd = {
                'command': 'analyze',
                'file_path': guest_path,
                'timeout': timeout
            }
            
            response = self._vm_manager._send_agent_command_with_retry(
                sockets['agent'], analysis_cmd,
                timeout=timeout + 10, max_retries=3, retry_delay=2.0
            )
            
            duration = time.time() - start_time
            
            if response.get('success'):
                return AnalysisResult(
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
                return AnalysisResult(
                    success=False,
                    file_path=file_path,
                    architecture=arch.value,
                    duration=duration,
                    error=response.get('error', 'Analysis failed'),
                    stdout=response.get('stdout', ''),
                    stderr=response.get('stderr', '')
                )
                
        finally:
                                                
            self.release(arch)
    
    def shutdown(self):
        logger.info("Shutting down VM pool...")
        self._vm_manager.stop_all()
        for arch in VMArchitecture:
            self._states[arch] = PoolVMState.COLD
    
    def get_status(self) -> Dict[str, Any]:
        return {
            'warmup_complete': self._warmup_complete,
            'vms': {
                arch.value: {
                    'state': self._states[arch].value,
                    'error': self._warmup_errors.get(arch),
                    'available': self._states[arch] == PoolVMState.READY,
                }
                for arch in VMArchitecture
            }
        }
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shutdown()
