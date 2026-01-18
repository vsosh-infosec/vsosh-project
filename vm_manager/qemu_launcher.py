import os
import subprocess
import time
import signal
import socket
import logging
from typing import Optional, List, Dict, Any
from dataclasses import dataclass

from .vm_config import VMConfig, VMArchitecture, AntiVMConfig

logger = logging.getLogger(__name__)


@dataclass
class QEMUProcess:
    monitor_socket: str
    serial_socket: str
    pid: int
    agent_socket: str = ""
    process: Optional[subprocess.Popen] = None
    config: Optional[VMConfig] = None
    _external: bool = False                                        
    
    def is_running(self) -> bool:
        if self._external:
                                     
            try:
                os.kill(self.pid, 0)
                return True
            except (OSError, ProcessLookupError):
                return False
        return self.process is not None and self.process.poll() is None
    
    def terminate(self, timeout: int = 5):
        if self._external:
                                                       
            try:
                os.kill(self.pid, 15)           
            except (OSError, ProcessLookupError):
                pass
        elif self.process and self.is_running():
            self.process.terminate()
            try:
                self.process.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
    
    @classmethod
    def from_existing(cls, pid: int, monitor_socket: str, serial_socket: str, agent_socket: str) -> 'QEMUProcess':
        return cls(
            monitor_socket=monitor_socket,
            serial_socket=serial_socket,
            pid=pid,
            agent_socket=agent_socket,
            process=None,
            config=None,
            _external=True
        )


class QEMULauncher:
    def __init__(self, sockets_dir: str = "/tmp/vm_sandbox"):
        self.sockets_dir = sockets_dir
        self._processes: Dict[str, QEMUProcess] = {}
        os.makedirs(sockets_dir, exist_ok=True)
    
    def _check_qemu_available(self, binary: str) -> bool:
        try:
            result = subprocess.run(['which', binary], capture_output=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    def _check_kvm_available(self) -> bool:
        return os.path.exists('/dev/kvm') and os.access('/dev/kvm', os.R_OK | os.W_OK)
    
    def _generate_base_args(self, config: VMConfig) -> List[str]:
        args = [config.qemu_binary]
        
                      
        if config.architecture == VMArchitecture.ARM64:
            args.extend(['-machine', 'virt,gic-version=2'])
            args.extend(['-cpu', 'max'])
        else:
            args.extend(['-machine', 'q35,accel=tcg'])
            args.extend(['-cpu', 'qemu64'])
        
                         
        args.extend(['-m', str(config.ram_mb)])
        args.extend(['-smp', str(config.cpus)])
        
                                                       
        if config.enable_kvm and self._check_kvm_available():
            if config.architecture == VMArchitecture.ARM64:
                                                                   
                try:
                    idx = args.index('virt,gic-version=2')
                    args[idx] = 'virt,gic-version=2,accel=kvm'
                    idx = args.index('max')
                    args[idx] = 'host'
                except ValueError:
                    pass                                          
        
        return args
    
    def _generate_storage_args(self, config: VMConfig, anti_vm: AntiVMConfig) -> List[str]:
        args = []
        
                                        
        import random
        serial = f"{anti_vm.disk_serial_prefix}{random.randint(10000000, 99999999)}"
        
                                                      
        args.extend([
            '-drive', f'file={config.image_path},if=none,id=disk0,format=qcow2',
        ])
        
        if config.architecture == VMArchitecture.ARM64:
            args.extend(['-device', f'virtio-blk-pci,drive=disk0,serial={serial}'])
        else:
            args.extend(['-device', f'ide-hd,drive=disk0,bus=ide.0,serial={serial}'])
        
        return args
    
    def _generate_network_args(self, config: VMConfig, anti_vm: AntiVMConfig) -> List[str]:
        args = []
        
                                        
        import random
        mac_suffix = ':'.join([f'{random.randint(0, 255):02x}' for _ in range(3)])
        mac_address = f"{anti_vm.mac_prefix}:{mac_suffix}"
        
        if config.network_enabled:
            args.extend([
                '-netdev', 'user,id=net0',
                '-device', f'virtio-net-pci,netdev=net0,mac={mac_address}'
            ])
        else:
                                              
            args.extend(['-nic', 'none'])
        
        return args
    
    def _generate_smbios_args(self, anti_vm: AntiVMConfig) -> List[str]:
        args = []
        
                                             
        profiles = {
            'dell_optiplex': {
                'type0': 'vendor=Dell Inc.,version=A12,date=03/15/2023',
                'type1': 'manufacturer=Dell Inc.,product=OptiPlex 7080,version=1.0,serial=ABC1234567,uuid=550e8400-e29b-41d4-a716-446655440000',
                'type2': 'manufacturer=Dell Inc.,product=0X8DXD,version=A00,serial=.XYZ9876543.',
                'type3': 'manufacturer=Dell Inc.,type=3,serial=GHI789012',
                'type4': 'manufacturer=Intel(R) Corporation,version=Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz',
            },
            'hp_prodesk': {
                'type0': 'vendor=HP,version=S14 Ver. 02.09.00,date=05/20/2023',
                'type1': 'manufacturer=HP,product=HP ProDesk 400 G7,version=1.0,serial=MXL1234ABC',
                'type2': 'manufacturer=HP,product=8767,version=KBC Version 08.60.00,serial=PWXYZ12345',
                'type3': 'manufacturer=HP,type=3,serial=MXL1234ABC',
                'type4': 'manufacturer=Intel(R) Corporation,version=Intel(R) Core(TM) i5-10500 CPU @ 3.10GHz',
            },
            'lenovo_thinkcentre': {
                'type0': 'vendor=LENOVO,version=M3CKT49A,date=01/10/2023',
                'type1': 'manufacturer=LENOVO,product=ThinkCentre M920q,version=ThinkCentre M920q,serial=PF2XXXXX',
                'type2': 'manufacturer=LENOVO,product=313D,version=SDK0J40697 WIN,serial=L1HFXXX01XX',
                'type3': 'manufacturer=LENOVO,type=3,serial=PF2XXXXX',
                'type4': 'manufacturer=Intel(R) Corporation,version=Intel(R) Core(TM) i7-9700T CPU @ 2.00GHz',
            },
        }
        
        profile = profiles.get(anti_vm.smbios_profile, profiles['dell_optiplex'])
        
                                                   
        if anti_vm.custom_smbios:
            profile.update(anti_vm.custom_smbios)
        
        for smbios_type, data in profile.items():
            type_num = smbios_type.replace('type', '')
            args.extend(['-smbios', f'type={type_num},{data}'])
        
        return args
    
    def _generate_cpu_args(self, config: VMConfig, anti_vm: AntiVMConfig) -> List[str]:
        args = []
        
        if config.architecture == VMArchitecture.X64:
                                                            
            cpu_flags = ['qemu64']
            
            if anti_vm.hide_hypervisor:
                cpu_flags.append('-hypervisor')
            
            if anti_vm.stabilize_tsc:
                cpu_flags.append('+invtsc')
            
                                        
            if anti_vm.hide_kvm_signature:
                cpu_flags.extend(['-kvm_pv_eoi', '-kvm_pv_unhalt', '-kvm_steal_time'])
            
            args.extend(['-cpu', ','.join(cpu_flags)])
        
        return args
    
    def _generate_display_args(self, config: VMConfig) -> List[str]:
        args = []
        
        if config.display == 'none':
            args.extend(['-display', 'none'])
            args.append('-nographic')
        elif config.display == 'vnc':
            port = config.vnc_port or 5900
            args.extend(['-vnc', f':{port - 5900}'])
        elif config.display == 'gtk':
            args.extend(['-display', 'gtk'])
        
        return args
    
    def _generate_device_args(self, config: VMConfig) -> List[str]:
        args = []
        
                                    
        args.extend(['-device', 'qemu-xhci,id=xhci'])
        args.extend(['-device', 'usb-kbd,id=kbd0'])
        args.extend(['-device', 'usb-mouse,id=mouse0'])
        
                           
        args.extend([
            '-device', 'intel-hda',
            '-device', 'hda-duplex'
        ])
        
                                      
        args.extend(['-device', 'virtio-rng-pci'])
        
        return args
    
    def _generate_communication_args(self, config: VMConfig) -> List[str]:
        args = []
        
        sockets = config.get_socket_paths(self.sockets_dir)
        
                                    
        args.extend([
            '-qmp', f"unix:{sockets['monitor']},server,nowait"
        ])
        
                                                        
        args.extend([
            '-chardev', f"socket,id=serial0,path={sockets['serial']},server=on,wait=off",
            '-serial', 'chardev:serial0'
        ])
        
                                       
        args.extend([
            '-device', 'virtio-serial-pci',
            '-chardev', f"socket,id=agent0,path={sockets['agent']},server=on,wait=off",
            '-device', 'virtserialport,chardev=agent0,name=org.sandbox.agent'
        ])
        
        return args
    
    def _generate_firmware_args(self, config: VMConfig) -> List[str]:
        args = []
        
        if config.architecture == VMArchitecture.ARM64:
                                                    
            uefi_paths = [
                '/usr/share/AAVMF/AAVMF_CODE.fd',
                '/usr/share/qemu-efi-aarch64/QEMU_EFI.fd',
                '/usr/share/edk2/aarch64/QEMU_EFI.fd',
            ]
            
            for path in uefi_paths:
                if os.path.exists(path):
                    args.extend(['-bios', path])
                    break
        
        return args
    
    def build_command(self, config: VMConfig, anti_vm: AntiVMConfig) -> List[str]:
        """Build complete QEMU command with all arguments"""
        args = []
        
        args.extend(self._generate_base_args(config))
        args.extend(self._generate_firmware_args(config))
        args.extend(self._generate_cpu_args(config, anti_vm))
        args.extend(self._generate_smbios_args(anti_vm))
        args.extend(self._generate_storage_args(config, anti_vm))
        args.extend(self._generate_network_args(config, anti_vm))
        args.extend(self._generate_display_args(config))
        args.extend(self._generate_device_args(config))
        args.extend(self._generate_communication_args(config))
        
                     
        args.append('-daemonize')
        
        return args
    
    def launch(self, config: VMConfig, anti_vm: AntiVMConfig) -> QEMUProcess:
        if not self._check_qemu_available(config.qemu_binary):
            raise RuntimeError(f"QEMU binary not found: {config.qemu_binary}")
        
        if not os.path.exists(config.image_path):
            raise FileNotFoundError(f"VM image not found: {config.image_path}")
        
                       
        cmd = self.build_command(config, anti_vm)
        
        logger.info(f"Launching VM: {config.name}")
        logger.debug(f"QEMU command: {' '.join(cmd)}")
        
                          
        sockets = config.get_socket_paths(self.sockets_dir)
        
                              
        for sock_path in sockets.values():
            if os.path.exists(sock_path):
                os.unlink(sock_path)
        
                                  
        try:
                                                         
            cmd_no_daemon = [arg for arg in cmd if arg != '-daemonize']
            
                                                                          
                                                                        
            process = subprocess.Popen(
                cmd_no_daemon,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
            )
            
                                                   
            start_time = time.time()
            while time.time() - start_time < config.boot_timeout:
                if os.path.exists(sockets['monitor']):
                    break
                if process.poll() is not None:
                    raise RuntimeError(f"QEMU exited with code {process.returncode}")
                time.sleep(0.1)
            else:
                process.kill()
                raise TimeoutError("QEMU monitor socket not created")
            
            qemu_proc = QEMUProcess(
                process=process,
                config=config,
                monitor_socket=sockets['monitor'],
                serial_socket=sockets['serial'],
                agent_socket=sockets['agent'],
                pid=process.pid,
            )
            
            self._processes[config.name] = qemu_proc
            logger.info(f"VM {config.name} started with PID {process.pid}")
            
            return qemu_proc
            
        except Exception as e:
            logger.error(f"Failed to launch VM: {e}")
            raise
    
    def stop(self, vm_name: str, force: bool = False):
        """Stop a running VM"""
        if vm_name not in self._processes:
            return
        
        proc = self._processes[vm_name]
        
        if force:
            proc.process.kill()
        else:
                                        
            try:
                self._send_qmp_command(proc.monitor_socket, {'execute': 'system_powerdown'})
                proc.process.wait(timeout=10)
            except Exception:
                proc.process.kill()
        
        proc.process.wait()
        del self._processes[vm_name]
        
                          
        sockets = proc.config.get_socket_paths(self.sockets_dir)
        for sock_path in sockets.values():
            if os.path.exists(sock_path):
                os.unlink(sock_path)
        
        logger.info(f"VM {vm_name} stopped")
    
    def stop_all(self):
        for vm_name in list(self._processes.keys()):
            self.stop(vm_name, force=True)
    
    def _send_qmp_command(self, socket_path: str, command: Dict[str, Any]) -> Dict[str, Any]:
        import json
        
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.connect(socket_path)
            sock.settimeout(5.0)
            
                           
            sock.recv(4096)
            
                                           
            sock.send(b'{"execute": "qmp_capabilities"}\n')
            sock.recv(4096)
            
                          
            sock.send((json.dumps(command) + '\n').encode())
            response = sock.recv(4096)
            
            return json.loads(response.decode())
        finally:
            sock.close()
    
    def get_process(self, vm_name: str) -> Optional[QEMUProcess]:
        return self._processes.get(vm_name)
    
    def is_running(self, vm_name: str) -> bool:
        proc = self._processes.get(vm_name)
        return proc is not None and proc.is_running()
