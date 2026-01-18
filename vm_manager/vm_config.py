import os
import yaml
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any


class VMArchitecture(Enum):
    ARM64 = "aarch64"
    X64 = "x86_64"


@dataclass
class VMConfig:                    
    name: str
    architecture: VMArchitecture
    image_path: str
    
               
    ram_mb: int = 4096               
    cpus: int = 4
    
             
    disk_size_gb: int = 20
    disk_serial: str = "WD-WCAV12345678"
    
             
    mac_address: str = "D4:BE:D9:12:34:56"
    network_enabled: bool = False                        
    
             
    display: str = "none"                         
    vnc_port: Optional[int] = None
    
               
    snapshot_name: str = "clean"
    
                   
    enable_kvm: bool = True                        
    machine_type: str = "virt"                             
    
           
    qemu_binary: Optional[str] = None
    
                   
    monitor_socket: Optional[str] = None
    serial_socket: Optional[str] = None
    agent_socket: Optional[str] = None
    
              
    boot_timeout: int = 30
    analysis_timeout: int = 60
    snapshot_timeout: int = 10

    def __post_init__(self):
        if self.qemu_binary is None:
            if self.architecture == VMArchitecture.ARM64:
                self.qemu_binary = "qemu-system-aarch64"
            else:
                self.qemu_binary = "qemu-system-x86_64"
        
        if self.architecture == VMArchitecture.X64:
            self.machine_type = "q35"
                                                  
            if self.cpus > 2:
                self.cpus = 2
    
    def get_socket_paths(self, base_dir: str) -> Dict[str, str]:
        vm_id = f"{self.name}_{os.getpid()}"
        return {
            'monitor': os.path.join(base_dir, f"{vm_id}_monitor.sock"),
            'serial': os.path.join(base_dir, f"{vm_id}_serial.sock"),
            'agent': os.path.join(base_dir, f"{vm_id}_agent.sock"),
        }


@dataclass
class AntiVMConfig:
    hide_hypervisor: bool = True
    hide_kvm_signature: bool = True
    
                     
    smbios_profile: str = "dell_optiplex"
    custom_smbios: Optional[Dict[str, str]] = None
    
                       
    disk_serial_prefix: str = "WD-WCAV"
    mac_prefix: str = "D4:BE:D9"            
    
            
    stabilize_tsc: bool = True
    tsc_frequency: int = 3600000000           
    
             
    fake_thermal_sensors: bool = True
    fake_fan_sensors: bool = True
    fake_battery: bool = True
    
                    
    generate_user_files: bool = True
    generate_browser_history: bool = True
    
                           
    hide_vm_processes: bool = True
    hide_vm_modules: bool = True


@dataclass 
class VMManagerConfig:      
    images_dir: str = "vm_images"
    sockets_dir: str = "/tmp/vm_sandbox"
    logs_dir: str = "logs/vm"
    
                       
    arm64_config: Optional[VMConfig] = None
    x64_config: Optional[VMConfig] = None
    
                      
    anti_vm: AntiVMConfig = field(default_factory=AntiVMConfig)
    
              
    default_ram_mb: int = 4096
    default_analysis_timeout: int = 60
    
    @classmethod
    def from_yaml(cls, path: str) -> 'VMManagerConfig':
        with open(path, 'r') as f:
            data = yaml.safe_load(f)
        
        config = cls()
        
                     
        config.images_dir = data.get('paths', {}).get('images_dir', config.images_dir)
        config.sockets_dir = data.get('paths', {}).get('sockets_dir', config.sockets_dir)
        config.logs_dir = data.get('paths', {}).get('logs_dir', config.logs_dir)
        
                          
        vm_data = data.get('vm', {})
        
                        
        timeouts = data.get('timeouts', {})
        boot_timeout_kvm = timeouts.get('vm_boot', 120)
        boot_timeout_tcg = timeouts.get('vm_boot_tcg', 1200)                  
        analysis_timeout = timeouts.get('analysis', 60)
        
        if 'arm64' in vm_data:
            arm_data = vm_data['arm64']
            accel = arm_data.get('accel', 'kvm')
            config.arm64_config = VMConfig(
                name="sandbox_arm64",
                architecture=VMArchitecture.ARM64,
                image_path=arm_data.get('image', 'vm_images/ubuntu-arm64.qcow2'),
                ram_mb=_parse_ram(arm_data.get('ram', '4G')),
                cpus=arm_data.get('cpus', 4),
                snapshot_name=arm_data.get('snapshot', 'clean'),
                enable_kvm=(accel == 'kvm'),
                boot_timeout=boot_timeout_kvm,
                analysis_timeout=analysis_timeout,
            )
        
        if 'x64' in vm_data:
            x64_data = vm_data['x64']
            accel = x64_data.get('accel', 'tcg')
                                                  
            x64_boot_timeout = boot_timeout_kvm if accel == 'kvm' else boot_timeout_tcg
            config.x64_config = VMConfig(
                name="sandbox_x64",
                architecture=VMArchitecture.X64,
                image_path=x64_data.get('image', 'vm_images/ubuntu-x64.qcow2'),
                ram_mb=_parse_ram(x64_data.get('ram', '4G')),
                cpus=x64_data.get('cpus', 2),
                snapshot_name=x64_data.get('snapshot', 'clean'),
                enable_kvm=(accel == 'kvm'),
                boot_timeout=x64_boot_timeout,
                analysis_timeout=analysis_timeout,
            )
        
                              
        anti_vm_data = data.get('anti_vm', {})
        config.anti_vm = AntiVMConfig(
            smbios_profile=anti_vm_data.get('smbios_profile', 'dell_optiplex'),
            mac_prefix=anti_vm_data.get('mac_prefix', 'D4:BE:D9'),
            disk_serial_prefix=anti_vm_data.get('disk_serial', 'WD-WCAV'),
            hide_hypervisor=anti_vm_data.get('hide_hypervisor', True),
            fake_thermal_sensors=anti_vm_data.get('fake_sensors', True),
            generate_user_files=anti_vm_data.get('user_artifacts', True),
        )
        
                        
        timeouts = data.get('timeouts', {})
        config.default_analysis_timeout = timeouts.get('analysis', 60)
        
        return config
    
    def to_yaml(self, path: str):
        data = {
            'paths': {
                'images_dir': self.images_dir,
                'sockets_dir': self.sockets_dir,
                'logs_dir': self.logs_dir,
            },
            'vm': {},
            'anti_vm': {
                'smbios_profile': self.anti_vm.smbios_profile,
                'mac_prefix': self.anti_vm.mac_prefix,
                'disk_serial': self.anti_vm.disk_serial_prefix,
                'hide_hypervisor': self.anti_vm.hide_hypervisor,
                'fake_sensors': self.anti_vm.fake_thermal_sensors,
                'user_artifacts': self.anti_vm.generate_user_files,
            },
            'timeouts': {
                'analysis': self.default_analysis_timeout,
            }
        }
        
        if self.arm64_config:
            data['vm']['arm64'] = {
                'image': self.arm64_config.image_path,
                'ram': f"{self.arm64_config.ram_mb // 1024}G",
                'cpus': self.arm64_config.cpus,
                'snapshot': self.arm64_config.snapshot_name,
            }
        
        if self.x64_config:
            data['vm']['x64'] = {
                'image': self.x64_config.image_path,
                'ram': f"{self.x64_config.ram_mb // 1024}G",
                'cpus': self.x64_config.cpus,
                'snapshot': self.x64_config.snapshot_name,
            }
        
        with open(path, 'w') as f:
            yaml.dump(data, f, default_flow_style=False)


def _parse_ram(value: str) -> int:
    value = value.strip().upper()
    if value.endswith('G'):
        return int(value[:-1]) * 1024
    elif value.endswith('M'):
        return int(value[:-1])
    else:
        return int(value)
