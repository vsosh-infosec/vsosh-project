import os, random, string, uuid, time
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum

class CPUVendor(Enum):
    INTEL = "GenuineIntel"
    AMD = "AuthenticAMD"

@dataclass
class CPUIDConfig:
    hide_hypervisor_bit: bool = True
    hide_kvm_signature: bool = True
    custom_hv_vendor: Optional[str] = None
    cpu_vendor: CPUVendor = CPUVendor.INTEL
    disable_pv_features: bool = True

KVM_FEATURES = ['kvm_pv_eoi', 'kvm_pv_unhalt', 'kvm_steal_time', 'kvmclock', 'kvmclock-stable-bit']

class CPUIDMasker:
    def __init__(self, config: Optional[CPUIDConfig] = None):
        self.config = config or CPUIDConfig()
    
    def get_cpu_model_flags(self, arch: str = "x86_64") -> List[str]:
        if arch == "aarch64":
            return ["-cpu", "max"]
        features = []
        if self.config.hide_hypervisor_bit:
            features.append("-hypervisor")
        if self.config.disable_pv_features:
            features.extend([f"-{f}" for f in KVM_FEATURES])
        features.extend(['+sse4.1', '+sse4.2', '+ssse3', '+popcnt', '+avx', '+aes'])
        return ["-cpu", "qemu64," + ",".join(features)]

def get_cpuid_args(arch: str = "x86_64", hide_hypervisor: bool = True, use_kvm: bool = False) -> List[str]:
    cfg = CPUIDConfig(hide_hypervisor_bit=hide_hypervisor, disable_pv_features=hide_hypervisor)
    m = CPUIDMasker(cfg)
    machine = "virt,accel=kvm,gic-version=3" if arch == "aarch64" and use_kvm else "virt,accel=tcg" if arch == "aarch64" else "q35,accel=tcg,hpet=off"
    return ["-machine", machine] + m.get_cpu_model_flags(arch)

MAC_OUI = {'dell': ['D4:BE:D9', '18:03:73'], 'hp': ['94:57:A5', '00:21:5A'], 'intel': ['00:1B:21', '00:1E:67']}
DISK_SERIAL = {'western_digital': 'WD-WCAV', 'seagate': 'ST', 'samsung': 'S'}

@dataclass
class HardwareConfig:
    mac_vendor: str = 'dell'
    custom_mac: Optional[str] = None
    disk_vendor: str = 'western_digital'
    custom_disk_serial: Optional[str] = None

class HardwareSpoofer:
    def __init__(self, config: Optional[HardwareConfig] = None):
        self.config = config or HardwareConfig()
    
    def generate_mac_address(self) -> str:
        if self.config.custom_mac:
            return self.config.custom_mac
        oui = random.choice(MAC_OUI.get(self.config.mac_vendor, MAC_OUI['intel']))
        return f"{oui}:{':'.join(f'{random.randint(0,255):02X}' for _ in range(3))}"
    
    def generate_disk_serial(self) -> str:
        if self.config.custom_disk_serial:
            return self.config.custom_disk_serial
        prefix = DISK_SERIAL.get(self.config.disk_vendor, 'WD-WCAV')
        return f"{prefix}{''.join(random.choices(string.ascii_uppercase + string.digits, k=8))}"

def get_hardware_args(image: str, mac_vendor: str = 'dell', disk_vendor: str = 'western_digital', network: bool = False) -> List[str]:
    h = HardwareSpoofer(HardwareConfig(mac_vendor=mac_vendor, disk_vendor=disk_vendor))
    args = ['-drive', f'file={image},if=none,id=disk0,format=qcow2,serial={h.generate_disk_serial()}', '-device', 'ide-hd,drive=disk0,bus=ide.0']
    if network:
        args.extend(['-netdev', 'user,id=net0', '-device', f'virtio-net-pci,netdev=net0,mac={h.generate_mac_address()}'])
    else:
        args.extend(['-nic', 'none'])
    return args

@dataclass
class SMBIOSProfile:
    bios_vendor: str = "Dell Inc."
    bios_version: str = "A12"
    bios_date: str = "03/15/2023"
    sys_manufacturer: str = "Dell Inc."
    sys_product: str = "OptiPlex 7080"
    sys_serial: str = ""
    sys_uuid: str = ""
    board_manufacturer: str = "Dell Inc."
    board_product: str = "0X8DXD"
    board_serial: str = ""
    chassis_manufacturer: str = "Dell Inc."
    chassis_type: int = 3
    chassis_serial: str = ""

SMBIOS_PROFILES = {
    'dell_optiplex': SMBIOSProfile(),
    'hp_prodesk': SMBIOSProfile(bios_vendor="HP", sys_manufacturer="HP", sys_product="HP ProDesk 400 G7", board_manufacturer="HP", chassis_manufacturer="HP"),
    'lenovo_thinkcentre': SMBIOSProfile(bios_vendor="LENOVO", sys_manufacturer="LENOVO", sys_product="ThinkCentre M920q", board_manufacturer="LENOVO", chassis_manufacturer="LENOVO"),
}

class SMBIOSSpoofer:
    def __init__(self, profile: Optional[SMBIOSProfile] = None, profile_name: str = 'dell_optiplex'):
        self.profile = profile or SMBIOS_PROFILES.get(profile_name, SMBIOS_PROFILES['dell_optiplex'])
        if not self.profile.sys_serial:
            self.profile.sys_serial = ''.join(random.choices(string.ascii_uppercase + string.digits, k=7))
        if not self.profile.sys_uuid:
            self.profile.sys_uuid = str(uuid.uuid4())
        if not self.profile.board_serial:
            self.profile.board_serial = f".{''.join(random.choices(string.ascii_uppercase + string.digits, k=10))}."
        if not self.profile.chassis_serial:
            self.profile.chassis_serial = self.profile.sys_serial
    
    def get_qemu_args(self) -> List[str]:
        p = self.profile
        return [
            '-smbios', f"type=0,vendor={p.bios_vendor},version={p.bios_version},date={p.bios_date}",
            '-smbios', f"type=1,manufacturer={p.sys_manufacturer},product={p.sys_product},serial={p.sys_serial},uuid={p.sys_uuid}",
            '-smbios', f"type=2,manufacturer={p.board_manufacturer},product={p.board_product},serial={p.board_serial}",
            '-smbios', f"type=3,manufacturer={p.chassis_manufacturer},type={p.chassis_type},serial={p.chassis_serial}",
        ]

def get_smbios_args(profile_name: str = 'dell_optiplex') -> List[str]:
    return SMBIOSSpoofer(profile_name=profile_name).get_qemu_args()

@dataclass
class TimingConfig:
    enable_invtsc: bool = True
    tsc_frequency: int = 3600000000
    kvmclock: bool = False

class TimingFixer:
    def __init__(self, config: Optional[TimingConfig] = None):
        self.config = config or TimingConfig()
    
    def get_cpu_timing_flags(self) -> List[str]:
        flags = []
        if self.config.enable_invtsc:
            flags.append('+invtsc')
        if self.config.tsc_frequency:
            flags.append(f'tsc-frequency={self.config.tsc_frequency}')
        if not self.config.kvmclock:
            flags.extend(['-kvmclock', '-kvmclock-stable-bit'])
        return flags
    
    def get_all_timing_args(self) -> List[str]:
        return ['-rtc', 'base=utc,clock=host,driftfix=slew']

def get_timing_args(stabilize: bool = True, tsc_freq: int = 3600000000) -> List[str]:
    return TimingFixer(TimingConfig(enable_invtsc=stabilize, tsc_frequency=tsc_freq)).get_all_timing_args() if stabilize else []

def get_timing_cpu_flags(stabilize: bool = True, tsc_freq: int = 3600000000) -> List[str]:
    return TimingFixer(TimingConfig(enable_invtsc=stabilize, tsc_frequency=tsc_freq)).get_cpu_timing_flags() if stabilize else []

@dataclass
class ThermalZone:
    name: str = "x86_pkg_temp"
    base_temp: int = 45
    def get_temp(self) -> int:
        return (self.base_temp + random.randint(-5, 5)) * 1000

@dataclass
class FanSensor:
    label: str = "CPU Fan"
    base_rpm: int = 2400
    def get_rpm(self) -> int:
        return self.base_rpm + random.randint(-200, 200)

@dataclass
class SensorsConfig:
    thermal_zones: List[ThermalZone] = field(default_factory=lambda: [ThermalZone(name="x86_pkg_temp", base_temp=47), ThermalZone(name="acpitz", base_temp=42)])
    fans: List[FanSensor] = field(default_factory=lambda: [FanSensor(label="CPU Fan"), FanSensor(label="System Fan", base_rpm=1800)])
    ac_online: bool = True

class SensorsFaker:
    def __init__(self, config: Optional[SensorsConfig] = None):
        self.config = config or SensorsConfig()
    
    def create_fake_sysfs(self, base: str = "/opt/anti_vm/fake_sysfs"):
        p = Path(base)
        for d in ["class/thermal", "class/hwmon", "class/power_supply"]:
            (p / d).mkdir(parents=True, exist_ok=True)
        for i, tz in enumerate(self.config.thermal_zones):
            zd = p / f"class/thermal/thermal_zone{i}"
            zd.mkdir(exist_ok=True)
            (zd / "temp").write_text(str(tz.get_temp()))
            (zd / "type").write_text(tz.name)
        hw = p / "class/hwmon/hwmon0"
        hw.mkdir(exist_ok=True)
        (hw / "name").write_text("coretemp")
        for i in range(4):
            (hw / f"temp{i+1}_input").write_text(str(45000 + random.randint(-3000, 5000)))
        hw1 = p / "class/hwmon/hwmon1"
        hw1.mkdir(exist_ok=True)
        (hw1 / "name").write_text("dell_smm")
        for i, fan in enumerate(self.config.fans):
            (hw1 / f"fan{i+1}_input").write_text(str(fan.get_rpm()))
        ac = p / "class/power_supply/AC"
        ac.mkdir(exist_ok=True)
        (ac / "type").write_text("Mains")
        (ac / "online").write_text("1" if self.config.ac_online else "0")

def create_desktop_sensors() -> SensorsFaker:
    return SensorsFaker(SensorsConfig())

@dataclass
class AntiVMQEMUConfig:
    architecture: str = "x86_64"
    use_kvm: bool = False
    ram_mb: int = 4096
    cpus: int = 4
    disk_image: str = ""
    smbios_profile: str = "dell_optiplex"
    mac_vendor: str = "dell"
    disk_vendor: str = "western_digital"
    network_enabled: bool = False
    display: str = "none"
    stabilize_timing: bool = True
    tsc_frequency: int = 3600000000
    hide_hypervisor: bool = True
    monitor_socket: Optional[str] = None
    serial_socket: Optional[str] = None
    agent_socket: Optional[str] = None

class QEMUArgsBuilder:
    def __init__(self, config: AntiVMQEMUConfig):
        self.config = config
        self.smbios = SMBIOSSpoofer(profile_name=config.smbios_profile)
        self.hardware = HardwareSpoofer(HardwareConfig(mac_vendor=config.mac_vendor, disk_vendor=config.disk_vendor))
        self.timing = TimingFixer(TimingConfig(enable_invtsc=config.stabilize_timing, tsc_frequency=config.tsc_frequency))
    
    def build_args(self) -> List[str]:
        c = self.config
        args = ["qemu-system-aarch64" if c.architecture == "aarch64" else "qemu-system-x86_64"]
        if c.architecture == "aarch64":
            m = "virt,accel=kvm,gic-version=3" if c.use_kvm else "virt,accel=tcg"
            args.extend(["-machine", m, "-cpu", "host" if c.use_kvm else "max"])
        else:
            args.extend(["-machine", "q35,accel=tcg,hpet=off"])
            cpu = ["qemu64"]
            if c.hide_hypervisor:
                cpu.extend(["-hypervisor"] + [f"-{f}" for f in KVM_FEATURES])
            if c.stabilize_timing:
                cpu.extend(self.timing.get_cpu_timing_flags())
            cpu.extend(["+sse4.1", "+sse4.2", "+avx", "+aes"])
            args.extend(["-cpu", ",".join(cpu)])
        args.extend(["-m", str(c.ram_mb), "-smp", str(c.cpus)])
        if c.architecture == "x86_64":
            args.extend(self.smbios.get_qemu_args())
        if c.disk_image:
            serial = self.hardware.generate_disk_serial()
            args.extend(["-drive", f"file={c.disk_image},if=none,id=disk0,format=qcow2,serial={serial}"])
            args.extend(["-device", "virtio-blk-pci,drive=disk0" if c.architecture == "aarch64" else "ide-hd,drive=disk0,bus=ide.0"])
        mac = self.hardware.generate_mac_address()
        if c.network_enabled:
            args.extend(["-netdev", "user,id=net0", "-device", f"virtio-net-pci,netdev=net0,mac={mac}"])
        else:
            args.extend(["-nic", "none"])
        if c.display == "none":
            args.extend(["-display", "none", "-nographic"])
        elif c.display == "vnc":
            args.extend(["-vnc", ":0"])
        args.extend(["-device", "qemu-xhci,id=xhci", "-device", "usb-kbd", "-device", "usb-mouse", "-device", "virtio-rng-pci"])
        args.extend(self.timing.get_all_timing_args())
        if c.monitor_socket:
            args.extend(["-qmp", f"unix:{c.monitor_socket},server,nowait"])
        if c.serial_socket:
            args.extend(["-chardev", f"socket,id=serial0,path={c.serial_socket},server=on,wait=off", "-serial", "chardev:serial0"])
        if c.agent_socket:
            args.extend(["-device", "virtio-serial-pci", "-chardev", f"socket,id=agent0,path={c.agent_socket},server=on,wait=off", "-device", "virtserialport,chardev=agent0,name=org.sandbox.agent"])
        return args

def build_anti_vm_args(architecture: str = "x86_64", disk_image: str = "", ram_mb: int = 4096, cpus: int = 4, smbios_profile: str = "dell_optiplex", hide_hypervisor: bool = True, network_enabled: bool = False, monitor_socket: Optional[str] = None, serial_socket: Optional[str] = None, agent_socket: Optional[str] = None) -> List[str]:
    return QEMUArgsBuilder(AntiVMQEMUConfig(architecture=architecture, disk_image=disk_image, ram_mb=ram_mb, cpus=cpus, smbios_profile=smbios_profile, hide_hypervisor=hide_hypervisor, network_enabled=network_enabled, monitor_socket=monitor_socket, serial_socket=serial_socket, agent_socket=agent_socket)).build_args()
