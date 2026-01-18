"""
VM Manager - QEMU/KVM Virtual Machine Management for Malware Analysis

This module provides a high-level API for managing virtual machines
with support for fast snapshots and anti-VM detection evasion.
"""

from .vm_config import VMConfig, VMArchitecture
from .qemu_launcher import QEMULauncher
from .snapshot import SnapshotManager
from .vm_manager import VMManager
from .vm_pool import VMPool

__all__ = [
    'VMConfig',
    'VMArchitecture', 
    'QEMULauncher',
    'SnapshotManager',
    'VMManager',
    'VMPool',
]

__version__ = '1.0.0'
