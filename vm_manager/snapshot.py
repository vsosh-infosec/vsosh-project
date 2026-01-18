"""
Snapshot Manager - Fast VM state save/restore for sandbox analysis
"""

import os
import json
import socket
import time
import logging
import subprocess
import threading
from typing import Optional, Dict, List, Any
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class SnapshotInfo:
    """Information about a VM snapshot"""
    name: str
    vm_name: str
    created_at: float
    description: str = ""
    size_bytes: int = 0


class SnapshotManager:
    """
    Manages VM snapshots for fast state save/restore.
    
    Uses QEMU's internal snapshots (savevm/loadvm) for speed,
    as they are stored within the qcow2 image and can be restored
    in 1-3 seconds without full VM restart.
    """
    
    def __init__(self, socket_path: str, timeout: float = 60.0):
        """
        Initialize snapshot manager.
        
        Args:
            socket_path: Path to QEMU QMP monitor socket
            timeout: Default timeout for QMP operations
        """
        self.socket_path = socket_path
        self._sock: Optional[socket.socket] = None
        self._timeout = timeout
        self._lock = threading.Lock()
    
    def _connect(self):
        """Connect to QMP socket"""
        if self._sock is not None:
            return
        
        logger.debug(f"Connecting to QMP socket: {self.socket_path}")
        
        if not os.path.exists(self.socket_path):
            raise ConnectionError(f"QMP socket does not exist: {self.socket_path}")
        
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(self._timeout)
        
        try:
            self._sock.connect(self.socket_path)
            logger.debug("Connected to QMP")
        except Exception as e:
            logger.error(f"Failed to connect to QMP: {e}")
            self._sock.close()
            self._sock = None
            raise
        
                                                             
        greeting = self._recv(expect_greeting=True)
        logger.debug(f"QMP greeting: {str(greeting)[:100]}")
        
                                       
        self._send({'execute': 'qmp_capabilities'})
        caps_resp = self._recv()
        logger.debug(f"QMP capabilities: {caps_resp}")
    
    def _disconnect(self):
        """Disconnect from QMP socket"""
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None
    
    def _send(self, command: Dict[str, Any]):
        """Send QMP command"""
        data = json.dumps(command) + '\n'
        self._sock.send(data.encode())
    
    def _recv(self, expect_greeting: bool = False) -> Dict[str, Any]:
        """Receive QMP response"""
        buffer = b''
        while True:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("QMP connection closed")
            buffer += chunk
            
                               
            try:
                                                               
                lines = buffer.decode().strip().split('\n')
                for line in lines:
                    if line.strip():
                        msg = json.loads(line)
                                                          
                        if expect_greeting and 'QMP' in msg:
                            return msg
                                                                             
                        if 'return' in msg or 'error' in msg:
                            return msg
                                                                     
            except json.JSONDecodeError:
                continue
    
    def _execute(self, command: str, arguments: Optional[Dict] = None, 
                 timeout: Optional[float] = None) -> Dict[str, Any]:
        """Execute a QMP command and return result"""
        with self._lock:
            old_timeout = self._timeout
            if timeout:
                self._timeout = timeout
            
            try:
                self._connect()
                
                cmd = {'execute': command}
                if arguments:
                    cmd['arguments'] = arguments
                
                self._send(cmd)
                
                                                          
                if timeout and self._sock:
                    self._sock.settimeout(timeout)
                
                response = self._recv()
                
                if 'error' in response:
                    raise RuntimeError(f"QMP error: {response['error']}")
                result = response.get('return', {})
                self._disconnect()
                return result
            except socket.timeout:
                logger.error(f"QMP command '{command}' timed out")
                self._disconnect()
                raise TimeoutError(f"QMP command '{command}' timed out")
            except Exception as e:
                                                                      
                self._disconnect()
                raise
            finally:
                self._timeout = old_timeout
    
    def create_snapshot(self, name: str, description: str = "", 
                        timeout: float = 120.0) -> SnapshotInfo:
        """
        Create a VM snapshot (savevm).
        
        This saves the complete VM state (memory, CPU, devices) to
        the qcow2 image. Takes 2-30 seconds depending on RAM size.
        
        Args:
            name: Snapshot name
            description: Optional description
            timeout: Timeout for snapshot operation (default 120s for large RAM)
            
        Returns:
            SnapshotInfo object
        """
        logger.info(f"Creating snapshot: {name} (timeout={timeout}s)")
        start_time = time.time()
        
        try:
                                                                                  
                                                                          
            result = self._execute('human-monitor-command', {
                'command-line': f'savevm {name}'
            }, timeout=timeout)
            
            duration = time.time() - start_time
            logger.info(f"Snapshot '{name}' created in {duration:.2f}s")
            
            return SnapshotInfo(
                name=name,
                vm_name="",
                created_at=time.time(),
                description=description,
            )
            
        except TimeoutError:
            logger.error(f"Snapshot creation timed out after {timeout}s")
            raise
        except Exception as e:
            logger.error(f"Failed to create snapshot: {e}")
            raise
    
    def restore_snapshot(self, name: str, timeout: float = 60.0) -> float:
        """
        Restore a VM snapshot (loadvm).
        
        This restores the complete VM state from a snapshot.
        Typically takes 1-5 seconds for live snapshots.
        
        Args:
            name: Snapshot name to restore
            timeout: Timeout for restore operation
            
        Returns:
            Time taken in seconds
        """
        logger.info(f"Restoring snapshot: {name} (timeout={timeout}s)")
        start_time = time.time()
        
        try:
            result = self._execute('human-monitor-command', {
                'command-line': f'loadvm {name}'
            }, timeout=timeout)
            
            duration = time.time() - start_time
            logger.info(f"Snapshot '{name}' restored in {duration:.2f}s")
            
            return duration
            
        except TimeoutError:
            logger.error(f"Snapshot restore timed out after {timeout}s")
            raise
        except Exception as e:
            logger.error(f"Failed to restore snapshot: {e}")
            raise
    
    def delete_snapshot(self, name: str):
        """Delete a VM snapshot"""
        logger.info(f"Deleting snapshot: {name}")
        
        try:
            self._execute('human-monitor-command', {
                'command-line': f'delvm {name}'
            })
            logger.info(f"Snapshot '{name}' deleted")
        except Exception as e:
            logger.error(f"Failed to delete snapshot: {e}")
            raise
    
    def list_snapshots(self) -> List[SnapshotInfo]:
        """List all snapshots for the VM"""
        try:
            result = self._execute('human-monitor-command', {
                'command-line': 'info snapshots'
            })
            
                                          
            snapshots = []
            if result:
                lines = result.strip().split('\n')
                for line in lines[1:]:               
                    parts = line.split()
                    if len(parts) >= 2:
                        snapshots.append(SnapshotInfo(
                            name=parts[1] if len(parts) > 1 else parts[0],
                            vm_name="",
                            created_at=0,
                        ))
            
            return snapshots
            
        except Exception as e:
            logger.error(f"Failed to list snapshots: {e}")
            return []
    
    def snapshot_exists(self, name: str) -> bool:
        """Check if a snapshot exists"""
        snapshots = self.list_snapshots()
        return any(s.name == name for s in snapshots)
    
    def close(self):
        """Close the snapshot manager"""
        self._disconnect()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


class ExternalSnapshotManager:
    """
    Alternative snapshot manager using external qcow2 snapshots.
    
    This approach creates a new overlay file for each analysis,
    which can be faster for some use cases but uses more disk space.
    """
    
    def __init__(self, base_image: str, snapshots_dir: str):
        """
        Initialize external snapshot manager.
        
        Args:
            base_image: Path to base qcow2 image
            snapshots_dir: Directory for overlay files
        """
        self.base_image = base_image
        self.snapshots_dir = snapshots_dir
        os.makedirs(snapshots_dir, exist_ok=True)
    
    def create_overlay(self, name: str) -> str:
        """
        Create a new overlay image based on the base image.
        
        Args:
            name: Overlay name
            
        Returns:
            Path to overlay image
        """
        overlay_path = os.path.join(self.snapshots_dir, f"{name}.qcow2")
        
        cmd = [
            'qemu-img', 'create',
            '-f', 'qcow2',
            '-F', 'qcow2',
            '-b', os.path.abspath(self.base_image),
            overlay_path
        ]
        
        subprocess.run(cmd, check=True, capture_output=True)
        logger.info(f"Created overlay: {overlay_path}")
        
        return overlay_path
    
    def delete_overlay(self, name: str):
        """Delete an overlay image"""
        overlay_path = os.path.join(self.snapshots_dir, f"{name}.qcow2")
        if os.path.exists(overlay_path):
            os.unlink(overlay_path)
            logger.info(f"Deleted overlay: {overlay_path}")
    
    def commit_overlay(self, name: str):
        """
        Commit overlay changes to base image.
        WARNING: This modifies the base image!
        """
        overlay_path = os.path.join(self.snapshots_dir, f"{name}.qcow2")
        
        cmd = ['qemu-img', 'commit', overlay_path]
        subprocess.run(cmd, check=True, capture_output=True)
        
        logger.info(f"Committed overlay to base: {name}")
    
    def rebase_overlay(self, name: str, new_base: str):
        """Rebase overlay to a new base image"""
        overlay_path = os.path.join(self.snapshots_dir, f"{name}.qcow2")
        
        cmd = [
            'qemu-img', 'rebase',
            '-b', new_base,
            '-F', 'qcow2',
            overlay_path
        ]
        
        subprocess.run(cmd, check=True, capture_output=True)
        logger.info(f"Rebased overlay {name} to {new_base}")
    
    def get_overlay_info(self, name: str) -> Dict[str, Any]:
        """Get information about an overlay image"""
        overlay_path = os.path.join(self.snapshots_dir, f"{name}.qcow2")
        
        cmd = ['qemu-img', 'info', '--output=json', overlay_path]
        result = subprocess.run(cmd, check=True, capture_output=True)
        
        return json.loads(result.stdout)
    
    def list_overlays(self) -> List[str]:
        """List all overlay images"""
        overlays = []
        for f in os.listdir(self.snapshots_dir):
            if f.endswith('.qcow2'):
                overlays.append(f[:-6])                           
        return overlays
    
    def cleanup_old_overlays(self, max_age_hours: int = 24):
        """Remove overlay files older than specified hours"""
        import time
        cutoff = time.time() - (max_age_hours * 3600)
        
        for f in os.listdir(self.snapshots_dir):
            path = os.path.join(self.snapshots_dir, f)
            if os.path.getmtime(path) < cutoff:
                os.unlink(path)
                logger.info(f"Cleaned up old overlay: {f}")
