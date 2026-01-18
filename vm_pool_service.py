                      
"""
Persistent VM Pool Service

This script keeps VMs warmed up and ready for analysis.
Run this as a systemd service or in the background to have VMs always ready.

Usage:
    python3 vm_pool_service.py

Features:
    - Starts ARM64 and X64 VMs in parallel
    - Creates live snapshots for fast restore
    - Monitors VM health
    - Auto-recovers from errors
"""

import os
import sys
import time
import signal
import logging

                     
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vm_manager import VMManager, VMPool
from vm_manager.vm_config import VMArchitecture

                   
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/vm_pool_service.log')
    ]
)
logger = logging.getLogger('VMPoolService')

                            
pool = None
running = True


def signal_handler(signum, frame):
    global running
    logger.info(f"Received signal {signum}, shutting down...")
    running = False


def main():
    global pool, running
    
                           
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
                                  
    os.makedirs('logs', exist_ok=True)
    
    logger.info("=" * 50)
    logger.info("VM Pool Service Starting")
    logger.info("=" * 50)
    
                           
    try:
        vm_manager = VMManager(config_path='vm_config.yaml')
        pool = VMPool(vm_manager)
    except Exception as e:
        logger.error(f"Failed to initialize: {e}")
        return 1
    
                  
    logger.info("Starting VM warmup...")
    logger.info("  ARM64: KVM acceleration (fast boot)")
    logger.info("  X64: TCG emulation (slow boot, ~15-20 min)")
    logger.info("")
    
                         
    results = pool.warmup(blocking=False)
    
                  
    last_status_time = 0
    STATUS_INTERVAL = 60                                 
    
    while running:
        current_time = time.time()
        
                                   
        if current_time - last_status_time >= STATUS_INTERVAL:
            arm64_state = pool.get_state(VMArchitecture.ARM64)
            x64_state = pool.get_state(VMArchitecture.X64)
            
            logger.info(f"VM Pool Status: ARM64={arm64_state.value}, X64={x64_state.value}")
            
            if arm64_state.value == 'ready':
                logger.info("  ARM64 ready for analysis ✓")
            elif arm64_state.value == 'warming':
                logger.info("  ARM64 warming up...")
                
            if x64_state.value == 'ready':
                logger.info("  X64 ready for analysis ✓")
            elif x64_state.value == 'warming':
                logger.info("  X64 warming up (TCG - this takes ~15-20 min)...")
            elif x64_state.value == 'error':
                logger.warning(f"  X64 error: {pool._warmup_errors.get(VMArchitecture.X64)}")
            
            last_status_time = current_time
        
        time.sleep(5)
    
    logger.info("VM Pool Service stopped")
    return 0


if __name__ == '__main__':
    sys.exit(main())
