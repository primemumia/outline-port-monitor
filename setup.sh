#!/bin/bash

#########################################################################
# OUTLINE MONITOR AUTOMATIC SETUP SCRIPT
# Automatically installs and configures the Interactive Outline Monitor
# 
# Features:
# - Interactive Outline Management port detection/setup
# - Monitors ALL ports 1024-65535 (except management port)
# - 2-minute IP blocking on port changes
# - 1-second monitoring interval
# - Auto-start on boot with systemd
# - Complete logging and monitoring
#########################################################################

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Script variables
SCRIPT_NAME="outline-monitor"
INSTALL_DIR="/opt/outline-monitor"
SERVICE_NAME="outline-monitor"
LOG_FILE="/var/log/outline-monitor-setup.log"

# Functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a "$LOG_FILE"
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1" | tee -a "$LOG_FILE"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a "$LOG_FILE"
}

log_info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO:${NC} $1" | tee -a "$LOG_FILE"
}

# Header
print_header() {
    clear
    echo -e "${PURPLE}"
    echo "########################################################################"
    echo "#                OUTLINE MONITOR AUTOMATIC SETUP                      #"
    echo "#                                                                      #"
    echo "#  🔐 Advanced Port Protection System                                 #"
    echo "#  🚀 Interactive Outline Management Port Detection                   #"
    echo "#  📡 Monitors ALL ports 1024-65535 (except management)              #"
    echo "#  ⚡ 1-second monitoring, 2-minute IP blocking                       #"
    echo "#  🛡️  Permanent system integration with systemd                      #"
    echo "#                                                                      #"
    echo "########################################################################"
    echo -e "${NC}"
    echo
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root. Use: sudo $0"
        exit 1
    fi
    log "✅ Root privileges confirmed"
}

# Check system requirements
check_requirements() {
    log "🔍 Checking system requirements..."
    
    # Check OS
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot determine OS version"
        exit 1
    fi
    
    source /etc/os-release
    log "✅ OS: $PRETTY_NAME"
    
    # Check required commands
    local required_commands=("python3" "systemctl" "iptables" "ss")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log_error "Required command '$cmd' not found"
            exit 1
        fi
    done
    log "✅ All required commands available"
    
    # Check Python version
    local python_version=$(python3 --version 2>&1 | grep -oE '[0-9]+\.[0-9]+')
    local major=$(echo $python_version | cut -d. -f1)
    local minor=$(echo $python_version | cut -d. -f2)
    
    if [[ $major -lt 3 ]] || [[ $major -eq 3 && $minor -lt 6 ]]; then
        log_error "Python 3.6+ required. Found: $python_version"
        exit 1
    fi
    log "✅ Python version: $python_version"
}

# Install required packages
install_packages() {
    log "📦 Installing required packages..."
    
    # Update package list
    apt-get update -qq
    
    # Install packages
    local packages=("python3" "python3-pip" "iptables" "iproute2" "systemd")
    
    for package in "${packages[@]}"; do
        if ! dpkg -l | grep -q "^ii  $package "; then
            log "Installing: $package"
            apt-get install -y "$package" >> "$LOG_FILE" 2>&1
        else
            log "✅ Already installed: $package"
        fi
    done
    
    log "✅ All packages installed"
}

# Create installation directory
create_directories() {
    log "📁 Creating directories..."
    
    # Create installation directory
    mkdir -p "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"
    
    # Create log directory
    mkdir -p "/var/log"
    touch "/var/log/outline-monitor.log"
    chmod 644 "/var/log/outline-monitor.log"
    
    log "✅ Directories created"
}

# Install Python script
install_python_script() {
    log "🐍 Installing Python monitoring script..."
    
    # Create the interactive monitor script
    cat > "$INSTALL_DIR/outline_monitor_interactive.py" << 'PYTHON_EOF'
#!/usr/bin/env python3
"""
Interactive Outline Monitor - Dynamic Port Protection
Reads configuration from config file or asks for setup
"""

import subprocess
import time
import re
import threading
import signal
import logging
import sys
import os
import json
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

CONFIG_FILE = "/opt/outline-monitor/config.json"

def setup_logging():
    """Logging yapılandırması"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/var/log/outline-monitor.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def load_config():
    """Konfigürasyon dosyasından ayarları yükle"""
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
        return config
    except FileNotFoundError:
        print(f"❌ Configuration file not found: {CONFIG_FILE}")
        print("🔧 Please run: outline-monitor setup")
        return None
    except json.JSONDecodeError:
        print(f"❌ Invalid configuration file: {CONFIG_FILE}")
        return None

def detect_outline_ports():
    """Outline server portlarını otomatik tespit et"""
    try:
        cmd = "ss -tuln | awk 'NR>1 {print $5}' | grep -oE ':[0-9]+$' | cut -c2- | sort -n | uniq"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        
        active_ports = []
        for line in result.stdout.split('\n'):
            if line.strip():
                try:
                    port = int(line.strip())
                    active_ports.append(port)
                except ValueError:
                    continue
        
        detected_management = []
        for port in active_ports:
            if 27000 <= port <= 27100:
                detected_management.append(port)
        
        return detected_management, active_ports
        
    except Exception as e:
        print(f"Port detection error: {e}")
        return [], []

def get_outline_management_port():
    """Kullanıcıdan Outline Management portunu al"""
    print("\n" + "="*60)
    print("🔍 OUTLINE SERVER PORT DETECTION")
    print("="*60)
    
    detected_mgmt, all_ports = detect_outline_ports()
    
    if detected_mgmt:
        print(f"📡 Detected possible Outline Management ports: {detected_mgmt}")
        for port in detected_mgmt:
            choice = input(f"Is {port} your Outline Management port? (y/n): ").lower().strip()
            if choice in ['y', 'yes']:
                return port
    
    print("\n🔧 Please enter your Outline Server Management port manually:")
    print("   (This is usually between 27000-27100)")
    print("   (Check your Outline Manager URL: https://your-ip:PORT)")
    
    while True:
        try:
            port_input = input("\nOutline Management Port: ").strip()
            management_port = int(port_input)
            
            if 1 <= management_port <= 65535:
                confirm = input(f"Confirm Outline Management port {management_port}? (y/n): ").lower().strip()
                if confirm in ['y', 'yes']:
                    return management_port
            else:
                print("❌ Port must be between 1-65535")
                
        except ValueError:
            print("❌ Please enter a valid number")
        except KeyboardInterrupt:
            print("\n❌ Setup cancelled")
            sys.exit(1)

def save_config(management_port):
    """Konfigürasyonu kaydet"""
    config = {
        "management_port": management_port,
        "monitor_range": [1024, 65535],
        "check_interval": 1,
        "block_duration": 120
    }
    
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)
    
    return config

class InteractiveOutlineMonitor:
    def __init__(self, config=None):
        if config is None:
            # Interactive setup mode
            print("🔧 Configuration setup required...")
            management_port = get_outline_management_port()
            config = save_config(management_port)
            print(f"\n✅ Configuration saved! Management port: {management_port}")
        
        # Load configuration
        self.management_port = config["management_port"]
        self.FORBIDDEN_PORTS = [self.management_port]
        self.dynamic_range = tuple(config["monitor_range"])
        
        # Performance ayarları
        self.CHECK_INTERVAL = config["check_interval"]
        self.BLOCK_DURATION = config["block_duration"]
        self.MAX_WORKERS = 15
        self.BATCH_SIZE = 100
        
        # Port yönetimi
        self.active_ports = {}
        self.blocked_ips = {}
        
        # Monitoring durumu
        self.running = True
        self.stats = {
            'scanned_ports': 0,
            'active_ports': 0,
            'blocked_ips': 0,
            'total_connections': 0
        }
        
        self.executor = ThreadPoolExecutor(max_workers=self.MAX_WORKERS)
        self.logger = setup_logging()
    
    def get_active_ports_safe(self):
        """Aktif portları tespit et - Management port'u ATLA"""
        try:
            cmd = "ss -tuln | awk 'NR>1 {print $5}' | grep -oE ':[0-9]+$' | cut -c2- | sort -n | uniq"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            
            active_ports = []
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    try:
                        port = int(line.strip())
                        
                        if port in self.FORBIDDEN_PORTS:
                            self.logger.debug(f"⚠️  Port {port} FORBIDDEN - Skipped (Management port)")
                            continue
                        
                        if self.dynamic_range[0] <= port <= self.dynamic_range[1]:
                            active_ports.append(port)
                            
                    except ValueError:
                        continue
            
            return active_ports
            
        except Exception as e:
            self.logger.error(f"Active port detection error: {e}")
            return []
    
    def scan_port_ips(self, port):
        """Tek port'un IP'lerini tara"""
        try:
            if port in self.FORBIDDEN_PORTS:
                self.logger.warning(f"🚨 CRITICAL: Port {port} is forbidden! Skipping!")
                return []
            
            cmd = f"ss -tn state established '( dport = :{port} or sport = :{port} )'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3)
            
            unique_ips = set()
            
            for line in result.stdout.split('\n'):
                if f':{port}' in line and not line.startswith('Recv-Q'):
                    ips = re.findall(r'(?:::ffff:)?(\d+\.\d+\.\d+\.\d+)', line)
                    for ip in ips:
                        if not self.is_local_ip(ip):
                            unique_ips.add(ip)
            
            return list(unique_ips)
            
        except Exception as e:
            self.logger.debug(f"Port {port} scan error: {e}")
            return []
    
    def scan_ports_batch(self, ports_batch):
        """Port batch'ini parallel tara"""
        batch_results = {}
        
        for port in ports_batch:
            if port in self.FORBIDDEN_PORTS:
                self.logger.warning(f"🚨 BATCH CHECK: Port {port} forbidden - SKIPPING!")
                continue
                
            ips = self.scan_port_ips(port)
            if ips:
                batch_results[port] = ips
        
        return batch_results
    
    def is_local_ip(self, ip):
        """Local IP kontrolü"""
        try:
            parts = ip.split('.')
            first = int(parts[0])
            second = int(parts[1]) if len(parts) > 1 else 0
            
            return (first == 10 or first == 127 or 
                   (first == 192 and second == 168) or
                   (first == 172 and 16 <= second <= 31))
        except:
            return True
    
    def block_ip_async(self, ip, port, reason="IP change"):
        """IP'yi asenkron engelle"""
        def _block_task():
            try:
                if port in self.FORBIDDEN_PORTS:
                    self.logger.error(f"🚨 CRITICAL ERROR: Port {port} is management port - Blocking CANCELLED!")
                    return
                
                end_time = datetime.now() + timedelta(seconds=self.BLOCK_DURATION)
                
                self.logger.warning(f"🚫 Blocking IP {ip} (Port {port}) - {reason}")
                self.logger.info(f"⏰ Block until: {end_time.strftime('%H:%M:%S')}")
                
                commands = [
                    ['iptables', '-I', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', str(port), '-j', 'DROP'],
                    ['iptables', '-I', 'INPUT', '-s', ip, '-p', 'udp', '--dport', str(port), '-j', 'DROP'],
                    ['iptables', '-I', 'OUTPUT', '-d', ip, '-p', 'tcp', '--sport', str(port), '-j', 'DROP'],
                    ['iptables', '-I', 'OUTPUT', '-d', ip, '-p', 'udp', '--sport', str(port), '-j', 'DROP']
                ]
                
                success_count = 0
                for cmd in commands:
                    try:
                        subprocess.run(cmd, check=True, timeout=5)
                        success_count += 1
                    except subprocess.CalledProcessError:
                        pass
                
                if success_count > 0:
                    block_key = f"{ip}:{port}"
                    self.blocked_ips[block_key] = end_time
                    self.stats['blocked_ips'] = len(self.blocked_ips)
                    self.logger.info(f"✅ IP {ip} blocked for port {port} ({success_count}/4 rules)")
                    
                    time.sleep(self.BLOCK_DURATION)
                    self.unblock_ip(ip, port)
                
            except Exception as e:
                self.logger.error(f"Block task error for IP {ip}: {e}")
        
        thread = threading.Thread(target=_block_task, name=f"Block-{ip}-{port}")
        thread.daemon = True
        thread.start()
    
    def unblock_ip(self, ip, port):
        """IP engeli kaldır"""
        try:
            self.logger.info(f"🔓 Unblocking IP {ip} for port {port}")
            
            commands = [
                ['iptables', '-D', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', str(port), '-j', 'DROP'],
                ['iptables', '-D', 'INPUT', '-s', ip, '-p', 'udp', '--dport', str(port), '-j', 'DROP'],
                ['iptables', '-D', 'OUTPUT', '-d', ip, '-p', 'tcp', '--sport', str(port), '-j', 'DROP'],
                ['iptables', '-D', 'OUTPUT', '-d', ip, '-p', 'udp', '--sport', str(port), '-j', 'DROP']
            ]
            
            for cmd in commands:
                subprocess.run(cmd, check=False, timeout=5)
            
            block_key = f"{ip}:{port}"
            if block_key in self.blocked_ips:
                del self.blocked_ips[block_key]
                self.stats['blocked_ips'] = len(self.blocked_ips)
            
            self.logger.info(f"✅ IP {ip} unblocked for port {port}")
            
        except Exception as e:
            self.logger.error(f"Unblock error for IP {ip}:{port}: {e}")
    
    def process_port_changes(self, port, current_ips, previous_ips):
        """Port IP değişimlerini işle"""
        if not previous_ips:
            if current_ips:
                self.active_ports[port] = current_ips.copy()
                self.logger.info(f"📡 Port {port}: {len(current_ips)} IPs detected")
            return
        
        current_set = set(current_ips)
        previous_set = set(previous_ips)
        
        new_ips = current_set - previous_set
        lost_ips = previous_set - current_set
        
        if new_ips or lost_ips:
            self.logger.warning(f"🔄 Port {port}: IP change detected!")
            
            if new_ips:
                self.logger.warning(f"🆕 New IPs: {list(new_ips)}")
                
                ips_to_block = previous_set - new_ips
                for old_ip in ips_to_block:
                    block_key = f"{old_ip}:{port}"
                    if block_key not in self.blocked_ips:
                        self.block_ip_async(old_ip, port, "New IP detected")
            
            if lost_ips:
                self.logger.info(f"📤 Lost IPs: {list(lost_ips)}")
            
            self.active_ports[port] = current_ips.copy()
            self.logger.info(f"✅ Port {port}: Updated to {len(current_ips)} active IPs")
    
    def main_monitoring_loop(self):
        """Ana monitoring döngüsü"""
        scan_count = 0
        
        while self.running:
            start_time = time.time()
            
            try:
                active_ports = self.get_active_ports_safe()
                
                if not active_ports:
                    self.logger.debug("No monitorable ports found")
                    time.sleep(self.CHECK_INTERVAL)
                    continue
                
                port_batches = [active_ports[i:i + self.BATCH_SIZE] 
                               for i in range(0, len(active_ports), self.BATCH_SIZE)]
                
                futures = []
                for batch in port_batches:
                    future = self.executor.submit(self.scan_ports_batch, batch)
                    futures.append(future)
                
                all_results = {}
                for future in as_completed(futures, timeout=10):
                    try:
                        batch_result = future.result()
                        all_results.update(batch_result)
                    except Exception as e:
                        self.logger.error(f"Batch scan error: {e}")
                
                changes_detected = 0
                total_connections = 0
                
                for port, current_ips in all_results.items():
                    if current_ips:
                        total_connections += len(current_ips)
                        
                        previous_ips = self.active_ports.get(port, [])
                        current_set = set(current_ips)
                        previous_set = set(previous_ips)
                        
                        if current_set != previous_set:
                            self.process_port_changes(port, current_ips, previous_ips)
                            changes_detected += 1
                
                scan_count += 1
                elapsed = time.time() - start_time
                
                self.stats.update({
                    'scanned_ports': len(active_ports),
                    'active_ports': len(all_results),
                    'total_connections': total_connections
                })
                
                if scan_count % 60 == 0:
                    blocked_summary = len(self.blocked_ips)
                    self.logger.info(f"📊 1min Report: {self.stats['active_ports']} active ports, "
                                  f"{total_connections} total connections, "
                                  f"{blocked_summary} blocks, {elapsed:.2f}s scan")
                
                if changes_detected > 0:
                    self.logger.info(f"🔄 {changes_detected} port changes detected this scan")
                
                sleep_time = max(0.1, self.CHECK_INTERVAL - elapsed)
                time.sleep(sleep_time)
                
            except Exception as e:
                self.logger.error(f"Main monitoring error: {e}")
                time.sleep(2)
    
    def start(self):
        """Monitoring başlat"""
        self.logger.info("🚀 INTERACTIVE Outline Monitor Starting")
        self.logger.info(f"🚨 PROTECTED MANAGEMENT PORT: {self.management_port}")
        self.logger.info(f"📡 MONITORING ALL PORTS: {self.dynamic_range[0]}-{self.dynamic_range[1]} (except {self.management_port})")
        self.logger.info(f"⚡ Ultra Fast Scan: {self.CHECK_INTERVAL}s interval")
        self.logger.info(f"🚫 Block Duration: {self.BLOCK_DURATION//60}min")
        self.logger.info(f"🔧 Performance: {self.MAX_WORKERS} workers, {self.BATCH_SIZE} batch size")
        self.logger.info("=" * 80)
        
        try:
            self.main_monitoring_loop()
        except KeyboardInterrupt:
            self.logger.info("⏹️  Shutdown requested...")
            self.stop()
    
    def stop(self):
        """Güvenli kapatma"""
        self.running = False
        
        self.logger.info("🧹 Clearing all blocks...")
        blocked_count = len(self.blocked_ips)
        
        for block_key in list(self.blocked_ips.keys()):
            try:
                ip, port = block_key.split(':')
                self.unblock_ip(ip, int(port))
            except Exception as e:
                self.logger.error(f"Cleanup error for {block_key}: {e}")
        
        self.executor.shutdown(wait=True)
        
        if blocked_count > 0:
            self.logger.info(f"✅ Cleared {blocked_count} IP blocks")
        
        self.logger.info("✅ INTERACTIVE Outline Monitor stopped safely")

# Signal handling
monitor = None

def signal_handler(signum, frame):
    global monitor
    if monitor:
        monitor.stop()
    exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ This script must be run as root (use sudo)")
        sys.exit(1)
    
    # Load or create configuration
    config = load_config()
    
    if config is None:
        print("🔧 No configuration found. Running setup...")
        sys.exit(1)
    
    print(f"\n✅ Loaded configuration - Management Port: {config['management_port']}")
    print("🔄 Starting monitoring system...")
    
    monitor = InteractiveOutlineMonitor(config)
    monitor.start()
PYTHON_EOF
#!/usr/bin/env python3
"""
Interactive Outline Monitor - Dynamic Port Protection
Automatically detects or asks for Outline Server port
Protects Management port + monitors all other ports in 1024-65535 range
"""

import subprocess
import time
import re
import threading
import signal
import logging
import sys
import os
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

def setup_logging():
    """Logging yapılandırması"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/var/log/outline-monitor.log'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

def detect_outline_ports():
    """Outline server portlarını otomatik tespit et"""
    try:
        # Outline Manager portları (varsayılan aralıklar)
        management_candidates = []
        
        # ss ile aktif portları kontrol et
        cmd = "ss -tuln | awk 'NR>1 {print $5}' | grep -oE ':[0-9]+$' | cut -c2- | sort -n | uniq"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        
        active_ports = []
        for line in result.stdout.split('\n'):
            if line.strip():
                try:
                    port = int(line.strip())
                    active_ports.append(port)
                except ValueError:
                    continue
        
        # Outline tipik port aralıkları
        outline_ranges = [
            (27000, 27100),  # Management port aralığı
            (50000, 60000),  # Client port aralığı  
        ]
        
        detected_management = []
        for port in active_ports:
            if 27000 <= port <= 27100:  # Management port olabilir
                detected_management.append(port)
        
        return detected_management, active_ports
        
    except Exception as e:
        print(f"Port detection error: {e}")
        return [], []

def get_outline_management_port():
    """Kullanıcıdan Outline Management portunu al veya otomatik tespit et"""
    print("\n" + "="*60)
    print("🔍 OUTLINE SERVER PORT DETECTION")
    print("="*60)
    
    # Otomatik tespit
    detected_mgmt, all_ports = detect_outline_ports()
    
    if detected_mgmt:
        print(f"📡 Detected possible Outline Management ports: {detected_mgmt}")
        for port in detected_mgmt:
            choice = input(f"Is {port} your Outline Management port? (y/n): ").lower().strip()
            if choice in ['y', 'yes']:
                return port
    
    # Manuel giriş
    print("\n🔧 Please enter your Outline Server Management port manually:")
    print("   (This is usually between 27000-27100)")
    print("   (Check your Outline Manager URL: https://your-ip:PORT)")
    
    while True:
        try:
            port_input = input("\nOutline Management Port: ").strip()
            management_port = int(port_input)
            
            if 1 <= management_port <= 65535:
                confirm = input(f"Confirm Outline Management port {management_port}? (y/n): ").lower().strip()
                if confirm in ['y', 'yes']:
                    return management_port
                else:
                    continue
            else:
                print("❌ Port must be between 1-65535")
                
        except ValueError:
            print("❌ Please enter a valid number")
        except KeyboardInterrupt:
            print("\n❌ Setup cancelled")
            sys.exit(1)

class InteractiveOutlineMonitor:
    def __init__(self, management_port):
        # KRITIK: Management port'u kullanıcıdan al
        self.FORBIDDEN_PORTS = [management_port]  # Dynamic management port
        self.management_port = management_port
        
        # İzlenecek portlar - TÜM aralık (management hariç)
        self.dynamic_range = (1024, 65535)  # Tüm dinamik portlar
        
        # Port yönetimi
        self.active_ports = {}              # Port -> IP mapping
        self.blocked_ips = {}               # IP -> end_time
        
        # Performance ayarları
        self.CHECK_INTERVAL = 1             # 1 saniyede bir kontrol
        self.BLOCK_DURATION = 120           # 2 dakika engelleme
        self.MAX_WORKERS = 15               # Thread pool
        self.BATCH_SIZE = 100               # Port batch boyutu
        
        # Monitoring durumu
        self.running = True
        self.stats = {
            'scanned_ports': 0,
            'active_ports': 0,
            'blocked_ips': 0,
            'total_connections': 0
        }
        
        self.executor = ThreadPoolExecutor(max_workers=self.MAX_WORKERS)
        
        # Logger
        self.logger = setup_logging()
    
    def get_active_ports_safe(self):
        """Aktif portları tespit et - Management port'u ATLA"""
        try:
            # Sadece LISTEN ve ESTABLISHED portları
            cmd = "ss -tuln | awk 'NR>1 {print $5}' | grep -oE ':[0-9]+$' | cut -c2- | sort -n | uniq"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            
            active_ports = []
            
            for line in result.stdout.split('\n'):
                if line.strip():
                    try:
                        port = int(line.strip())
                        
                        # KRITIK KONTROL: Forbidden port'ları atla!
                        if port in self.FORBIDDEN_PORTS:
                            self.logger.debug(f"⚠️  Port {port} FORBIDDEN - Skipped (Management port)")
                            continue
                        
                        # İzlenecek aralıkta mı? (TÜM PORTLAR 1024-65535)
                        if self.dynamic_range[0] <= port <= self.dynamic_range[1]:
                            active_ports.append(port)
                            
                    except ValueError:
                        continue
            
            return active_ports
            
        except Exception as e:
            self.logger.error(f"Active port detection error: {e}")
            return []
    
    def scan_port_ips(self, port):
        """Tek port'un IP'lerini tara"""
        try:
            # DOUBLE CHECK: Forbidden port kontrolü
            if port in self.FORBIDDEN_PORTS:
                self.logger.warning(f"🚨 CRITICAL: Port {port} is forbidden! Skipping!")
                return []
            
            cmd = f"ss -tn state established '( dport = :{port} or sport = :{port} )'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=3)
            
            unique_ips = set()
            
            for line in result.stdout.split('\n'):
                if f':{port}' in line and not line.startswith('Recv-Q'):
                    # IPv6 mapped format destekli IP extraction
                    ips = re.findall(r'(?:::ffff:)?(\d+\.\d+\.\d+\.\d+)', line)
                    for ip in ips:
                        if not self.is_local_ip(ip):
                            unique_ips.add(ip)
            
            return list(unique_ips)
            
        except Exception as e:
            self.logger.debug(f"Port {port} scan error: {e}")
            return []
    
    def scan_ports_batch(self, ports_batch):
        """Port batch'ini parallel tara"""
        batch_results = {}
        
        for port in ports_batch:
            # TRIPLE CHECK: Her port için forbidden kontrolü
            if port in self.FORBIDDEN_PORTS:
                self.logger.warning(f"🚨 BATCH CHECK: Port {port} forbidden - SKIPPING!")
                continue
                
            ips = self.scan_port_ips(port)
            if ips:  # Sadece IP'si olan portları kaydet
                batch_results[port] = ips
        
        return batch_results
    
    def is_local_ip(self, ip):
        """Local IP kontrolü"""
        try:
            parts = ip.split('.')
            first = int(parts[0])
            second = int(parts[1]) if len(parts) > 1 else 0
            
            return (first == 10 or first == 127 or 
                   (first == 192 and second == 168) or
                   (first == 172 and 16 <= second <= 31))
        except:
            return True
    
    def block_ip_async(self, ip, port, reason="IP change"):
        """IP'yi asenkron engelle"""
        def _block_task():
            try:
                # FINAL CHECK: Forbidden port için engelleme yapma!
                if port in self.FORBIDDEN_PORTS:
                    self.logger.error(f"🚨 CRITICAL ERROR: Port {port} is management port - Blocking CANCELLED!")
                    return
                
                end_time = datetime.now() + timedelta(seconds=self.BLOCK_DURATION)
                
                self.logger.warning(f"🚫 Blocking IP {ip} (Port {port}) - {reason}")
                self.logger.info(f"⏰ Block until: {end_time.strftime('%H:%M:%S')}")
                
                # Port-specific blocking (sadece bu port için)
                commands = [
                    ['iptables', '-I', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', str(port), '-j', 'DROP'],
                    ['iptables', '-I', 'INPUT', '-s', ip, '-p', 'udp', '--dport', str(port), '-j', 'DROP'],
                    ['iptables', '-I', 'OUTPUT', '-d', ip, '-p', 'tcp', '--sport', str(port), '-j', 'DROP'],
                    ['iptables', '-I', 'OUTPUT', '-d', ip, '-p', 'udp', '--sport', str(port), '-j', 'DROP']
                ]
                
                success_count = 0
                for cmd in commands:
                    try:
                        subprocess.run(cmd, check=True, timeout=5)
                        success_count += 1
                    except subprocess.CalledProcessError:
                        pass  # Kural zaten var olabilir
                
                if success_count > 0:
                    block_key = f"{ip}:{port}"
                    self.blocked_ips[block_key] = end_time
                    self.stats['blocked_ips'] = len(self.blocked_ips)
                    self.logger.info(f"✅ IP {ip} blocked for port {port} ({success_count}/4 rules)")
                    
                    # Auto-unblock timer
                    time.sleep(self.BLOCK_DURATION)
                    self.unblock_ip(ip, port)
                
            except Exception as e:
                self.logger.error(f"Block task error for IP {ip}: {e}")
        
        # Background thread
        thread = threading.Thread(target=_block_task, name=f"Block-{ip}-{port}")
        thread.daemon = True
        thread.start()
    
    def unblock_ip(self, ip, port):
        """IP engeli kaldır"""
        try:
            self.logger.info(f"🔓 Unblocking IP {ip} for port {port}")
            
            commands = [
                ['iptables', '-D', 'INPUT', '-s', ip, '-p', 'tcp', '--dport', str(port), '-j', 'DROP'],
                ['iptables', '-D', 'INPUT', '-s', ip, '-p', 'udp', '--dport', str(port), '-j', 'DROP'],
                ['iptables', '-D', 'OUTPUT', '-d', ip, '-p', 'tcp', '--sport', str(port), '-j', 'DROP'],
                ['iptables', '-D', 'OUTPUT', '-d', ip, '-p', 'udp', '--sport', str(port), '-j', 'DROP']
            ]
            
            for cmd in commands:
                subprocess.run(cmd, check=False, timeout=5)
            
            # Block listesinden kaldır
            block_key = f"{ip}:{port}"
            if block_key in self.blocked_ips:
                del self.blocked_ips[block_key]
                self.stats['blocked_ips'] = len(self.blocked_ips)
            
            self.logger.info(f"✅ IP {ip} unblocked for port {port}")
            
        except Exception as e:
            self.logger.error(f"Unblock error for IP {ip}:{port}: {e}")
    
    def process_port_changes(self, port, current_ips, previous_ips):
        """Port IP değişimlerini işle"""
        if not previous_ips:  # İlk tarama
            if current_ips:
                self.active_ports[port] = current_ips.copy()
                self.logger.info(f"📡 Port {port}: {len(current_ips)} IPs detected")
            return
        
        # IP değişimi kontrolü
        current_set = set(current_ips)
        previous_set = set(previous_ips)
        
        new_ips = current_set - previous_set
        lost_ips = previous_set - current_set
        
        if new_ips or lost_ips:
            self.logger.warning(f"🔄 Port {port}: IP change detected!")
            
            if new_ips:
                self.logger.warning(f"🆕 New IPs: {list(new_ips)}")
                
                # Eski IP'leri engelle
                ips_to_block = previous_set - new_ips
                for old_ip in ips_to_block:
                    block_key = f"{old_ip}:{port}"
                    if block_key not in self.blocked_ips:
                        self.block_ip_async(old_ip, port, "New IP detected")
            
            if lost_ips:
                self.logger.info(f"📤 Lost IPs: {list(lost_ips)}")
            
            # Güncelle
            self.active_ports[port] = current_ips.copy()
            self.logger.info(f"✅ Port {port}: Updated to {len(current_ips)} active IPs")
    
    def main_monitoring_loop(self):
        """Ana monitoring döngüsü"""
        scan_count = 0
        
        while self.running:
            start_time = time.time()
            
            try:
                # Aktif portları tespit et (Management port HARİÇ)
                active_ports = self.get_active_ports_safe()
                
                if not active_ports:
                    self.logger.debug("No monitorable ports found")
                    time.sleep(self.CHECK_INTERVAL)
                    continue
                
                # Port'ları batch'lere böl (TÜM PORTLAR EŞİT)
                port_batches = [active_ports[i:i + self.BATCH_SIZE] 
                               for i in range(0, len(active_ports), self.BATCH_SIZE)]
                
                # Parallel tarama
                futures = []
                for batch in port_batches:
                    future = self.executor.submit(self.scan_ports_batch, batch)
                    futures.append(future)
                
                # Sonuçları topla
                all_results = {}
                for future in as_completed(futures, timeout=10):
                    try:
                        batch_result = future.result()
                        all_results.update(batch_result)
                    except Exception as e:
                        self.logger.error(f"Batch scan error: {e}")
                
                # IP değişimlerini işle (TÜM PORTLAR EŞİT MUAMELE)
                changes_detected = 0
                total_connections = 0
                
                for port, current_ips in all_results.items():
                    if current_ips:
                        total_connections += len(current_ips)
                        
                        previous_ips = self.active_ports.get(port, [])
                        current_set = set(current_ips)
                        previous_set = set(previous_ips)
                        
                        if current_set != previous_set:
                            self.process_port_changes(port, current_ips, previous_ips)
                            changes_detected += 1
                
                # İstatistikler
                scan_count += 1
                elapsed = time.time() - start_time
                
                self.stats.update({
                    'scanned_ports': len(active_ports),
                    'active_ports': len(all_results),
                    'total_connections': total_connections
                })
                
                # Her 60 saniyede durum raporu
                if scan_count % 60 == 0:
                    blocked_summary = len(self.blocked_ips)
                    self.logger.info(f"📊 1min Report: {self.stats['active_ports']} active ports, "
                                  f"{total_connections} total connections, "
                                  f"{blocked_summary} blocks, {elapsed:.2f}s scan")
                
                if changes_detected > 0:
                    self.logger.info(f"🔄 {changes_detected} port changes detected this scan")
                
                # Ultra fast interval
                sleep_time = max(0.1, self.CHECK_INTERVAL - elapsed)
                time.sleep(sleep_time)
                
            except Exception as e:
                self.logger.error(f"Main monitoring error: {e}")
                time.sleep(2)
    
    def start(self):
        """Monitoring başlat"""
        self.logger.info("🚀 INTERACTIVE Outline Monitor Starting")
        self.logger.info(f"🚨 PROTECTED MANAGEMENT PORT: {self.management_port}")
        self.logger.info(f"📡 MONITORING ALL PORTS: {self.dynamic_range[0]}-{self.dynamic_range[1]} (except {self.management_port})")
        self.logger.info(f"⚡ Ultra Fast Scan: {self.CHECK_INTERVAL}s interval")
        self.logger.info(f"🚫 Block Duration: {self.BLOCK_DURATION//60}min")
        self.logger.info(f"🔧 Performance: {self.MAX_WORKERS} workers, {self.BATCH_SIZE} batch size")
        self.logger.info("=" * 80)
        
        try:
            self.main_monitoring_loop()
        except KeyboardInterrupt:
            self.logger.info("⏹️  Shutdown requested...")
            self.stop()
    
    def stop(self):
        """Güvenli kapatma"""
        self.running = False
        
        # Tüm engelleri kaldır
        self.logger.info("🧹 Clearing all blocks...")
        blocked_count = len(self.blocked_ips)
        
        for block_key in list(self.blocked_ips.keys()):
            try:
                ip, port = block_key.split(':')
                self.unblock_ip(ip, int(port))
            except Exception as e:
                self.logger.error(f"Cleanup error for {block_key}: {e}")
        
        # Thread pool kapat
        self.executor.shutdown(wait=True)
        
        if blocked_count > 0:
            self.logger.info(f"✅ Cleared {blocked_count} IP blocks")
        
        self.logger.info("✅ INTERACTIVE Outline Monitor stopped safely")

# Signal handling
monitor = None

def signal_handler(signum, frame):
    global monitor
    if monitor:
        monitor.stop()
    exit(0)

signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

if __name__ == "__main__":
    # Root kontrolü
    if os.geteuid() != 0:
        print("❌ This script must be run as root (use sudo)")
        sys.exit(1)
    
    # Interactive port setup
    management_port = get_outline_management_port()
    
    print(f"\n✅ Outline Management Port set to: {management_port}")
    print("🔄 Starting monitoring system...")
    
    monitor = InteractiveOutlineMonitor(management_port)
    monitor.start()
PYTHON_EOF
    
    # Make executable
    chmod +x "$INSTALL_DIR/outline_monitor_interactive.py"
    
    # Create port configuration helper
    cat > "$INSTALL_DIR/configure.py" << 'CONFIG_EOF'
#!/usr/bin/env python3
"""
Port Configuration Helper for Outline Monitor
"""

import subprocess
import sys
import os
import json

CONFIG_FILE = "/opt/outline-monitor/config.json"

def detect_outline_ports():
    """Outline server portlarını otomatik tespit et"""
    try:
        cmd = "ss -tuln | awk 'NR>1 {print $5}' | grep -oE ':[0-9]+$' | cut -c2- | sort -n | uniq"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        
        active_ports = []
        for line in result.stdout.split('\n'):
            if line.strip():
                try:
                    port = int(line.strip())
                    active_ports.append(port)
                except ValueError:
                    continue
        
        detected_management = []
        for port in active_ports:
            if 27000 <= port <= 27100:
                detected_management.append(port)
        
        return detected_management, active_ports
        
    except Exception as e:
        print(f"Port detection error: {e}")
        return [], []

def get_outline_management_port():
    """Kullanıcıdan Outline Management portunu al"""
    print("\n" + "="*60)
    print("🔍 OUTLINE SERVER PORT DETECTION")
    print("="*60)
    
    detected_mgmt, all_ports = detect_outline_ports()
    
    if detected_mgmt:
        print(f"📡 Detected possible Outline Management ports: {detected_mgmt}")
        for port in detected_mgmt:
            choice = input(f"Is {port} your Outline Management port? (y/n): ").lower().strip()
            if choice in ['y', 'yes']:
                return port
    
    print("\n🔧 Please enter your Outline Server Management port manually:")
    print("   (This is usually between 27000-27100)")
    print("   (Check your Outline Manager URL: https://your-ip:PORT)")
    
    while True:
        try:
            port_input = input("\nOutline Management Port: ").strip()
            management_port = int(port_input)
            
            if 1 <= management_port <= 65535:
                confirm = input(f"Confirm Outline Management port {management_port}? (y/n): ").lower().strip()
                if confirm in ['y', 'yes']:
                    return management_port
            else:
                print("❌ Port must be between 1-65535")
                
        except ValueError:
            print("❌ Please enter a valid number")
        except KeyboardInterrupt:
            print("\n❌ Setup cancelled")
            sys.exit(1)

def save_config(management_port):
    """Konfigürasyonu dosyaya kaydet"""
    config = {
        "management_port": management_port,
        "monitor_range": [1024, 65535],
        "check_interval": 1,
        "block_duration": 120
    }
    
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)
    
    print(f"\n✅ Configuration saved to: {CONFIG_FILE}")
    return True

def main():
    if os.geteuid() != 0:
        print("❌ This script must be run as root (use sudo)")
        sys.exit(1)
    
    print("🔧 Outline Monitor - Port Configuration")
    
    management_port = get_outline_management_port()
    
    if save_config(management_port):
        print(f"\n✅ Outline Management Port set to: {management_port}")
        print("🔄 You can now start the monitoring service with: outline-monitor start")
        return True
    else:
        print("❌ Failed to save configuration")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
CONFIG_EOF
    
    chmod +x "$INSTALL_DIR/configure.py"
    
    log "✅ Python script installed at $INSTALL_DIR/outline_monitor_interactive.py"
    log "✅ Configuration helper installed at $INSTALL_DIR/configure.py"
}

# Create systemd service
create_systemd_service() {
    log "⚙️  Creating systemd service..."
    
    cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=Interactive Outline Monitor - Advanced Port Protection
Documentation=https://github.com/outline-monitor
After=network.target iptables.service
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/bin/python3 $INSTALL_DIR/outline_monitor_interactive.py
ExecReload=/bin/kill -HUP \$MAINPID
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=outline-monitor

# Security settings
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/log /tmp
PrivateTmp=yes

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF
    
    # Reload systemd
    systemctl daemon-reload
    
    log "✅ Systemd service created: $SERVICE_NAME.service"
}

# Create management scripts
create_management_scripts() {
    log "📜 Creating management scripts..."
    
    # Control script
    cat > "$INSTALL_DIR/outline-monitor-control.sh" << 'CONTROL_EOF'
#!/bin/bash

SERVICE_NAME="outline-monitor"
LOG_FILE="/var/log/outline-monitor.log"

case "$1" in
    start)
        echo "🚀 Starting Outline Monitor..."
        systemctl start $SERVICE_NAME
        systemctl status $SERVICE_NAME --no-pager
        ;;
    stop)
        echo "⏹️  Stopping Outline Monitor..."
        systemctl stop $SERVICE_NAME
        ;;
    restart)
        echo "🔄 Restarting Outline Monitor..."
        systemctl restart $SERVICE_NAME
        systemctl status $SERVICE_NAME --no-pager
        ;;
    status)
        systemctl status $SERVICE_NAME --no-pager
        ;;
    logs)
        echo "📋 Recent logs:"
        journalctl -u $SERVICE_NAME -n 50 --no-pager
        ;;
    tail)
        echo "📋 Following logs (Ctrl+C to exit):"
        journalctl -u $SERVICE_NAME -f
        ;;
    enable)
        echo "🔧 Enabling auto-start on boot..."
        systemctl enable $SERVICE_NAME
        ;;
    disable)
        echo "🔧 Disabling auto-start on boot..."
        systemctl disable $SERVICE_NAME
        ;;
    clean)
        echo "🧹 Cleaning iptables rules..."
        iptables -F
        echo "✅ All iptables rules cleared"
        ;;
    setup)
        echo "🔧 Running interactive port setup..."
        python3 /opt/outline-monitor/configure.py
        if [ $? -eq 0 ]; then
            echo "✅ Port configuration completed!"
            echo "🚀 You can now start monitoring with: outline-monitor start"
        else
            echo "❌ Port configuration failed"
        fi
        ;;
    delete)
        echo "🗑️  COMPLETE UNINSTALL - This will remove everything!"
        echo "⚠️  WARNING: This action cannot be undone!"
        read -p "Are you sure you want to completely remove Outline Monitor? (yes/NO): " confirm
        if [[ "$confirm" == "yes" ]]; then
            echo "🛑 Stopping and disabling service..."
            systemctl stop $SERVICE_NAME 2>/dev/null || true
            systemctl disable $SERVICE_NAME 2>/dev/null || true
            
            echo "🗑️  Removing systemd service..."
            rm -f "/etc/systemd/system/$SERVICE_NAME.service"
            systemctl daemon-reload
            
            echo "🧹 Cleaning all iptables rules..."
            iptables -F 2>/dev/null || true
            iptables -X 2>/dev/null || true
            
            echo "📁 Removing installation directory..."
            rm -rf "/opt/outline-monitor"
            
            echo "🔗 Removing global command..."
            rm -f "/usr/local/bin/outline-monitor"
            
            echo "📋 Removing log files..."
            rm -f "/var/log/outline-monitor.log"
            rm -f "/var/log/outline-monitor-setup.log"
            
            echo "✅ COMPLETE REMOVAL FINISHED!"
            echo "🔄 Outline Monitor has been completely uninstalled from the system."
        else
            echo "❌ Uninstall cancelled"
        fi
        ;;
    *)
        echo "Outline Monitor Control Script"
        echo "Usage: $0 {start|stop|restart|status|logs|tail|enable|disable|clean|setup|delete}"
        echo ""
        echo "Commands:"
        echo "  start    - Start the monitoring service"
        echo "  stop     - Stop the monitoring service"
        echo "  restart  - Restart the monitoring service"
        echo "  status   - Show service status"
        echo "  logs     - Show recent logs"
        echo "  tail     - Follow logs in real-time"
        echo "  enable   - Enable auto-start on boot"
        echo "  disable  - Disable auto-start on boot"
        echo "  clean    - Clear all iptables rules"
        echo "  setup    - Run interactive port setup"
        echo "  delete   - COMPLETELY REMOVE Outline Monitor from system"
        exit 1
        ;;
esac
CONTROL_EOF
    
    chmod +x "$INSTALL_DIR/outline-monitor-control.sh"
    
    # Create symlink for easy access
    ln -sf "$INSTALL_DIR/outline-monitor-control.sh" "/usr/local/bin/outline-monitor"
    
    # Create uninstall script
    cat > "$INSTALL_DIR/uninstall.sh" << 'UNINSTALL_EOF'
#!/bin/bash

#########################################################################
# OUTLINE MONITOR COMPLETE UNINSTALL SCRIPT
# Completely removes Outline Monitor from the system
#########################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

SERVICE_NAME="outline-monitor"
INSTALL_DIR="/opt/outline-monitor"

# Header
print_header() {
    clear
    echo -e "${RED}"
    echo "########################################################################"
    echo "#               OUTLINE MONITOR COMPLETE UNINSTALL                    #"
    echo "#                                                                      #"
    echo "#  ⚠️  WARNING: This will completely remove Outline Monitor!          #"
    echo "#  🗑️  All files, services, and configurations will be deleted       #"
    echo "#  🧹 All iptables rules will be cleared                             #"
    echo "#  🚫 This action CANNOT be undone!                                  #"
    echo "########################################################################"
    echo -e "${NC}"
    echo
}

# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: This script must be run as root. Use: sudo $0${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Root privileges confirmed${NC}"
}

# Confirmation
get_confirmation() {
    echo -e "${YELLOW}🚨 DANGER ZONE - COMPLETE SYSTEM REMOVAL${NC}"
    echo
    echo "This will remove:"
    echo "  📁 /opt/outline-monitor/ (all files)"
    echo "  ⚙️  systemd service"
    echo "  🔗 /usr/local/bin/outline-monitor command"
    echo "  📋 All log files"
    echo "  🧹 All iptables rules (COMPLETE FLUSH)"
    echo
    echo -e "${RED}⚠️  WARNING: All your iptables rules will be cleared!${NC}"
    
    read -p "Type 'DELETE_EVERYTHING' to confirm complete removal: " confirmation
    
    if [[ "$confirmation" != "DELETE_EVERYTHING" ]]; then
        echo -e "${YELLOW}❌ Uninstall cancelled. System unchanged.${NC}"
        exit 0
    fi
    
    echo -e "${RED}🛑 Proceeding with complete removal...${NC}"
    echo
}

# Main removal
main() {
    print_header
    check_root
    get_confirmation
    
    echo -e "${BLUE}🚀 Starting complete removal process...${NC}"
    
    # Stop service
    echo -e "${BLUE}🛑 Stopping service...${NC}"
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
    
    # Remove service file
    echo -e "${BLUE}🗑️  Removing systemd service...${NC}"
    rm -f "/etc/systemd/system/$SERVICE_NAME.service"
    systemctl daemon-reload
    
    # Clean iptables
    echo -e "${BLUE}🧹 Cleaning ALL iptables rules...${NC}"
    backup_file="/tmp/iptables-backup-$(date +%Y%m%d-%H%M%S).rules"
    iptables-save > "$backup_file" 2>/dev/null || true
    iptables -F 2>/dev/null || true
    iptables -X 2>/dev/null || true
    iptables -t nat -F 2>/dev/null || true
    iptables -t nat -X 2>/dev/null || true
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    
    # Remove files
    echo -e "${BLUE}📁 Removing installation...${NC}"
    rm -rf "$INSTALL_DIR"
    rm -f "/usr/local/bin/outline-monitor"
    
    # Remove logs
    echo -e "${BLUE}📋 Removing logs...${NC}"
    rm -f "/var/log/outline-monitor.log"
    rm -f "/var/log/outline-monitor-setup.log"
    rm -f "/var/log/correct-outline-monitor.log"
    
    # Kill processes
    pkill -f "outline.*monitor" 2>/dev/null || true
    
    echo
    echo -e "${GREEN}"
    echo "########################################################################"
    echo "#                    COMPLETE REMOVAL FINISHED!                       #"
    echo "########################################################################"
    echo -e "${NC}"
    echo
    echo -e "${GREEN}✅ Outline Monitor completely removed from system${NC}"
    echo -e "${YELLOW}📋 Iptables backup saved to: $backup_file${NC}"
    echo -e "${PURPLE}🔄 System is clean and ready for fresh installation${NC}"
}

main "$@"
UNINSTALL_EOF
    
    chmod +x "$INSTALL_DIR/uninstall.sh"
    
    log "✅ Management scripts created"
    log "✅ Command 'outline-monitor' available globally"
    log "✅ Uninstall script created at $INSTALL_DIR/uninstall.sh"
}

# Interactive setup
interactive_setup() {
    log "🔧 Starting interactive port configuration..."
    
    echo -e "${YELLOW}"
    echo "=========================================================================="
    echo "                    OUTLINE MANAGEMENT PORT SETUP"
    echo "=========================================================================="
    echo -e "${NC}"
    
    # Run the port configuration helper
    if python3 "$INSTALL_DIR/configure.py"; then
        log "✅ Port configuration completed successfully"
    else
        log_warning "Port configuration failed - you can run it later with: outline-monitor setup"
        return 1
    fi
}

# Configure firewall
configure_firewall() {
    log "🔥 Configuring firewall..."
    
    # Backup current iptables rules
    iptables-save > "/opt/outline-monitor/iptables-backup-$(date +%Y%m%d-%H%M%S).rules"
    
    # Basic firewall rules (preserve existing)
    log "✅ Firewall configured (existing rules preserved)"
}

# Enable and start service
enable_service() {
    log "🎯 Enabling service (will start later)..."
    
    # Enable service (but don't start yet)
    systemctl enable "$SERVICE_NAME"
    
    log "✅ Service enabled for auto-start on boot"
    log "⚠️  Service will start after port configuration"
}

# Print completion message
print_completion() {
    echo
    echo -e "${GREEN}"
    echo "########################################################################"
    echo "#                    INSTALLATION COMPLETED!                          #"
    echo "########################################################################"
    echo -e "${NC}"
    echo
    echo -e "${BLUE}📍 Installation Location:${NC} $INSTALL_DIR"
    echo -e "${BLUE}📋 Log File:${NC} /var/log/outline-monitor.log"
    echo -e "${BLUE}⚙️  Service Name:${NC} $SERVICE_NAME"
    echo -e "${BLUE}🗑️  Uninstall Script:${NC} $INSTALL_DIR/uninstall.sh"
    echo
    echo -e "${YELLOW}🎮 CONTROL COMMANDS:${NC}"
    echo "  outline-monitor start      # Start monitoring"
    echo "  outline-monitor stop       # Stop monitoring"
    echo "  outline-monitor restart    # Restart monitoring"
    echo "  outline-monitor status     # Check status"
    echo "  outline-monitor logs       # View recent logs"
    echo "  outline-monitor tail       # Follow logs real-time"
    echo "  outline-monitor setup      # Re-run port setup"
    echo "  outline-monitor clean      # Clear all blocks"
    echo "  outline-monitor delete     # COMPLETELY REMOVE system"
    echo
    echo -e "${GREEN}✅ The system is now configured to monitor ALL ports (1024-65535) except your management port${NC}"
    echo -e "${GREEN}✅ Auto-start on boot is enabled${NC}"
    echo -e "${GREEN}✅ 2-minute IP blocking with 1-second monitoring will be active after port setup${NC}"
    echo
    echo -e "${PURPLE}🚀 To start monitoring: outline-monitor start${NC}"
    echo -e "${PURPLE}📊 To check status: outline-monitor status${NC}"
    echo -e "${PURPLE}� To reconfigure port: outline-monitor setup${NC}"
    echo
}

# Main execution
main() {
    print_header
    
    log "🚀 Starting Outline Monitor setup..."
    
    check_root
    check_requirements
    install_packages
    create_directories
    install_python_script
    create_systemd_service
    create_management_scripts
    configure_firewall
    enable_service
    interactive_setup
    
    print_completion
    
    log "✅ Setup completed successfully!"
}

# Run main function
main "$@"
