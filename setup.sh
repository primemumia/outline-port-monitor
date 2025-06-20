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
    echo "###############################################################"
    echo "#                                                             #"
    echo "#           🛡️  OUTLINE MONITOR SETUP SCRIPT 🛡️               #"
    echo "#                                                             #"
    echo "#    Advanced Port Protection & Change Detection System      #"
    echo "#                                                             #"
    echo "###############################################################"
    echo -e "${NC}"
    echo ""
    echo -e "${BLUE}Features:${NC}"
    echo "• Interactive Outline Management port detection"
    echo "• Monitors ALL ports 1024-65535 (except management)"
    echo "• 2-minute IP blocking on suspicious changes"
    echo "• 1-second monitoring with async performance"
    echo "• Auto-start on boot with systemd service"
    echo "• Complete logging and change tracking"
    echo ""
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check system compatibility
check_system() {
    log "Checking system compatibility..."
    
    # Check if systemctl is available
    if ! command -v systemctl &> /dev/null; then
        log_error "systemctl not found. This script requires systemd."
        exit 1
    fi
    
    # Check if iptables is available
    if ! command -v iptables &> /dev/null; then
        log_error "iptables not found. Installing iptables..."
        if command -v apt-get &> /dev/null; then
            apt-get update && apt-get install -y iptables
        elif command -v yum &> /dev/null; then
            yum install -y iptables
        else
            log_error "Cannot install iptables. Please install it manually."
            exit 1
        fi
    fi
    
    # Check if Python 3 is available
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 not found. Installing Python 3..."
        if command -v apt-get &> /dev/null; then
            apt-get update && apt-get install -y python3 python3-pip
        elif command -v yum &> /dev/null; then
            yum install -y python3 python3-pip
        else
            log_error "Cannot install Python 3. Please install it manually."
            exit 1
        fi
    fi
    
    log "✅ System compatibility check passed"
}

# Create installation directory
create_install_directory() {
    log "Creating installation directory..."
    mkdir -p "$INSTALL_DIR"
    log "✅ Directory created: $INSTALL_DIR"
}

# Create the main monitoring Python script
create_monitor_script() {
    log "Creating main monitoring script..."
    
    cat > "$INSTALL_DIR/port_monitor.py" << 'EOF'
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

def setup_logging():
    """Logging configuration"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('/var/log/outline-monitor.log'),
            logging.StreamHandler()
        ]
    )

class InteractiveOutlineMonitor:
    def __init__(self, config):
        self.config = config
        self.management_port = config['management_port']
        self.logger = logging.getLogger(__name__)
        
        # Port monitoring range (1024-65535, excluding management port)
        self.monitor_ports = [p for p in range(1024, 65536) if p != self.management_port]
        
        # Thread control
        self.running = True
        self.monitoring_threads = []
        
        # Connection tracking
        self.current_connections = {}
        self.blocked_ips = {}
        self.ip_change_history = defaultdict(list)
        
        # Batch processing
        self.batch_size = 50
        self.check_interval = 1.0
        
        # Statistics
        self.stats = {
            'checks_performed': 0,
            'ips_blocked': 0,
            'changes_detected': 0,
            'start_time': datetime.now()
        }
        
        self.logger.info(f"🚀 Interactive Outline Monitor initialized")
        self.logger.info(f"📡 Management Port (Protected): {self.management_port}")
        self.logger.info(f"🔍 Monitoring Ports: 1024-65535 (except {self.management_port})")
        self.logger.info(f"⏱️  Check Interval: {self.check_interval}s")
        self.logger.info(f"🧩 Batch Size: {self.batch_size}")

    def get_connections_for_ports(self, ports):
        """Get connections for specific ports using netstat"""
        try:
            cmd = ['netstat', '-tn']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                return {}
                
            connections = {}
            for line in result.stdout.split('\n'):
                if 'ESTABLISHED' in line:
                    parts = line.split()
                    if len(parts) >= 5:
                        local_addr = parts[3]
                        foreign_addr = parts[4]
                        
                        try:
                            local_port = int(local_addr.split(':')[-1])
                            foreign_ip = foreign_addr.split(':')[0]
                            
                            if local_port in ports and foreign_ip not in ['127.0.0.1', '::1']:
                                if local_port not in connections:
                                    connections[local_port] = []
                                connections[local_port].append(foreign_ip)
                        except (ValueError, IndexError):
                            continue
                            
            return connections
            
        except subprocess.TimeoutExpired:
            self.logger.error("⏰ Netstat command timed out")
            return {}
        except Exception as e:
            self.logger.error(f"❌ Error getting connections: {e}")
            return {}

    def block_ip_temporarily(self, ip, port, duration_minutes=2):
        """Block IP temporarily using iptables"""
        try:
            # Add to blocked IPs tracking
            unblock_time = datetime.now() + timedelta(minutes=duration_minutes)
            self.blocked_ips[ip] = {
                'port': port,
                'blocked_at': datetime.now(),
                'unblock_at': unblock_time
            }
            
            # Block the IP using iptables
            block_cmd = ['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP']
            subprocess.run(block_cmd, check=True, capture_output=True)
            
            self.stats['ips_blocked'] += 1
            self.logger.warning(f"🚫 BLOCKED IP {ip} (changed on port {port}) for {duration_minutes} minutes")
            
            # Schedule unblock
            def unblock_later():
                time.sleep(duration_minutes * 60)
                self.unblock_ip(ip)
            
            threading.Thread(target=unblock_later, daemon=True).start()
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"❌ Failed to block IP {ip}: {e}")
        except Exception as e:
            self.logger.error(f"❌ Error blocking IP {ip}: {e}")

    def unblock_ip(self, ip):
        """Unblock IP by removing iptables rule"""
        try:
            if ip in self.blocked_ips:
                # Remove from iptables
                unblock_cmd = ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']
                subprocess.run(unblock_cmd, capture_output=True)
                
                port = self.blocked_ips[ip]['port']
                del self.blocked_ips[ip]
                
                self.logger.info(f"✅ UNBLOCKED IP {ip} (was blocked for port {port})")
            
        except Exception as e:
            self.logger.error(f"❌ Error unblocking IP {ip}: {e}")

    def cleanup_expired_blocks(self):
        """Clean up expired IP blocks"""
        now = datetime.now()
        expired_ips = [ip for ip, data in self.blocked_ips.items() 
                      if now >= data['unblock_at']]
        
        for ip in expired_ips:
            self.unblock_ip(ip)

    def process_port_batch(self, ports):
        """Process a batch of ports"""
        connections = self.get_connections_for_ports(ports)
        changes_detected = []
        
        for port in ports:
            current_ips = set(connections.get(port, []))
            previous_ips = set(self.current_connections.get(port, []))
            
            if current_ips != previous_ips:
                # Change detected
                new_ips = current_ips - previous_ips
                lost_ips = previous_ips - current_ips
                
                if new_ips or lost_ips:
                    change_info = {
                        'port': port,
                        'new_ips': list(new_ips),
                        'lost_ips': list(lost_ips),
                        'timestamp': datetime.now()
                    }
                    changes_detected.append(change_info)
                    
                    # Log the change
                    if new_ips:
                        self.logger.info(f"🔄 Port {port}: New IPs {list(new_ips)}")
                    if lost_ips:
                        self.logger.info(f"📤 Port {port}: Lost IPs {list(lost_ips)}")
                    
                    # Block new IPs (potential suspicious activity)
                    for new_ip in new_ips:
                        if new_ip not in self.blocked_ips:
                            self.block_ip_temporarily(new_ip, port)
                            
                    # Update history
                    self.ip_change_history[port].append(change_info)
                    
                # Update current connections
                self.current_connections[port] = list(current_ips)
        
        return changes_detected

    def monitor_batch_worker(self):
        """Worker thread for batch monitoring"""
        while self.running:
            try:
                # Split ports into batches
                port_batches = [self.monitor_ports[i:i + self.batch_size] 
                              for i in range(0, len(self.monitor_ports), self.batch_size)]
                
                all_changes = []
                
                # Process batches in parallel
                with ThreadPoolExecutor(max_workers=4) as executor:
                    futures = [executor.submit(self.process_port_batch, batch) 
                             for batch in port_batches]
                    
                    for future in as_completed(futures):
                        try:
                            batch_changes = future.result(timeout=5)
                            all_changes.extend(batch_changes)
                        except Exception as e:
                            self.logger.error(f"❌ Batch processing error: {e}")
                
                # Update statistics
                self.stats['checks_performed'] += 1
                if all_changes:
                    self.stats['changes_detected'] += len(all_changes)
                
                # Cleanup expired blocks
                self.cleanup_expired_blocks()
                
                # Log periodic status
                if self.stats['checks_performed'] % 60 == 0:  # Every minute
                    uptime = datetime.now() - self.stats['start_time']
                    self.logger.info(f"📊 Status: {self.stats['checks_performed']} checks, "
                                   f"{self.stats['changes_detected']} changes, "
                                   f"{self.stats['ips_blocked']} IPs blocked, "
                                   f"uptime: {uptime}")
                
                time.sleep(self.check_interval)
                
            except Exception as e:
                self.logger.error(f"❌ Monitoring error: {e}")
                time.sleep(self.check_interval)

    def signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"🛑 Received signal {signum}, shutting down...")
        self.stop()

    def start(self):
        """Start monitoring"""
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        self.logger.info("🚀 Starting Interactive Outline Monitor...")
        
        # Initial connection scan
        self.logger.info("🔍 Performing initial connection scan...")
        port_batches = [self.monitor_ports[i:i + self.batch_size] 
                       for i in range(0, len(self.monitor_ports), self.batch_size)]
        
        for batch in port_batches:
            connections = self.get_connections_for_ports(batch)
            for port, ips in connections.items():
                self.current_connections[port] = ips
                if ips:
                    self.logger.info(f"📡 Port {port}: Found {len(ips)} connections")
        
        self.logger.info("✅ Initial scan completed")
        
        # Start monitoring thread
        monitor_thread = threading.Thread(target=self.monitor_batch_worker, daemon=True)
        monitor_thread.start()
        self.monitoring_threads.append(monitor_thread)
        
        self.logger.info("🔄 Monitoring started - Press Ctrl+C to stop")
        
        try:
            # Keep main thread alive
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("🛑 Received keyboard interrupt")
        finally:
            self.stop()

    def stop(self):
        """Stop monitoring"""
        self.logger.info("🛑 Stopping monitoring...")
        self.running = False
        
        # Unblock all IPs
        for ip in list(self.blocked_ips.keys()):
            self.unblock_ip(ip)
        
        # Final statistics
        uptime = datetime.now() - self.stats['start_time']
        self.logger.info(f"📊 Final Statistics:")
        self.logger.info(f"   • Uptime: {uptime}")
        self.logger.info(f"   • Checks performed: {self.stats['checks_performed']}")
        self.logger.info(f"   • Changes detected: {self.stats['changes_detected']}")
        self.logger.info(f"   • IPs blocked: {self.stats['ips_blocked']}")
        
        self.logger.info("✅ Monitoring stopped")

def load_config():
    """Load configuration from file"""
    config_file = '/opt/outline-monitor/config.json'
    
    if os.path.exists(config_file):
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
                return config
        except Exception as e:
            print(f"❌ Error loading config: {e}")
            return None
    else:
        print(f"⚠️  Configuration file not found: {config_file}")
        print("🔧 Please run the setup first: sudo python3 /opt/outline-monitor/configure.py")
        return None

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("❌ This script must be run as root (use sudo)")
        sys.exit(1)
    
    # Setup logging
    setup_logging()
    
    # Load or create configuration
    config = load_config()
    
    if config is None:
        print("🔧 No configuration found. Running setup...")
        sys.exit(1)
    
    print(f"\n✅ Loaded configuration - Management Port: {config['management_port']}")
    print("🔄 Starting monitoring system...")
    
    monitor = InteractiveOutlineMonitor(config)
    monitor.start()
EOF

    chmod +x "$INSTALL_DIR/port_monitor.py"
    log "✅ Main monitoring script created"
}

# Create the configuration script
create_configure_script() {
    log "Creating configuration script..."
    
    cat > "$INSTALL_DIR/configure.py" << 'EOF'
#!/usr/bin/env python3
"""
Interactive Outline Monitor Configuration
Sets up the management port and saves configuration
"""

import json
import os
import subprocess
import re
import sys

CONFIG_FILE = '/opt/outline-monitor/config.json'

def detect_outline_port():
    """Try to detect Outline Server management port automatically"""
    try:
        # Check for common Outline processes
        result = subprocess.run(['netstat', '-tlnp'], capture_output=True, text=True)
        
        # Look for processes listening on management-like ports
        management_ports = []
        for line in result.stdout.split('\n'):
            if ':' in line and 'LISTEN' in line:
                try:
                    # Extract port from netstat output
                    parts = line.split()
                    local_address = parts[3]
                    port = int(local_address.split(':')[-1])
                    
                    # Check if this might be Outline management port
                    if 20000 <= port <= 30000:  # Common range for Outline
                        management_ports.append(port)
                        
                except (ValueError, IndexError):
                    continue
        
        if management_ports:
            return sorted(list(set(management_ports)))
        
        # Also check for specific Outline Server indicators
        try:
            ps_result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            for line in ps_result.stdout.split('\n'):
                if 'outline' in line.lower() or 'shadowbox' in line.lower():
                    # Try to extract port from command line
                    port_match = re.search(r'--port[= ](\d+)', line)
                    if port_match:
                        port = int(port_match.group(1))
                        if port not in management_ports:
                            management_ports.append(port)
        except:
            pass
            
        return sorted(list(set(management_ports)))
        
    except Exception as e:
        print(f"⚠️  Auto-detection failed: {e}")
        return []

def safe_input(prompt, default=None):
    """Safe input function that handles EOF errors"""
    try:
        if default:
            user_input = input(f"{prompt} [{default}]: ").strip()
            return user_input if user_input else str(default)
        else:
            return input(f"{prompt}: ").strip()
    except EOFError:
        print("\n⚠️  Input not available (running in non-interactive mode)")
        if default:
            print(f"Using default value: {default}")
            return str(default)
        else:
            print("❌ Interactive input required but not available")
            sys.exit(1)
    except KeyboardInterrupt:
        print("\n⚠️  Setup cancelled by user")
        sys.exit(1)

def get_management_port():
    """Get management port from user input or auto-detection"""
    print("\n🔍 Detecting Outline Server management port...")
    
    detected_ports = detect_outline_port()
    
    if detected_ports:
        print(f"✅ Detected possible Outline management ports: {detected_ports}")
        
        if len(detected_ports) == 1:
            port = detected_ports[0]
            print(f"\n📡 Found single port: {port}")
            response = safe_input(f"Use detected port {port}? (y/n)", "y")
            if response.lower() in ['y', 'yes', '']:
                return port
        else:
            print("\n📡 Multiple ports detected:")
            for i, port in enumerate(detected_ports, 1):
                print(f"  {i}. Port {port}")
            
            print("\nOptions:")
            print("• Enter 1-{} to select a detected port".format(len(detected_ports)))
            print("• Enter a custom port number (1024-65535)")
            print("• Press Enter for default (27046)")
            
            while True:
                try:
                    choice = safe_input("Your choice", "27046")
                    
                    # Check if it's a selection from detected ports
                    if choice.isdigit():
                        choice_num = int(choice)
                        if 1 <= choice_num <= len(detected_ports):
                            selected_port = detected_ports[choice_num - 1]
                            print(f"✅ Selected detected port: {selected_port}")
                            return selected_port
                        elif 1024 <= choice_num <= 65535:
                            print(f"✅ Using custom port: {choice_num}")
                            return choice_num
                        else:
                            print("❌ Invalid port number. Must be between 1024-65535")
                            continue
                    else:
                        print("❌ Please enter a number")
                        continue
                        
                except ValueError:
                    print("❌ Invalid input. Please enter a number")
                    continue
    
    # Manual input fallback
    print("\n🔧 No ports auto-detected or manual entry selected")
    print("📝 Please enter your Outline Server management port")
    print("💡 This is usually in the 20000-30000 range (e.g., 27046)")
    print("🔗 Check your Outline Manager URL: https://your-server-ip:PORT")
    
    while True:
        try:
            port_input = safe_input("Management port", "27046")
            
            if not port_input:
                port = 27046  # Default
            else:
                port = int(port_input)
            
            if 1024 <= port <= 65535:
                confirm = safe_input(f"Confirm port {port} as your Outline management port? (y/n)", "y")
                if confirm.lower() in ['y', 'yes', '']:
                    return port
                else:
                    continue
            else:
                print("❌ Port must be between 1024 and 65535")
                
        except ValueError:
            print("❌ Please enter a valid port number")

def save_config(management_port):
    """Save configuration to file"""
    config = {
        'management_port': management_port,
        'monitoring_enabled': True,
        'block_duration_minutes': 2,
        'check_interval_seconds': 1,
        'version': '1.0'
    }
    
    try:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Set proper permissions
        os.chmod(CONFIG_FILE, 0o600)
        
        return True
        
    except Exception as e:
        print(f"❌ Error saving configuration: {e}")
        return False

def main():
    print("🔧 Interactive Outline Monitor Configuration")
    print("=" * 50)
    
    if os.geteuid() != 0:
        print("❌ This script must be run as root (use sudo)")
        sys.exit(1)
    
    # Check if config already exists
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                existing_config = json.load(f)
            
            current_port = existing_config.get('management_port', 'unknown')
            print(f"\n⚠️  Configuration already exists")
            print(f"📡 Current management port: {current_port}")
            
            response = safe_input("Reconfigure? (y/n)", "n")
            if response.lower() not in ['y', 'yes']:
                print("✅ Keeping existing configuration")
                return
                
        except Exception as e:
            print(f"⚠️  Error reading existing config: {e}")
            print("🔧 Will create new configuration")
    
    # Get management port
    management_port = get_management_port()
    
    print(f"\n📡 Selected management port: {management_port}")
    print(f"🔍 Will monitor ports: 1024-65535 (except {management_port})")
    print(f"⏱️  Check interval: 1 second")
    print(f"🚫 Block duration: 2 minutes")
    
    response = safe_input("\nSave this configuration? (y/n)", "y")
    if response.lower() in ['y', 'yes', '']:
        if save_config(management_port):
            print("✅ Configuration saved successfully!")
            print(f"📁 Config file: {CONFIG_FILE}")
            print("\n🚀 You can now start the monitor with:")
            print("   sudo systemctl start outline-monitor")
        else:
            print("❌ Failed to save configuration")
            sys.exit(1)
    else:
        print("⚠️  Configuration not saved")

if __name__ == "__main__":
    main()
EOF

    chmod +x "$INSTALL_DIR/configure.py"
    log "✅ Configuration script created"
}
        print(f"✅ Detected possible Outline management ports: {detected_ports}")
        
        if len(detected_ports) == 1:
            port = detected_ports[0]
            response = input(f"Use detected port {port}? (y/n) [y]: ").strip().lower()
            if response in ['', 'y', 'yes']:
                return port
        else:
            print("Multiple ports detected:")
            for i, port in enumerate(detected_ports, 1):
                print(f"  {i}. Port {port}")
            
            while True:
                try:
                    choice = input(f"Select port (1-{len(detected_ports)}) or enter custom port: ").strip()
                    
                    if choice.isdigit():
                        choice_num = int(choice)
                        if 1 <= choice_num <= len(detected_ports):
                            return detected_ports[choice_num - 1]
                        elif 1024 <= choice_num <= 65535:
                            return choice_num
                    
                    print("❌ Invalid selection. Please try again.")
                except KeyboardInterrupt:
                    print("\n⚠️  Setup cancelled")
                    sys.exit(1)
    
    # Manual input
    print("\n🔧 No ports auto-detected or manual entry selected")
    print("📝 Please enter your Outline Server management port")
    print("💡 This is usually in the 20000-30000 range (e.g., 27046)")
    
    while True:
        try:
            port_input = input("Management port [27046]: ").strip()
            
            if not port_input:
                port = 27046  # Default
            else:
                port = int(port_input)
            
            if 1024 <= port <= 65535:
                return port
            else:
                print("❌ Port must be between 1024 and 65535")
                
        except ValueError:
            print("❌ Please enter a valid port number")
        except KeyboardInterrupt:
            print("\n⚠️  Setup cancelled")
            sys.exit(1)

def save_config(management_port):
    """Save configuration to file"""
    config = {
        'management_port': management_port,
        'monitoring_enabled': True,
        'block_duration_minutes': 2,
        'check_interval_seconds': 1,
        'version': '1.0'
    }
    
    try:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
        
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=2)
        
        # Set proper permissions
        os.chmod(CONFIG_FILE, 0o600)
        
        return True
        
    except Exception as e:
        print(f"❌ Error saving configuration: {e}")
        return False

def main():
    print("🔧 Interactive Outline Monitor Configuration")
    print("=" * 50)
    
    if os.geteuid() != 0:
        print("❌ This script must be run as root (use sudo)")
        sys.exit(1)
    
    # Check if config already exists
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                existing_config = json.load(f)
            
            current_port = existing_config.get('management_port', 'unknown')
            print(f"\n⚠️  Configuration already exists")
            print(f"📡 Current management port: {current_port}")
            
            response = input("Reconfigure? (y/n) [n]: ").strip().lower()
            if response not in ['y', 'yes']:
                print("✅ Keeping existing configuration")
                return
                
        except Exception as e:
            print(f"⚠️  Error reading existing config: {e}")
            print("🔧 Will create new configuration")
    
    # Get management port
    management_port = get_management_port()
    
    print(f"\n📡 Selected management port: {management_port}")
    print(f"🔍 Will monitor ports: 1024-65535 (except {management_port})")
    print(f"⏱️  Check interval: 1 second")
    print(f"🚫 Block duration: 2 minutes")
    
    response = input("\nSave this configuration? (y/n) [y]: ").strip().lower()
    if response in ['', 'y', 'yes']:
        if save_config(management_port):
            print("✅ Configuration saved successfully!")
            print(f"📁 Config file: {CONFIG_FILE}")
            print("\n🚀 You can now start the monitor with:")
            print("   sudo systemctl start outline-monitor")
        else:
            print("❌ Failed to save configuration")
            sys.exit(1)
    else:
        print("⚠️  Configuration not saved")

if __name__ == "__main__":
    main()
EOF

    chmod +x "$INSTALL_DIR/configure.py"
    log "✅ Configuration script created"
}

# Create systemd service
create_systemd_service() {
    log "Creating systemd service..."
    
    cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=Interactive Outline Monitor - Port Protection System
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=/usr/bin/python3 $INSTALL_DIR/port_monitor.py
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR /var/log /tmp

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log "✅ Systemd service created"
}

# Configure firewall rules
configure_firewall() {
    log "Configuring firewall rules..."
    
    # Create iptables rules for the monitoring system
    # These rules will be managed by the Python script
    
    # Ensure iptables is configured to allow the management port
    iptables -C INPUT -p tcp --dport 22 -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport 22 -j ACCEPT
    
    # Save iptables rules (distribution-specific)
    if command -v iptables-save &> /dev/null; then
        if [ -f /etc/iptables/rules.v4 ]; then
            iptables-save > /etc/iptables/rules.v4
        elif [ -f /etc/sysconfig/iptables ]; then
            iptables-save > /etc/sysconfig/iptables
        fi
    fi
    
    log "✅ Firewall configured"
}

# Enable and start service
enable_service() {
    log "Enabling and starting service..."
    
    systemctl enable "$SERVICE_NAME"
    log "✅ Service enabled for auto-start"
    
    # Note: We don't start the service here because configuration is needed first
    log "ℹ️  Service will be started after configuration"
}

# Interactive setup
interactive_setup() {
    log "Running interactive configuration setup..."
    
    echo ""
    echo -e "${BLUE}🔧 CONFIGURATION SETUP${NC}"
    echo "================================"
    echo ""
    echo "The monitor needs to know your Outline Server management port"
    echo "to protect it from monitoring and accidental blocking."
    echo ""
    
    # Run the configuration script
    python3 "$INSTALL_DIR/configure.py"
    
    if [ $? -eq 0 ]; then
        log "✅ Configuration completed successfully"
        
        # Now we can start the service
        echo ""
        echo -e "${GREEN}🚀 Starting the monitoring service...${NC}"
        
        if systemctl start "$SERVICE_NAME"; then
            log "✅ Service started successfully"
            
            # Show service status
            sleep 2
            echo ""
            echo -e "${BLUE}📊 Service Status:${NC}"
            systemctl status "$SERVICE_NAME" --no-pager -l
            
        else
            log_error "Failed to start service"
            echo ""
            echo -e "${YELLOW}🔧 To start manually later:${NC}"
            echo "   sudo systemctl start $SERVICE_NAME"
        fi
    else
        log_warning "Configuration was not completed"
        echo ""
        echo -e "${YELLOW}🔧 To configure later:${NC}"
        echo "   sudo python3 $INSTALL_DIR/configure.py"
        echo "   sudo systemctl start $SERVICE_NAME"
    fi
}

# Print completion message
print_completion() {
    echo ""
    echo -e "${GREEN}"
    echo "###############################################################"
    echo "#                                                             #"
    echo "#                🎉 INSTALLATION COMPLETE! 🎉                 #"
    echo "#                                                             #"
    echo "###############################################################"
    echo -e "${NC}"
    echo ""
    echo -e "${BLUE}📋 Installation Summary:${NC}"
    echo "• Installation directory: $INSTALL_DIR"
    echo "• Service name: $SERVICE_NAME"
    echo "• Log file: /var/log/outline-monitor.log"
    echo "• Configuration: $INSTALL_DIR/config.json"
    echo ""
    echo -e "${BLUE}🎛️  Management Commands:${NC}"
    echo "• Status:       sudo systemctl status $SERVICE_NAME"
    echo "• Start:        sudo systemctl start $SERVICE_NAME"
    echo "• Stop:         sudo systemctl stop $SERVICE_NAME"
    echo "• Restart:      sudo systemctl restart $SERVICE_NAME"
    echo "• Logs:         sudo journalctl -f -u $SERVICE_NAME"
    echo "• Configure:    sudo python3 $INSTALL_DIR/configure.py"
    echo ""
    echo -e "${BLUE}📁 Important Files:${NC}"
    echo "• Main script:  $INSTALL_DIR/port_monitor.py"
    echo "• Config tool:  $INSTALL_DIR/configure.py"
    echo "• Service file: /etc/systemd/system/$SERVICE_NAME.service"
    echo ""
    echo -e "${YELLOW}💡 Notes:${NC}"
    echo "• The service runs automatically on boot"
    echo "• All ports 1024-65535 are monitored (except your management port)"
    echo "• IP changes trigger 2-minute blocks automatically"
    echo "• Check logs with: sudo tail -f /var/log/outline-monitor.log"
    echo ""
    echo -e "${GREEN}✅ Your Outline Server is now protected!${NC}"
}

# Uninstall function
uninstall() {
    echo -e "${RED}"
    echo "###############################################################"
    echo "#                                                             #"
    echo "#                    ⚠️  UNINSTALL MODE ⚠️                     #"
    echo "#                                                             #"
    echo "###############################################################"
    echo -e "${NC}"
    echo ""
    echo -e "${YELLOW}This will completely remove the Outline Monitor:${NC}"
    echo "• Stop and disable the service"
    echo "• Remove all files and directories"
    echo "• Clean up firewall rules"
    echo "• Remove systemd service"
    echo ""
    
    read -p "Are you sure you want to uninstall? (type 'YES' to confirm): " confirm
    
    if [ "$confirm" != "YES" ]; then
        echo "❌ Uninstall cancelled"
        exit 0
    fi
    
    log "🗑️  Starting uninstall process..."
    
    # Stop and disable service
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "Stopping service..."
        systemctl stop "$SERVICE_NAME"
    fi
    
    if systemctl is-enabled --quiet "$SERVICE_NAME"; then
        log "Disabling service..."
        systemctl disable "$SERVICE_NAME"
    fi
    
    # Remove service file
    if [ -f "/etc/systemd/system/$SERVICE_NAME.service" ]; then
        log "Removing systemd service..."
        rm -f "/etc/systemd/system/$SERVICE_NAME.service"
        systemctl daemon-reload
    fi
    
    # Clean up any remaining iptables rules (optional, as they might be wanted)
    echo ""
    read -p "Remove all iptables DROP rules created by the monitor? (y/n) [n]: " clean_iptables
    if [[ "$clean_iptables" =~ ^[Yy]$ ]]; then
        log "Cleaning iptables rules..."
        # Remove all DROP rules with single IP sources (created by our monitor)
        iptables -L INPUT -n --line-numbers | grep "DROP.*\..*\..*\." | awk '{print $1}' | sort -nr | while read line; do
            iptables -D INPUT "$line" 2>/dev/null || true
        done
    fi
    
    # Remove installation directory
    if [ -d "$INSTALL_DIR" ]; then
        log "Removing installation directory..."
        rm -rf "$INSTALL_DIR"
    fi
    
    # Remove log file
    if [ -f "/var/log/outline-monitor.log" ]; then
        log "Removing log file..."
        rm -f "/var/log/outline-monitor.log"
    fi
    
    # Remove setup log
    if [ -f "$LOG_FILE" ]; then
        rm -f "$LOG_FILE"
    fi
    
    echo ""
    echo -e "${GREEN}✅ Uninstall completed successfully!${NC}"
    echo ""
    echo "The Outline Monitor has been completely removed from your system."
    echo ""
}

# Help function
show_help() {
    echo "Interactive Outline Monitor Setup Script"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  install     Install and configure the monitor (default)"
    echo "  uninstall   Completely remove the monitor"
    echo "  delete      Same as uninstall"
    echo "  help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                # Install the monitor"
    echo "  $0 install        # Install the monitor"
    echo "  $0 uninstall      # Remove the monitor"
    echo "  $0 delete         # Remove the monitor"
    echo ""
}

# Main function
main() {
    # Parse command line arguments
    case "${1:-install}" in
        install)
            print_header
            check_root
            check_system
            create_install_directory
            create_monitor_script
            create_configure_script
            create_systemd_service
            configure_firewall
            enable_service
            interactive_setup
            print_completion
            log "✅ Setup completed successfully!"
            ;;
        uninstall|delete)
            check_root
            uninstall
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            echo "❌ Unknown option: $1"
            echo ""
            show_help
            exit 1
            ;;
    esac
}

# Run main function
main "$@"
