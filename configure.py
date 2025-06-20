#!/usr/bin/env python3
"""
Port Configuration Helper for Outline Monitor
Saves port configuration to file for systemd service
"""

import subprocess
import sys
import os
import json

CONFIG_FILE = "/opt/outline-monitor/config.json"

def detect_outline_ports():
    """Outline server portlarını auto detection"""
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
            if 27000 <= port <= 27100:  # Management port olabilir
                detected_management.append(port)
        
        return detected_management, active_ports
        
    except Exception as e:
        print(f"Port detection error: {e}")
        return [], []

def get_outline_management_port():
    """Get Outline Management port from user"""
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

def save_config(management_port):
    """Konfigürasyonu save to file"""
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
    
    # Get management port
    management_port = get_outline_management_port()
    
    # Save configuration
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
