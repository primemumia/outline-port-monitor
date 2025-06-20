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
            print(f"� Current management port: {current_port}")
            
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
            print("\n� You can now start the monitor with:")
            print("   sudo systemctl start outline-monitor")
        else:
            print("❌ Failed to save configuration")
            sys.exit(1)
    else:
        print("⚠️  Configuration not saved")

if __name__ == "__main__":
    main()
