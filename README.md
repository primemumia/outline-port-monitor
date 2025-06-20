# 🛡️ Interactive Outline Monitor

Advanced port protection system for Outline Server with intelligent IP change detection and automatic blocking.

## ✨ Features

- **🔍 Intelligent Port Detection**: Automatically detects Outline Server management port or allows manual configuration
- **🛡️ Comprehensive Protection**: Monitors ALL ports 1024-65535 except your management port
- **⚡ Real-time Monitoring**: 1-second interval monitoring with high-performance async processing
- **🚫 Automatic IP Blocking**: 2-minute temporary blocks for suspicious IP changes
- **🎯 Batch Processing**: Efficient monitoring using thread pools and batch operations
- **📊 Complete Logging**: Detailed logs of all activities and statistics
- **🔄 Auto-start**: Systemd service that starts automatically on boot
- **🛠️ Easy Management**: Simple installation, configuration, and removal

## 🚀 Quick Installation

### One-line Installation (Recommended)
```bash
curl -sSL https://raw.githubusercontent.com/primemumia/outline-port-monitor/main/install.sh | sudo bash
```

Or with wget:
```bash
wget -qO- https://raw.githubusercontent.com/primemumia/outline-port-monitor/main/install.sh | sudo bash
```

### Manual Installation
```bash
# Download the setup script
wget https://raw.githubusercontent.com/primemumia/outline-port-monitor/main/setup.sh
chmod +x setup.sh

# Run installation
sudo ./setup.sh
```

## 🔧 How It Works

1. **Port Detection**: The system either auto-detects your Outline Server management port or asks you to specify it
2. **Monitoring**: Continuously monitors all ports 1024-65535 except the management port
3. **Change Detection**: Detects when new IPs connect to any monitored port
4. **Automatic Blocking**: Temporarily blocks new IPs for 2 minutes using iptables
5. **Smart Protection**: Never touches your Outline Server management port

## 📋 Management Commands

```bash
# Check service status
sudo systemctl status outline-monitor

# Start the service
sudo systemctl start outline-monitor

# Stop the service
sudo systemctl stop outline-monitor

# Restart the service
sudo systemctl restart outline-monitor

# View real-time logs
sudo journalctl -f -u outline-monitor

# View log file
sudo tail -f /var/log/outline-monitor.log

# Reconfigure (change management port)
sudo python3 /opt/outline-monitor/configure.py
```

## 🗑️ Uninstallation

### Complete Removal
```bash
# Option 1: Using the setup script
sudo /opt/outline-monitor/setup.sh uninstall

# Option 2: Using the uninstall script
curl -sSL https://raw.githubusercontent.com/primemumia/outline-port-monitor/main/uninstall.sh | sudo bash
```

This will completely remove:
- The monitoring service
- All installed files
- Systemd service configuration
- Optionally clean iptables rules
- All logs and configuration

## 🔧 Configuration

### Automatic Setup
During installation, the system will:
1. Try to auto-detect your Outline Server management port
2. Show detected ports for confirmation
3. Allow manual port entry if needed
4. Save configuration to `/opt/outline-monitor/config.json`

### Manual Configuration
```bash
sudo python3 /opt/outline-monitor/configure.py
```

### Configuration File
Location: `/opt/outline-monitor/config.json`
```json
{
  "management_port": 27046,
  "monitoring_enabled": true,
  "block_duration_minutes": 2,
  "check_interval_seconds": 1,
  "version": "1.0"
}
```

## 📊 Monitoring and Logs

### Real-time Monitoring
```bash
# Service logs
sudo journalctl -f -u outline-monitor

# Application logs
sudo tail -f /var/log/outline-monitor.log
```

### Log Information
The system logs:
- Service start/stop events
- Port change detections
- IP blocking/unblocking events
- Performance statistics
- Error conditions

### Example Log Output
```
2024-06-20 10:30:15 - INFO - 🚀 Interactive Outline Monitor initialized
2024-06-20 10:30:15 - INFO - 📡 Management Port (Protected): 27046
2024-06-20 10:30:15 - INFO - 🔍 Monitoring Ports: 1024-65535 (except 27046)
2024-06-20 10:30:16 - INFO - 🔄 Port 62073: New IPs ['192.168.1.100']
2024-06-20 10:30:16 - WARNING - 🚫 BLOCKED IP 192.168.1.100 (changed on port 62073) for 2 minutes
2024-06-20 10:32:16 - INFO - ✅ UNBLOCKED IP 192.168.1.100 (was blocked for port 62073)
```

## 🎯 Technical Details

### System Requirements
- Linux with systemd
- Python 3.6+
- iptables
- Root access (sudo)

### Architecture
- **Async Monitoring**: Uses ThreadPoolExecutor for parallel port checking
- **Batch Processing**: Monitors ports in configurable batches (default: 50 ports/batch)
- **Smart Filtering**: Excludes localhost and management port from monitoring
- **Memory Efficient**: Tracks only active connections and changes
- **Performance Optimized**: 1-second intervals with efficient netstat parsing

### Security Features
- **Minimal Privileges**: Service runs with restricted systemd security settings
- **Temporary Blocks**: All IP blocks are automatically removed after 2 minutes
- **Management Protection**: Never blocks or interferes with management port
- **Safe Uninstall**: Complete cleanup option available

## 🛠️ Troubleshooting

### Common Issues

**Service won't start**
```bash
# Check configuration
sudo python3 /opt/outline-monitor/configure.py

# Check service status
sudo systemctl status outline-monitor

# Check logs
sudo journalctl -u outline-monitor
```

**Port detection issues**
```bash
# Manual configuration
sudo python3 /opt/outline-monitor/configure.py

# Check what ports are listening
sudo netstat -tlnp | grep LISTEN
```

**Performance issues**
```bash
# Check system resources
top -p $(pgrep -f port_monitor)

# Review logs for errors
sudo tail -100 /var/log/outline-monitor.log
```

## 📁 File Locations

- **Main Script**: `/opt/outline-monitor/port_monitor.py`
- **Configuration**: `/opt/outline-monitor/config.json`
- **Service File**: `/etc/systemd/system/outline-monitor.service`
- **Application Log**: `/var/log/outline-monitor.log`
- **Setup Log**: `/var/log/outline-monitor-setup.log`

## 🤝 Contributing

Feel free to submit issues, feature requests, or pull requests to improve this monitoring system.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**⚠️ Important Notes:**
- This system provides additional security through IP change monitoring
- It's designed to work alongside your existing Outline Server, not replace it
- Always test in a non-production environment first
- Keep your Outline Server management interface secure and updated
