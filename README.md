# 🛡️ Outline Server Port Monitor

Advanced port protection system for Outline VPN servers with intelligent IP blocking and real-time monitoring.

## 🌟 Features

- 🔐 **Smart Management Port Protection** - Automatically detects and protects Outline Management port
- 📡 **Complete Port Monitoring** - Monitors ALL ports (1024-65535) except management port
- ⚡ **Ultra-Fast Detection** - 1-second monitoring interval with 2-minute IP blocking
- 🚀 **Interactive Setup** - Automatic port detection with manual override option
- 🛡️ **Systemd Integration** - Permanent service with auto-start on boot
- 🎮 **Easy Management** - Simple command-line interface
- 🗑️ **Complete Removal** - Safe uninstall with full system cleanup

## 🚀 Quick Installation

### One-Line Install
```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_USERNAME/outline-port-monitor/main/install.sh | sudo bash
```

### Manual Installation
```bash
# Download the installer
wget https://raw.githubusercontent.com/YOUR_USERNAME/outline-port-monitor/main/setup.sh

# Make executable and run
chmod +x setup.sh
sudo ./setup.sh
```

## 🎯 How It Works

1. **Port Detection**: Automatically scans for Outline Management ports (27000-27100)
2. **Interactive Setup**: Asks for confirmation or manual port entry
3. **Equal Monitoring**: All ports in range 1024-65535 get identical protection (except management)
4. **IP Change Detection**: When new IP connects to any monitored port, previous IPs are blocked
5. **Auto-Unblock**: Blocked IPs are automatically unblocked after 2 minutes

## 🎮 Management Commands

After installation, use these commands:

```bash
outline-monitor start      # Start monitoring
outline-monitor stop       # Stop monitoring  
outline-monitor restart    # Restart monitoring
outline-monitor status     # Check status
outline-monitor logs       # View recent logs
outline-monitor tail       # Follow logs in real-time
outline-monitor setup      # Re-run port setup
outline-monitor clean      # Clear all iptables blocks
outline-monitor delete     # COMPLETELY REMOVE system
```

## 📋 System Requirements

- **OS**: Ubuntu 18.04+ / Debian 9+ / CentOS 7+
- **Python**: 3.6+
- **Privileges**: Root access (sudo)
- **Dependencies**: iptables, systemd, ss command

## 🔧 Configuration

The system automatically configures itself during installation:

- **Management Port**: Detected automatically or set manually
- **Monitoring Range**: 1024-65535 (excluding management port)
- **Scan Interval**: 1 second
- **Block Duration**: 2 minutes
- **Performance**: 15 workers, 100 port batches

## 📊 Monitoring

### Real-time Status
```bash
outline-monitor status
```

### Live Logs
```bash
outline-monitor tail
```

### Service Logs
```bash
journalctl -u outline-monitor -f
```

## 🛡️ Security Features

- ✅ **Management Port Protection** - Never blocks Outline Manager access
- ✅ **Port-Specific Blocking** - Only blocks specific port access, not entire IP
- ✅ **Local IP Exclusion** - Never blocks local/private IP ranges
- ✅ **IPv6 Support** - Handles IPv6-mapped IPv4 addresses
- ✅ **Process Isolation** - Runs with minimal privileges
- ✅ **Auto-Recovery** - Automatic restart on failure

## 🗑️ Uninstallation

### Complete Removal
```bash
outline-monitor delete
```

### Manual Cleanup
```bash
sudo /opt/outline-monitor/uninstall.sh
```

**⚠️ WARNING**: Uninstall clears ALL iptables rules!

## 📁 File Locations

- **Installation**: `/opt/outline-monitor/`
- **Service**: `/etc/systemd/system/outline-monitor.service`
- **Logs**: `/var/log/outline-monitor.log`
- **Command**: `/usr/local/bin/outline-monitor`

## 🐛 Troubleshooting

### Check Service Status
```bash
systemctl status outline-monitor
```

### View Error Logs
```bash
outline-monitor logs
```

### Reset Configuration
```bash
outline-monitor setup
```

### Clear All Blocks
```bash
outline-monitor clean
```

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool modifies iptables rules. Always backup your firewall configuration before use. Test in a safe environment first.

## 🆘 Support

- 📧 **Issues**: Create an issue on GitHub
- 📖 **Documentation**: Check the [Wiki](https://github.com/YOUR_USERNAME/outline-port-monitor/wiki)
- 💬 **Discussions**: Use GitHub Discussions

---

Made with ❤️ for the Outline VPN community
