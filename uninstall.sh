#!/bin/bash

#########################################################################
# OUTLINE MONITOR COMPLETE UNINSTALL SCRIPT
# Completely removes Outline Monitor from the system
# 
# This script will:
# - Stop and disable the service
# - Remove all files and directories
# - Clean all iptables rules
# - Remove systemd service
# - Remove global commands
# - Clean all logs
#########################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Script variables
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
    echo "#                                                                      #"
    echo "########################################################################"
    echo -e "${NC}"
    echo
}

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}ERROR: This script must be run as root. Use: sudo $0${NC}"
        exit 1
    fi
    echo -e "${GREEN}✅ Root privileges confirmed${NC}"
}

# Confirmation prompt
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
    echo -e "${RED}⚠️  This includes rules not related to Outline Monitor!${NC}"
    echo
    
    read -p "Type 'DELETE_EVERYTHING' to confirm complete removal: " confirmation
    
    if [[ "$confirmation" != "DELETE_EVERYTHING" ]]; then
        echo -e "${YELLOW}❌ Uninstall cancelled. System unchanged.${NC}"
        exit 0
    fi
    
    echo -e "${RED}🛑 Proceeding with complete removal...${NC}"
    echo
}

# Stop and disable service
stop_service() {
    echo -e "${BLUE}🛑 Stopping and disabling service...${NC}"
    
    if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl stop "$SERVICE_NAME"
        echo "✅ Service stopped"
    else
        echo "ℹ️  Service was not running"
    fi
    
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl disable "$SERVICE_NAME"
        echo "✅ Service disabled"
    else
        echo "ℹ️  Service was not enabled"
    fi
    
    echo -e "${GREEN}✅ Service management completed${NC}"
}

# Remove systemd service file
remove_service_file() {
    echo -e "${BLUE}🗑️  Removing systemd service...${NC}"
    
    if [[ -f "/etc/systemd/system/$SERVICE_NAME.service" ]]; then
        rm -f "/etc/systemd/system/$SERVICE_NAME.service"
        echo "✅ Service file removed"
    else
        echo "ℹ️  Service file not found"
    fi
    
    # Reload systemd
    systemctl daemon-reload
    systemctl reset-failed 2>/dev/null || true
    
    echo -e "${GREEN}✅ Systemd cleanup completed${NC}"
}

# Clean iptables rules
clean_iptables() {
    echo -e "${BLUE}🧹 Cleaning ALL iptables rules...${NC}"
    echo -e "${RED}⚠️  This will remove ALL firewall rules!${NC}"
    
    # Backup current rules
    backup_file="/tmp/iptables-backup-$(date +%Y%m%d-%H%M%S).rules"
    iptables-save > "$backup_file" 2>/dev/null || true
    echo "📋 Current rules backed up to: $backup_file"
    
    # Clear all rules
    iptables -F 2>/dev/null || true       # Flush all rules
    iptables -X 2>/dev/null || true       # Delete all chains
    iptables -t nat -F 2>/dev/null || true
    iptables -t nat -X 2>/dev/null || true
    iptables -t mangle -F 2>/dev/null || true
    iptables -t mangle -X 2>/dev/null || true
    iptables -t raw -F 2>/dev/null || true
    iptables -t raw -X 2>/dev/null || true
    
    # Set default policies to ACCEPT
    iptables -P INPUT ACCEPT 2>/dev/null || true
    iptables -P FORWARD ACCEPT 2>/dev/null || true
    iptables -P OUTPUT ACCEPT 2>/dev/null || true
    
    echo -e "${GREEN}✅ All iptables rules cleared${NC}"
    echo -e "${YELLOW}ℹ️  You may need to reconfigure your firewall${NC}"
}

# Remove installation directory
remove_installation() {
    echo -e "${BLUE}📁 Removing installation directory...${NC}"
    
    if [[ -d "$INSTALL_DIR" ]]; then
        rm -rf "$INSTALL_DIR"
        echo "✅ Installation directory removed: $INSTALL_DIR"
    else
        echo "ℹ️  Installation directory not found"
    fi
    
    echo -e "${GREEN}✅ Installation files removed${NC}"
}

# Remove global command
remove_global_command() {
    echo -e "${BLUE}🔗 Removing global command...${NC}"
    
    if [[ -L "/usr/local/bin/outline-monitor" ]] || [[ -f "/usr/local/bin/outline-monitor" ]]; then
        rm -f "/usr/local/bin/outline-monitor"
        echo "✅ Global command removed"
    else
        echo "ℹ️  Global command not found"
    fi
    
    echo -e "${GREEN}✅ Command cleanup completed${NC}"
}

# Remove log files
remove_logs() {
    echo -e "${BLUE}📋 Removing log files...${NC}"
    
    local log_files=(
        "/var/log/outline-monitor.log"
        "/var/log/outline-monitor-setup.log"
        "/var/log/correct-outline-monitor.log"
    )
    
    for log_file in "${log_files[@]}"; do
        if [[ -f "$log_file" ]]; then
            rm -f "$log_file"
            echo "✅ Removed: $log_file"
        fi
    done
    
    echo -e "${GREEN}✅ Log files cleaned${NC}"
}

# Remove any remaining traces
remove_traces() {
    echo -e "${BLUE}🔍 Removing any remaining traces...${NC}"
    
    # Check for any remaining outline-monitor processes
    if pgrep -f "outline.*monitor" >/dev/null 2>&1; then
        echo "🛑 Killing remaining processes..."
        pkill -f "outline.*monitor" 2>/dev/null || true
        sleep 2
    fi
    
    # Remove any temporary files
    rm -f /tmp/*outline*monitor* 2>/dev/null || true
    rm -f /tmp/test_ip_logic.py 2>/dev/null || true
    rm -f /tmp/debug_connections.py 2>/dev/null || true
    
    echo -e "${GREEN}✅ System traces removed${NC}"
}

# Print completion message
print_completion() {
    echo
    echo -e "${GREEN}"
    echo "########################################################################"
    echo "#                    COMPLETE REMOVAL FINISHED!                       #"
    echo "########################################################################"
    echo -e "${NC}"
    echo
    echo -e "${GREEN}✅ Outline Monitor has been completely removed from the system${NC}"
    echo
    echo -e "${BLUE}What was removed:${NC}"
    echo "  📁 Installation directory: $INSTALL_DIR"
    echo "  ⚙️  Systemd service: $SERVICE_NAME"
    echo "  🔗 Global command: outline-monitor"
    echo "  📋 All log files"
    echo "  🧹 All iptables rules (COMPLETE FLUSH)"
    echo "  🔍 All system traces"
    echo
    echo -e "${YELLOW}⚠️  IMPORTANT NOTES:${NC}"
    echo "  🔥 All firewall rules have been cleared"
    echo "  🛡️  You may need to reconfigure your firewall"
    echo "  📋 Iptables backup saved to: /tmp/iptables-backup-*.rules"
    echo
    echo -e "${PURPLE}🔄 System is now clean and ready for fresh installation${NC}"
    echo
}

# Main execution
main() {
    print_header
    check_root
    get_confirmation
    
    echo -e "${BLUE}🚀 Starting complete removal process...${NC}"
    echo
    
    stop_service
    remove_service_file
    clean_iptables
    remove_installation
    remove_global_command
    remove_logs
    remove_traces
    
    print_completion
}

# Run main function
main "$@"
