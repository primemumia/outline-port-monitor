#!/bin/bash

#########################################################################
# OUTLINE MONITOR QUICK INSTALLER
# One-line installation script for GitHub
#########################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m'

# GitHub repository info
GITHUB_USER="YOUR_USERNAME"
GITHUB_REPO="outline-port-monitor"
GITHUB_BRANCH="main"
SETUP_URL="https://raw.githubusercontent.com/${GITHUB_USER}/${GITHUB_REPO}/${GITHUB_BRANCH}/setup.sh"

print_header() {
    clear
    echo -e "${PURPLE}"
    echo "########################################################################"
    echo "#                OUTLINE MONITOR QUICK INSTALLER                      #"
    echo "#                                                                      #"
    echo "#  🚀 Downloading and installing from GitHub...                       #"
    echo "#  📦 Repository: ${GITHUB_USER}/${GITHUB_REPO}                       #"
    echo "#  🔗 Installing latest version from ${GITHUB_BRANCH} branch          #"
    echo "#                                                                      #"
    echo "########################################################################"
    echo -e "${NC}"
    echo
}

check_requirements() {
    echo -e "${BLUE}🔍 Checking system requirements...${NC}"
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}❌ This installer must be run as root. Use: sudo $0${NC}"
        exit 1
    fi
    
    # Check for required commands
    for cmd in curl wget; do
        if ! command -v "$cmd" &> /dev/null; then
            echo -e "${YELLOW}Installing $cmd...${NC}"
            apt-get update -qq && apt-get install -y "$cmd"
        fi
    done
    
    echo -e "${GREEN}✅ Requirements check passed${NC}"
}

download_and_run() {
    echo -e "${BLUE}📥 Downloading setup script from GitHub...${NC}"
    
    # Create temporary file
    TEMP_SETUP="/tmp/outline-monitor-setup-$(date +%s).sh"
    
    # Download setup script
    if curl -fsSL "$SETUP_URL" -o "$TEMP_SETUP"; then
        echo -e "${GREEN}✅ Setup script downloaded successfully${NC}"
    else
        echo -e "${RED}❌ Failed to download setup script${NC}"
        echo -e "${YELLOW}Trying with wget...${NC}"
        
        if wget -q "$SETUP_URL" -O "$TEMP_SETUP"; then
            echo -e "${GREEN}✅ Setup script downloaded with wget${NC}"
        else
            echo -e "${RED}❌ Failed to download setup script with both curl and wget${NC}"
            echo -e "${YELLOW}Please check your internet connection and try again${NC}"
            exit 1
        fi
    fi
    
    # Make executable
    chmod +x "$TEMP_SETUP"
    
    echo -e "${BLUE}🚀 Running setup script...${NC}"
    echo
    
    # Run the setup script
    "$TEMP_SETUP"
    
    # Cleanup
    rm -f "$TEMP_SETUP"
    
    echo
    echo -e "${GREEN}✅ Installation completed via GitHub!${NC}"
}

main() {
    print_header
    check_requirements
    download_and_run
}

main "$@"
