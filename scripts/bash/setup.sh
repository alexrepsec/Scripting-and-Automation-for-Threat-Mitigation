#!/bin/bash
# =============================================================================
# setup.sh — Environment Setup for Web Threat Monitor
# Scripting and Automation for Threat Mitigation
# Author: alexrepsec
# Description: Automates full environment setup on Ubuntu Server 22.04.
#              Installs Apache2 + PHP, configures log permissions, sets up
#              sudoers rule for iptables, and creates project directory structure.
# =============================================================================

set -e

GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m'

PROJECT_DIR="$HOME/threat-mitigation"
CURRENT_USER=$(whoami)

echo ""
echo "============================================================"
echo "  Web Threat Monitor — Environment Setup"
echo "  Scripting and Automation for Threat Mitigation"
echo "  Author: alexrepsec"
echo "============================================================"
echo ""

# ─── Step 1: Update system ───────────────────────────────────────────────────
echo -e "${BLUE}[*] Updating package lists...${NC}"
sudo apt update -qq
echo -e "${GREEN}[+] Package lists updated.${NC}"

# ─── Step 2: Install Apache2 ─────────────────────────────────────────────────
echo -e "${BLUE}[*] Installing Apache2...${NC}"
sudo apt install -y apache2
sudo systemctl start apache2
sudo systemctl enable apache2
echo -e "${GREEN}[+] Apache2 installed and running.${NC}"

# ─── Step 3: Install PHP ─────────────────────────────────────────────────────
echo -e "${BLUE}[*] Installing PHP...${NC}"
sudo apt install -y php libapache2-mod-php
sudo systemctl restart apache2
echo -e "${GREEN}[+] PHP installed.${NC}"

# ─── Step 4: Install Python3 dependencies ────────────────────────────────────
echo -e "${BLUE}[*] Installing Python3 dependencies...${NC}"
sudo apt install -y python3 python3-pip
sudo pip3 install watchdog jinja2 --break-system-packages 2>/dev/null || \
pip3 install watchdog jinja2
echo -e "${GREEN}[+] Python3 dependencies installed.${NC}"

# ─── Step 5: Create honeypot login page ──────────────────────────────────────
echo -e "${BLUE}[*] Creating honeypot login page...${NC}"
sudo tee /var/www/html/login.php > /dev/null << 'PHPEOF'
<?php
$user = $_GET['user'] ?? '';
$pass = $_GET['pass'] ?? '';
echo "<html><body>";
echo "<h2>Login Panel</h2>";
echo "<p>User: $user</p>";
echo "</body></html>";
?>
PHPEOF
echo -e "${GREEN}[+] Honeypot page created at /var/www/html/login.php${NC}"

# ─── Step 6: Configure Apache log permissions ────────────────────────────────
echo -e "${BLUE}[*] Configuring Apache log permissions...${NC}"
sudo chmod 644 /var/log/apache2/access.log
echo -e "${GREEN}[+] Log permissions set.${NC}"

# ─── Step 7: Configure sudoers for iptables ──────────────────────────────────
echo -e "${BLUE}[*] Configuring sudoers for iptables (no password)...${NC}"
SUDOERS_FILE="/etc/sudoers.d/iptables-monitor"
echo "$CURRENT_USER ALL=(ALL) NOPASSWD: /sbin/iptables" | sudo tee "$SUDOERS_FILE" > /dev/null
sudo chmod 440 "$SUDOERS_FILE"
echo -e "${GREEN}[+] Sudoers rule added for user: $CURRENT_USER${NC}"

# ─── Step 8: Create project directory structure ──────────────────────────────
echo -e "${BLUE}[*] Creating project directory structure...${NC}"
mkdir -p "$PROJECT_DIR"/{scripts/python,scripts/bash,reports,logs,config}
echo -e "${GREEN}[+] Project directories created at $PROJECT_DIR${NC}"

# ─── Step 9: Configure UFW ───────────────────────────────────────────────────
echo -e "${BLUE}[*] Configuring UFW firewall...${NC}"
sudo ufw allow 80/tcp > /dev/null 2>&1
echo -e "${GREEN}[+] UFW: Port 80 allowed.${NC}"

# ─── Summary ─────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo -e "${GREEN}  Setup complete!${NC}"
echo "============================================================"
echo ""
echo "  Apache2 status : $(sudo systemctl is-active apache2)"
echo "  Project dir    : $PROJECT_DIR"
echo "  Honeypot page  : http://$(hostname -I | awk '{print $1}')/login.php"
echo ""
echo "  Next steps:"
echo "  1. Copy web_threat_monitor.py to $PROJECT_DIR/scripts/python/"
echo "  2. Run: python3 $PROJECT_DIR/scripts/python/web_threat_monitor.py"
echo "  3. From Kali: nikto -h http://$(hostname -I | awk '{print $1}')"
echo ""
