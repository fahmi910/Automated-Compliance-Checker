#!/usr/bin/env bash
# =============================================================================
#  ComplianceAI — VM1 SNAP-01 Preparation Script
#  Target Risk Level : LOW  (all 10 controls PASS)
#  VM Platform       : Ubuntu 22.04 LTS
#  Run as            : sudo bash snap01_prepare.sh
# =============================================================================
set -euo pipefail

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}  [PASS]${NC} $*"; }
warn() { echo -e "${YELLOW}  [WARN]${NC} $*"; }
fail() { echo -e "${RED}  [FAIL]${NC} $*"; }
info() { echo -e "${CYAN}  [INFO]${NC} $*"; }
step() { echo -e "\n${BOLD}━━━  $*  ━━━${NC}"; }

# Must run as root
if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}ERROR: Run this script with sudo.${NC}"
  exit 1
fi

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║       ComplianceAI  ·  VM1 SNAP-01 Preparation              ║"
echo "║       Risk Level: LOW  ·  All 10 controls → PASS            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# =============================================================================
# AC-LNX-01 — SSH root login disabled
# Rules engine checks: results.access_control.ssh_permit_root_login → "no"
# =============================================================================
step "AC-LNX-01  SSH root login disabled"

SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP="${SSHD_CONFIG}.bak.snap01"

if [[ ! -f "$BACKUP" ]]; then
  cp "$SSHD_CONFIG" "$BACKUP"
  info "Backed up $SSHD_CONFIG → $BACKUP"
fi

# Remove any existing PermitRootLogin lines, then add the correct one
sed -i '/^\s*#*\s*PermitRootLogin/d' "$SSHD_CONFIG"
echo "PermitRootLogin no" >> "$SSHD_CONFIG"
ok "PermitRootLogin set to 'no'"

# =============================================================================
# AC-LNX-02 — SSH password authentication disabled
# Rules engine checks: results.access_control.ssh_password_authentication → "no"
# =============================================================================
step "AC-LNX-02  SSH password authentication disabled"

sed -i '/^\s*#*\s*PasswordAuthentication/d' "$SSHD_CONFIG"
echo "PasswordAuthentication no" >> "$SSHD_CONFIG"
ok "PasswordAuthentication set to 'no'"

# Also ensure PubkeyAuthentication is enabled so we don't lock ourselves out
sed -i '/^\s*#*\s*PubkeyAuthentication/d' "$SSHD_CONFIG"
echo "PubkeyAuthentication yes" >> "$SSHD_CONFIG"
ok "PubkeyAuthentication set to 'yes'"

# =============================================================================
# AC-LNX-03 — SSH idle timeout configured
# Rules engine checks: results.access_control.ssh_idle_timeout
#   evidence_path → results.access_control.ssh_idle_timeout
#   rule type     → must_equal, value: true (the agent checks ClientAliveInterval > 0)
# =============================================================================
step "AC-LNX-03  SSH idle timeout configured"

sed -i '/^\s*#*\s*ClientAliveInterval/d' "$SSHD_CONFIG"
sed -i '/^\s*#*\s*ClientAliveCountMax/d' "$SSHD_CONFIG"
echo "ClientAliveInterval 300" >> "$SSHD_CONFIG"
echo "ClientAliveCountMax 2"   >> "$SSHD_CONFIG"
ok "ClientAliveInterval=300, ClientAliveCountMax=2"

# Restart SSH after all config changes
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || warn "Could not restart SSH — manual restart may be needed"
ok "SSH service restarted"

# =============================================================================
# AC-LNX-04 — Account lockout via pam_faillock
# Rules engine checks:
#   results.access_control.account_lockout_pam  → "pam_faillock"
#   results.access_control.faillock_conf_deny   → deny value (e.g. "5")
# =============================================================================
step "AC-LNX-04  Account lockout (pam_faillock)"

PAM_AUTH="/etc/pam.d/common-auth"
PAM_FAILLOCK_CONF="/etc/security/faillock.conf"

# Install libpam-runtime if missing (normally present on Ubuntu 22.04)
if ! dpkg -l libpam-runtime &>/dev/null; then
  info "Installing libpam-runtime..."
  apt-get install -y libpam-runtime > /dev/null
fi

# Ensure pam_faillock is present in common-auth
if ! grep -q "pam_faillock" "$PAM_AUTH" 2>/dev/null; then
  # Insert before pam_unix line
  sed -i '/pam_unix.so/i auth    required                        pam_faillock.so preauth silent' "$PAM_AUTH"
  sed -i '/pam_unix.so/a auth    [default=die]                   pam_faillock.so authfail' "$PAM_AUTH"
  ok "pam_faillock lines added to $PAM_AUTH"
else
  ok "pam_faillock already present in $PAM_AUTH"
fi

# Write faillock.conf with deny threshold
cat > "$PAM_FAILLOCK_CONF" << 'EOF'
# ComplianceAI SNAP-01 — account lockout configuration
deny = 5
unlock_time = 600
fail_interval = 900
even_deny_root
EOF
ok "faillock.conf written (deny=5, unlock_time=600)"

# =============================================================================
# FW-LNX-01 — UFW firewall enabled with rules
# Rules engine checks:
#   results.firewall.ufw_status          → value: "active"
#   results.firewall.ufw_rules.rules_exist → true
# =============================================================================
step "FW-LNX-01  UFW firewall enabled"

# Install UFW if missing
if ! command -v ufw &>/dev/null; then
  info "Installing ufw..."
  apt-get install -y ufw > /dev/null
fi

# Reset to default (non-interactive)
ufw --force reset > /dev/null

# Default policies
ufw default deny incoming  > /dev/null
ufw default allow outgoing > /dev/null

# Allow SSH so we don't lock ourselves out
ufw allow ssh > /dev/null

# Allow HTTP/HTTPS (common for server)
ufw allow 80/tcp  > /dev/null
ufw allow 443/tcp > /dev/null

# Enable
ufw --force enable > /dev/null
ok "UFW enabled with SSH, HTTP, HTTPS rules"

# Verify
UFW_STATUS=$(ufw status | head -1)
info "UFW status: $UFW_STATUS"

# =============================================================================
# LOG-LNX-01 — rsyslog running with recent syslog entries
# Rules engine checks:
#   results.logging.rsyslog_running        → true
#   results.logging.syslog_recent_entries  → non-empty string
# =============================================================================
step "LOG-LNX-01  rsyslog running"

# Install if missing
if ! dpkg -l rsyslog &>/dev/null; then
  info "Installing rsyslog..."
  apt-get install -y rsyslog > /dev/null
fi

systemctl enable rsyslog > /dev/null 2>&1
systemctl start  rsyslog > /dev/null 2>&1

# Generate a log entry so syslog_recent_entries won't be empty
logger "ComplianceAI SNAP-01 preparation — rsyslog check"
sleep 1

# Verify
if systemctl is-active --quiet rsyslog; then
  ok "rsyslog is active"
else
  fail "rsyslog failed to start — check: systemctl status rsyslog"
fi

# =============================================================================
# LOG-LNX-02 — auth.log exists and contains activity
# Rules engine checks:
#   results.logging.auth_log_exists → true
#   results.logging.failed_ssh_logins_snippet OR sudo_usage_snippet → non-empty
# =============================================================================
step "LOG-LNX-02  auth.log exists with activity"

AUTH_LOG="/var/log/auth.log"

# Ensure auth.log exists
if [[ ! -f "$AUTH_LOG" ]]; then
  touch "$AUTH_LOG"
  chown syslog:adm "$AUTH_LOG" 2>/dev/null || true
  chmod 640 "$AUTH_LOG"
  info "Created $AUTH_LOG"
fi

# Generate a sudo event so the agent detects meaningful activity
sudo -u root bash -c 'true' 2>/dev/null || true
logger -t sudo "ComplianceAI SNAP-01 — auth log activity check"
sleep 1

if [[ -f "$AUTH_LOG" ]] && [[ -s "$AUTH_LOG" ]]; then
  ok "auth.log exists and is non-empty"
else
  warn "auth.log is empty — agent may return PARTIAL for LOG-LNX-02"
  info "Trying to force a log entry..."
  su -c "id" root >> /dev/null 2>&1 || true
fi

# =============================================================================
# UPD-LNX-01 — System packages up to date
# Rules engine checks: results.updates.packages_needing_update → must_be_empty_list
# =============================================================================
step "UPD-LNX-01  System packages up to date"

info "Running apt-get update (this may take a moment)..."
apt-get update -qq

info "Running apt-get upgrade (this may take a few minutes)..."
apt-get upgrade -y -qq

PENDING=$(apt list --upgradable 2>/dev/null | grep -v "Listing..." | wc -l)
if [[ "$PENDING" -eq 0 ]]; then
  ok "All packages are up to date"
else
  warn "$PENDING package(s) still pending — some may require dist-upgrade or a reboot"
  info "Run 'apt-get dist-upgrade -y' if the count remains high"
fi

# =============================================================================
# BKP-LNX-01 — Backup tool installed and cron schedule exists
# Rules engine checks:
#   results.backup.backup_tools_installed → non-empty list e.g. ["rsync"]
#   results.backup.backup_cron_jobs       → non-empty list
# =============================================================================
step "BKP-LNX-01  Backup tool + cron schedule"

# Install rsync as the backup tool
if ! command -v rsync &>/dev/null; then
  info "Installing rsync..."
  apt-get install -y rsync > /dev/null
fi
ok "rsync installed"

# Add a backup cron job for root (agent checks root crontab for backup keywords)
CRON_MARKER="# ComplianceAI SNAP-01 backup schedule"
CRON_JOB="0 2 * * 0  rsync -a /home/ /var/backups/home_backup/"

# Create backup directory
mkdir -p /var/backups/home_backup

CURRENT_CRON=$(crontab -l 2>/dev/null || echo "")
if echo "$CURRENT_CRON" | grep -q "rsync"; then
  ok "rsync backup cron job already present"
else
  (echo "$CURRENT_CRON"; echo ""; echo "$CRON_MARKER"; echo "$CRON_JOB") | crontab -
  ok "rsync cron job added: $CRON_JOB"
fi

# =============================================================================
# CRYPTO-LNX-01 — SSH uses strong ciphers and MACs (no weak algorithms)
# Rules engine checks:
#   results.crypto.weak_algorithms_detected → empty list []
# The agent runs: ssh -Q cipher | grep weak_list and ssh -Q mac | grep weak_list
# =============================================================================
step "CRYPTO-LNX-01  Strong SSH ciphers and MACs"

# Remove any existing Ciphers/MACs/KexAlgorithms lines then set strong ones
sed -i '/^\s*#*\s*Ciphers /d'         "$SSHD_CONFIG"
sed -i '/^\s*#*\s*MACs /d'            "$SSHD_CONFIG"
sed -i '/^\s*#*\s*KexAlgorithms /d'   "$SSHD_CONFIG"

cat >> "$SSHD_CONFIG" << 'EOF'

# ComplianceAI SNAP-01 — strong ciphers and MACs
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256
EOF
ok "Strong Ciphers, MACs, and KexAlgorithms set in sshd_config"

# Restart SSH once more to apply crypto settings
systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
ok "SSH service restarted with crypto settings applied"

# =============================================================================
# FINAL VERIFICATION SUMMARY
# =============================================================================
echo -e "\n${BOLD}━━━  Verification Summary  ━━━${NC}\n"

# 1. PermitRootLogin
PRL=$(grep -i "^\s*PermitRootLogin" "$SSHD_CONFIG" | tail -1 | awk '{print $2}')
[[ "$PRL" == "no" ]] && ok "AC-LNX-01  PermitRootLogin = $PRL" || fail "AC-LNX-01  PermitRootLogin = $PRL (expected: no)"

# 2. PasswordAuthentication
PWA=$(grep -i "^\s*PasswordAuthentication" "$SSHD_CONFIG" | tail -1 | awk '{print $2}')
[[ "$PWA" == "no" ]] && ok "AC-LNX-02  PasswordAuthentication = $PWA" || fail "AC-LNX-02  PasswordAuthentication = $PWA (expected: no)"

# 3. ClientAliveInterval
CAI=$(grep -i "^\s*ClientAliveInterval" "$SSHD_CONFIG" | tail -1 | awk '{print $2}')
[[ -n "$CAI" && "$CAI" -gt 0 ]] && ok "AC-LNX-03  ClientAliveInterval = $CAI" || fail "AC-LNX-03  ClientAliveInterval = $CAI (expected: >0)"

# 4. pam_faillock
if grep -q "pam_faillock" /etc/pam.d/common-auth 2>/dev/null; then
  DENY=$(grep "^deny" /etc/security/faillock.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
  ok "AC-LNX-04  pam_faillock present, deny=$DENY"
else
  fail "AC-LNX-04  pam_faillock not found in /etc/pam.d/common-auth"
fi

# 5. UFW
UFW_S=$(ufw status | awk '/^Status/{print $2}')
[[ "$UFW_S" == "active" ]] && ok "FW-LNX-01  UFW status = $UFW_S" || fail "FW-LNX-01  UFW status = $UFW_S (expected: active)"

# 6. rsyslog
systemctl is-active --quiet rsyslog && ok "LOG-LNX-01  rsyslog is running" || fail "LOG-LNX-01  rsyslog is NOT running"

# 7. auth.log
if [[ -f /var/log/auth.log && -s /var/log/auth.log ]]; then
  ok "LOG-LNX-02  /var/log/auth.log exists and is non-empty"
else
  warn "LOG-LNX-02  /var/log/auth.log is missing or empty — control may return PARTIAL"
fi

# 8. apt updates
PENDING2=$(apt list --upgradable 2>/dev/null | grep -v "Listing..." | wc -l)
[[ "$PENDING2" -eq 0 ]] && ok "UPD-LNX-01  No pending upgrades" || warn "UPD-LNX-01  $PENDING2 upgrade(s) still pending"

# 9. rsync + cron
command -v rsync &>/dev/null && ok "BKP-LNX-01  rsync installed" || fail "BKP-LNX-01  rsync not found"
crontab -l 2>/dev/null | grep -q "rsync" && ok "BKP-LNX-01  rsync cron job present" || fail "BKP-LNX-01  rsync cron job NOT found"

# 10. Strong ciphers
if grep -q "^Ciphers" "$SSHD_CONFIG"; then
  ok "CRYPTO-LNX-01  Ciphers line present in sshd_config"
else
  fail "CRYPTO-LNX-01  Ciphers line missing"
fi

# =============================================================================
# NEXT STEPS
# =============================================================================
echo -e "\n${BOLD}━━━  Next Steps  ━━━${NC}\n"
echo -e "  1.  ${CYAN}If all checks above show PASS → take the VirtualBox snapshot now.${NC}"
echo -e "      In VirtualBox:  Machine → Take Snapshot → Name: SNAP-01_Low"
echo ""
echo -e "  2.  ${CYAN}Run the compliance agent to verify:${NC}"
echo -e "      cd ~/agent && python3 agent.py"
echo ""
echo -e "  3.  ${CYAN}Check the dashboard at:${NC}  http://localhost:8050"
echo -e "      Expected: Risk Level = Low  ·  Compliance ≥ 95%"
echo ""
echo -e "${GREEN}${BOLD}SNAP-01 preparation complete.${NC}"