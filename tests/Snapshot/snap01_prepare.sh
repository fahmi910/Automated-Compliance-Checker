#!/usr/bin/env bash
# =============================================================================
#  ComplianceAI — VM1 SNAP-01 Preparation Script (v3)
#  Target Risk Level : LOW  (all 10 controls PASS)
#  VM Platform       : Ubuntu 22.04 LTS
#  Run as            : sudo bash snap01_prepare.sh
#
#  v3 changes:
#  - Removed set -euo pipefail (script no longer exits on any error)
#  - Each step is fully independent
#  - apt upgrade failure no longer skips SSH / UFW / rsyslog steps
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

ok()   { echo -e "${GREEN}  [PASS]${NC} $*"; }
warn() { echo -e "${YELLOW}  [WARN]${NC} $*"; }
fail() { echo -e "${RED}  [FAIL]${NC} $*"; }
info() { echo -e "${CYAN}  [INFO]${NC} $*"; }
step() { echo -e "\n${BOLD}━━━  $*  ━━━${NC}"; }

if [[ $EUID -ne 0 ]]; then
  echo -e "${RED}ERROR: Run this script with sudo.${NC}"
  exit 1
fi

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     ComplianceAI  ·  VM1 SNAP-01 Preparation  v3           ║"
echo "║     Risk Level: LOW  ·  All 10 controls → PASS             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

export DEBIAN_FRONTEND=noninteractive
SSHD_CONFIG="/etc/ssh/sshd_config"

# =============================================================================
# STEP 1 — UPD-LNX-01: System packages up to date
# =============================================================================
step "STEP 1 of 7  —  UPD-LNX-01  System packages"

info "Running apt-get update..."
apt-get update -qq 2>&1 || warn "apt-get update had warnings (continuing)"

info "Running apt-get upgrade..."
apt-get upgrade -y \
  -o Dpkg::Options::="--force-confdef" \
  -o Dpkg::Options::="--force-confold" \
  -qq 2>&1 || warn "apt-get upgrade had warnings (continuing)"

info "Running apt-get dist-upgrade..."
apt-get dist-upgrade -y \
  -o Dpkg::Options::="--force-confdef" \
  -o Dpkg::Options::="--force-confold" \
  -qq 2>&1 || warn "apt-get dist-upgrade had warnings (continuing)"

apt-get autoremove -y -qq 2>/dev/null || true

PENDING=$(apt list --upgradable 2>/dev/null | grep -v "Listing..." | wc -l)
if [[ "$PENDING" -eq 0 ]]; then
  ok "All packages up to date"
else
  warn "$PENDING package(s) still pending — reboot may clear them"
fi

# =============================================================================
# STEP 2 — AC-LNX-01, AC-LNX-02, AC-LNX-03, CRYPTO-LNX-01: SSH hardening
# =============================================================================
step "STEP 2 of 7  —  SSH hardening (AC-LNX-01/02/03, CRYPTO-LNX-01)"

cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.snap01" 2>/dev/null || true

# Remove existing directives to avoid duplicates
for directive in PermitRootLogin PasswordAuthentication PubkeyAuthentication \
                 ClientAliveInterval ClientAliveCountMax \
                 Ciphers MACs KexAlgorithms; do
  sed -i "/^\s*#*\s*${directive}\b/d" "$SSHD_CONFIG" 2>/dev/null || true
done

# Append all hardened settings
cat >> "$SSHD_CONFIG" << 'SSHEOF'

# ComplianceAI SNAP-01 hardening
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
ClientAliveInterval 300
ClientAliveCountMax 2
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256
SSHEOF

# Validate and restart
if sshd -t 2>/dev/null; then
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || warn "Could not restart SSH"
  ok "SSH hardened and restarted"
else
  warn "sshd_config validation failed — check: sudo sshd -t"
fi

# =============================================================================
# STEP 3 — AC-LNX-04: pam_faillock account lockout
# =============================================================================
step "STEP 3 of 7  —  AC-LNX-04  Account lockout (pam_faillock)"

# Write faillock.conf
cat > /etc/security/faillock.conf << 'PAMEOF'
# ComplianceAI SNAP-01
deny = 5
unlock_time = 600
fail_interval = 900
even_deny_root
PAMEOF
ok "faillock.conf written (deny=5)"

# Write pam-auth-update profile
cat > /usr/share/pam-configs/faillock << 'PROFILEEOF'
Name: Faillock Default (Ubuntu)
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]	pam_faillock.so authfail
Auth-Initial:
	required	pam_faillock.so preauth
PROFILEEOF
ok "pam-auth-update profile created"

# Apply safely (non-interactive)
pam-auth-update --force 2>/dev/null && ok "pam-auth-update applied" || warn "pam-auth-update failed"

# Verify
if grep -q "pam_faillock" /etc/pam.d/common-auth 2>/dev/null; then
  ok "pam_faillock confirmed in /etc/pam.d/common-auth"
else
  warn "pam_faillock not in common-auth — faillock.conf is still present as evidence"
fi

# =============================================================================
# STEP 4 — FW-LNX-01: UFW firewall
# =============================================================================
step "STEP 4 of 7  —  FW-LNX-01  UFW firewall"

if ! command -v ufw &>/dev/null; then
  info "Installing ufw..."
  apt-get install -y ufw -qq 2>/dev/null || warn "ufw install failed"
fi

ufw --force reset     > /dev/null 2>&1 || true
ufw default deny incoming  > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1
ufw allow ssh          > /dev/null 2>&1
ufw allow 80/tcp       > /dev/null 2>&1
ufw allow 443/tcp      > /dev/null 2>&1
ufw --force enable     > /dev/null 2>&1

UFW_S=$(ufw status 2>/dev/null | awk '/^Status/{print $2}')
[[ "$UFW_S" == "active" ]] && ok "UFW enabled with SSH/HTTP/HTTPS rules" || fail "UFW failed to enable"

# =============================================================================
# STEP 5 — LOG-LNX-01: rsyslog running with entries
# =============================================================================
step "STEP 5 of 7  —  LOG-LNX-01  rsyslog"

if ! dpkg -l rsyslog &>/dev/null 2>&1; then
  info "Installing rsyslog..."
  apt-get install -y rsyslog -qq 2>/dev/null || warn "rsyslog install failed"
fi

systemctl enable rsyslog > /dev/null 2>&1 || true
systemctl start  rsyslog > /dev/null 2>&1 || true
sleep 1
logger "ComplianceAI SNAP-01 rsyslog check" 2>/dev/null || true
sleep 1

systemctl is-active --quiet rsyslog \
  && ok "rsyslog is running" \
  || fail "rsyslog is NOT running — run: sudo systemctl start rsyslog"

# =============================================================================
# STEP 6 — LOG-LNX-02: auth.log exists with activity
# =============================================================================
step "STEP 6 of 7  —  LOG-LNX-02  auth.log"

AUTH_LOG="/var/log/auth.log"
if [[ ! -f "$AUTH_LOG" ]]; then
  touch "$AUTH_LOG"
  chown syslog:adm "$AUTH_LOG" 2>/dev/null || true
  chmod 640 "$AUTH_LOG" 2>/dev/null || true
  info "Created $AUTH_LOG"
fi

# Generate auth activity
logger -t sudo "ComplianceAI SNAP-01 auth check" 2>/dev/null || true
sleep 1

if [[ -f "$AUTH_LOG" && -s "$AUTH_LOG" ]]; then
  ok "auth.log exists and is non-empty"
else
  warn "auth.log is empty — LOG-LNX-02 may return PARTIAL"
fi

# =============================================================================
# STEP 7 — BKP-LNX-01: rsync installed + cron schedule
# =============================================================================
step "STEP 7 of 7  —  BKP-LNX-01  Backup"

if ! command -v rsync &>/dev/null; then
  info "Installing rsync..."
  apt-get install -y rsync -qq 2>/dev/null || warn "rsync install failed"
fi
ok "rsync installed"

mkdir -p /var/backups/home_backup 2>/dev/null || true

CURRENT_CRON=$(crontab -l 2>/dev/null || echo "")
if echo "$CURRENT_CRON" | grep -q "rsync"; then
  ok "rsync cron job already present"
else
  (echo "$CURRENT_CRON"; echo "0 2 * * 0  rsync -a /home/ /var/backups/home_backup/") | crontab - 2>/dev/null \
    && ok "rsync cron job added" \
    || warn "Failed to add cron job"
fi

# =============================================================================
# VERIFICATION SUMMARY
# =============================================================================
echo -e "\n${BOLD}━━━  Verification Summary  ━━━${NC}\n"

# AC-LNX-01
PRL=$(grep -i "^\s*PermitRootLogin" "$SSHD_CONFIG" | tail -1 | awk '{print $2}')
[[ "$PRL" == "no" ]] \
  && ok  "AC-LNX-01   PermitRootLogin = $PRL" \
  || fail "AC-LNX-01   PermitRootLogin = '$PRL' (expected: no)"

# AC-LNX-02
PWA=$(grep -i "^\s*PasswordAuthentication" "$SSHD_CONFIG" | tail -1 | awk '{print $2}')
[[ "$PWA" == "no" ]] \
  && ok  "AC-LNX-02   PasswordAuthentication = $PWA" \
  || fail "AC-LNX-02   PasswordAuthentication = '$PWA' (expected: no)"

# AC-LNX-03
CAI=$(grep -i "^\s*ClientAliveInterval" "$SSHD_CONFIG" | tail -1 | awk '{print $2}')
[[ -n "$CAI" && "$CAI" -gt 0 ]] \
  && ok  "AC-LNX-03   ClientAliveInterval = $CAI" \
  || fail "AC-LNX-03   ClientAliveInterval missing or zero"

# AC-LNX-04
if grep -q "pam_faillock" /etc/pam.d/common-auth 2>/dev/null; then
  DENY=$(grep "^deny" /etc/security/faillock.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
  ok "AC-LNX-04   pam_faillock active, deny=$DENY"
elif [[ -f /etc/security/faillock.conf ]]; then
  DENY=$(grep "^deny" /etc/security/faillock.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
  warn "AC-LNX-04   faillock.conf present (deny=$DENY) — pam_faillock not in common-auth"
else
  fail "AC-LNX-04   pam_faillock not configured"
fi

# FW-LNX-01
UFW_S=$(ufw status 2>/dev/null | awk '/^Status/{print $2}')
[[ "$UFW_S" == "active" ]] \
  && ok  "FW-LNX-01   UFW = $UFW_S" \
  || fail "FW-LNX-01   UFW = '$UFW_S' (expected: active)"

# LOG-LNX-01
systemctl is-active --quiet rsyslog \
  && ok  "LOG-LNX-01  rsyslog running" \
  || fail "LOG-LNX-01  rsyslog NOT running"

# LOG-LNX-02
[[ -f /var/log/auth.log && -s /var/log/auth.log ]] \
  && ok  "LOG-LNX-02  auth.log exists and non-empty" \
  || warn "LOG-LNX-02  auth.log is empty"

# UPD-LNX-01
PENDING2=$(apt list --upgradable 2>/dev/null | grep -v "Listing..." | wc -l)
[[ "$PENDING2" -eq 0 ]] \
  && ok  "UPD-LNX-01  No pending upgrades" \
  || warn "UPD-LNX-01  $PENDING2 upgrade(s) still pending — reboot then recheck"

# BKP-LNX-01
command -v rsync &>/dev/null \
  && ok  "BKP-LNX-01  rsync installed" \
  || fail "BKP-LNX-01  rsync not found"

crontab -l 2>/dev/null | grep -q "rsync" \
  && ok  "BKP-LNX-01  cron job present" \
  || fail "BKP-LNX-01  cron job missing"

# CRYPTO-LNX-01
grep -q "^Ciphers" "$SSHD_CONFIG" 2>/dev/null \
  && ok  "CRYPTO-LNX-01  Strong ciphers set" \
  || fail "CRYPTO-LNX-01  Ciphers line missing"

# =============================================================================
# NEXT STEPS
# =============================================================================
echo -e "\n${BOLD}━━━  Next Steps  ━━━${NC}\n"
echo -e "  1. ${CYAN}If all show PASS above — reboot to apply updates:${NC}"
echo -e "     sudo reboot"
echo ""
echo -e "  2. ${CYAN}After reboot, verify no pending upgrades:${NC}"
echo -e "     apt list --upgradable 2>/dev/null | grep -v 'Listing...'"
echo -e "     (should return nothing)"
echo ""
echo -e "  3. ${CYAN}Take VirtualBox snapshot:${NC}"
echo -e "     Machine → Take Snapshot → Name: SNAP-01_Low"
echo ""
echo -e "  4. ${CYAN}Run compliance agent:${NC}"
echo -e "     cd ~/agent && python3 agent.py"
echo ""
echo -e "  5. ${CYAN}Check dashboard:${NC} http://localhost:8050"
echo -e "     Expected: Risk Level = Low  ·  Compliance ≥ 95%"
echo ""
echo -e "${GREEN}${BOLD}Script complete. Reboot when ready.${NC}"