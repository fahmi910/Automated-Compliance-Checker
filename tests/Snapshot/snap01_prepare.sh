#!/usr/bin/env bash
# =============================================================================
#  ComplianceAI — VM1 SNAP-01 Preparation Script (v2 — safe PAM handling)
#  Target Risk Level : LOW  (all 10 controls PASS)
#  VM Platform       : Ubuntu 22.04 LTS
#  Run as            : sudo bash snap01_prepare.sh
# =============================================================================
set -euo pipefail

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
echo "║       ComplianceAI  ·  VM1 SNAP-01 Preparation  v2         ║"
echo "║       Risk Level: LOW  ·  All 10 controls → PASS           ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

SSHD_CONFIG="/etc/ssh/sshd_config"

# =============================================================================
# STEP 1 — Update packages
# UPD-LNX-01: results.updates.packages_needing_update → empty list
# Key fix: DEBIAN_FRONTEND=noninteractive prevents ALL interactive prompts
# including the PAM and openssh-server config dialogs
# =============================================================================
step "UPD-LNX-01  System packages up to date"

export DEBIAN_FRONTEND=noninteractive

info "Running apt-get update..."
apt-get update -qq

info "Running apt-get upgrade..."
apt-get upgrade -y \
  -o Dpkg::Options::="--force-confdef" \
  -o Dpkg::Options::="--force-confold" \
  -qq

info "Running apt-get dist-upgrade..."
apt-get dist-upgrade -y \
  -o Dpkg::Options::="--force-confdef" \
  -o Dpkg::Options::="--force-confold" \
  -qq

apt-get autoremove -y -qq

PENDING=$(apt list --upgradable 2>/dev/null | grep -v "Listing..." | wc -l)
if [[ "$PENDING" -eq 0 ]]; then
  ok "All packages are up to date"
else
  warn "$PENDING package(s) still pending — a reboot may clear them"
fi

# =============================================================================
# STEP 2 — SSH hardening
# AC-LNX-01: PermitRootLogin no
# AC-LNX-02: PasswordAuthentication no
# AC-LNX-03: ClientAliveInterval 300
# CRYPTO-LNX-01: strong Ciphers / MACs / KexAlgorithms
# =============================================================================
step "SSH hardening (AC-LNX-01, 02, 03, CRYPTO-LNX-01)"

cp "$SSHD_CONFIG" "${SSHD_CONFIG}.bak.snap01" 2>/dev/null || true

for directive in PermitRootLogin PasswordAuthentication PubkeyAuthentication \
                 ClientAliveInterval ClientAliveCountMax \
                 Ciphers MACs KexAlgorithms; do
  sed -i "/^\s*#*\s*${directive}\b/d" "$SSHD_CONFIG"
done

cat >> "$SSHD_CONFIG" << 'EOF'

# ComplianceAI SNAP-01
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
ClientAliveInterval 300
ClientAliveCountMax 2
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256
EOF

if sshd -t 2>/dev/null; then
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null
  ok "SSH restarted successfully"
else
  warn "sshd_config error — check: sudo sshd -t"
fi

# =============================================================================
# STEP 3 — Account lockout (pam_faillock) — SAFE Ubuntu method
# AC-LNX-04:
#   results.access_control.account_lockout_pam → "pam_faillock"
#   results.access_control.faillock_conf_deny  → "5"
#
# FIX from v1: We now use ONLY faillock.conf + pam-auth-update profile.
# We do NOT manually edit /etc/pam.d/common-auth directly.
# This prevents login breakage after reboot.
# =============================================================================
step "AC-LNX-04  Account lockout — safe pam-auth-update method"

# 1. Write faillock.conf
cat > /etc/security/faillock.conf << 'EOF'
# ComplianceAI SNAP-01
deny = 5
unlock_time = 600
fail_interval = 900
even_deny_root
EOF
ok "faillock.conf written"

# 2. Write pam-auth-update profile (Ubuntu approved method)
cat > /usr/share/pam-configs/faillock << 'EOF'
Name: Faillock Default (Ubuntu)
Default: yes
Priority: 0
Auth-Type: Primary
Auth:
	[default=die]	pam_faillock.so authfail
Auth-Initial:
	required	pam_faillock.so preauth
EOF
ok "pam-auth-update profile written"

# 3. Apply non-interactively — this safely updates common-auth
pam-auth-update --force 2>/dev/null
ok "pam-auth-update applied"

# 4. Verify
if grep -q "pam_faillock" /etc/pam.d/common-auth; then
  ok "pam_faillock confirmed in common-auth"
else
  warn "pam_faillock not in common-auth — faillock.conf may still work on Ubuntu 22.04"
fi

# =============================================================================
# STEP 4 — UFW firewall
# FW-LNX-01: ufw_status → "active", rules_exist → true
# =============================================================================
step "FW-LNX-01  UFW firewall"

if ! command -v ufw &>/dev/null; then
  apt-get install -y ufw -qq
fi

ufw --force reset     > /dev/null
ufw default deny incoming  > /dev/null
ufw default allow outgoing > /dev/null
ufw allow ssh    > /dev/null
ufw allow 80/tcp > /dev/null
ufw allow 443/tcp > /dev/null
ufw --force enable > /dev/null
ok "UFW enabled with SSH, HTTP, HTTPS rules"

# =============================================================================
# STEP 5 — rsyslog
# LOG-LNX-01: rsyslog_running → true, syslog_recent_entries → non-empty
# =============================================================================
step "LOG-LNX-01  rsyslog"

if ! dpkg -l rsyslog &>/dev/null; then
  apt-get install -y rsyslog -qq
fi
systemctl enable rsyslog > /dev/null 2>&1
systemctl start  rsyslog > /dev/null 2>&1
logger "ComplianceAI SNAP-01 rsyslog check"
sleep 1
systemctl is-active --quiet rsyslog && ok "rsyslog running" || fail "rsyslog not running"

# =============================================================================
# STEP 6 — auth.log
# LOG-LNX-02: auth_log_exists → true, meaningful activity present
# =============================================================================
step "LOG-LNX-02  auth.log"

AUTH_LOG="/var/log/auth.log"
[[ ! -f "$AUTH_LOG" ]] && touch "$AUTH_LOG" && chown syslog:adm "$AUTH_LOG" 2>/dev/null || true
logger -t sudo "ComplianceAI SNAP-01 auth log check"
sleep 1
[[ -f "$AUTH_LOG" && -s "$AUTH_LOG" ]] \
  && ok "auth.log exists and non-empty" \
  || warn "auth.log empty — LOG-LNX-02 may return PARTIAL"

# =============================================================================
# STEP 7 — Backup (rsync + cron)
# BKP-LNX-01: backup_tools_installed → ["rsync"], backup_cron_jobs → non-empty
# =============================================================================
step "BKP-LNX-01  Backup"

if ! command -v rsync &>/dev/null; then
  apt-get install -y rsync -qq
fi
ok "rsync installed"

mkdir -p /var/backups/home_backup
CURRENT_CRON=$(crontab -l 2>/dev/null || echo "")
if echo "$CURRENT_CRON" | grep -q "rsync"; then
  ok "rsync cron job already present"
else
  (echo "$CURRENT_CRON"; echo "0 2 * * 0  rsync -a /home/ /var/backups/home_backup/") | crontab -
  ok "rsync cron job added"
fi

# =============================================================================
# VERIFICATION SUMMARY
# =============================================================================
echo -e "\n${BOLD}━━━  Verification Summary  ━━━${NC}\n"

PRL=$(grep -i "^\s*PermitRootLogin" "$SSHD_CONFIG" | tail -1 | awk '{print $2}')
[[ "$PRL" == "no" ]]  && ok "AC-LNX-01  PermitRootLogin = $PRL"  || fail "AC-LNX-01  PermitRootLogin = '$PRL'"

PWA=$(grep -i "^\s*PasswordAuthentication" "$SSHD_CONFIG" | tail -1 | awk '{print $2}')
[[ "$PWA" == "no" ]]  && ok "AC-LNX-02  PasswordAuthentication = $PWA"  || fail "AC-LNX-02  PasswordAuthentication = '$PWA'"

CAI=$(grep -i "^\s*ClientAliveInterval" "$SSHD_CONFIG" | tail -1 | awk '{print $2}')
[[ -n "$CAI" && "$CAI" -gt 0 ]] && ok "AC-LNX-03  ClientAliveInterval = $CAI" || fail "AC-LNX-03  ClientAliveInterval missing"

if grep -q "pam_faillock" /etc/pam.d/common-auth 2>/dev/null; then
  DENY=$(grep "^deny" /etc/security/faillock.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
  ok "AC-LNX-04  pam_faillock active, deny=$DENY"
elif [[ -f /etc/security/faillock.conf ]]; then
  DENY=$(grep "^deny" /etc/security/faillock.conf 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
  warn "AC-LNX-04  faillock.conf present (deny=$DENY) — agent should detect this"
else
  fail "AC-LNX-04  pam_faillock not configured"
fi

UFW_S=$(ufw status | awk '/^Status/{print $2}')
[[ "$UFW_S" == "active" ]] && ok "FW-LNX-01  UFW = $UFW_S" || fail "FW-LNX-01  UFW = '$UFW_S'"

systemctl is-active --quiet rsyslog && ok "LOG-LNX-01  rsyslog running" || fail "LOG-LNX-01  rsyslog NOT running"

[[ -f /var/log/auth.log && -s /var/log/auth.log ]] \
  && ok "LOG-LNX-02  auth.log exists and non-empty" \
  || warn "LOG-LNX-02  auth.log empty"

PENDING2=$(apt list --upgradable 2>/dev/null | grep -v "Listing..." | wc -l)
[[ "$PENDING2" -eq 0 ]] \
  && ok "UPD-LNX-01  No pending upgrades" \
  || warn "UPD-LNX-01  $PENDING2 upgrade(s) pending — reboot then recheck"

command -v rsync &>/dev/null && ok "BKP-LNX-01  rsync installed" || fail "BKP-LNX-01  rsync not found"
crontab -l 2>/dev/null | grep -q "rsync" && ok "BKP-LNX-01  cron job present" || fail "BKP-LNX-01  cron job missing"

grep -q "^Ciphers" "$SSHD_CONFIG" && ok "CRYPTO-LNX-01  Strong ciphers set" || fail "CRYPTO-LNX-01  Ciphers line missing"

# =============================================================================
# NEXT STEPS
# =============================================================================
echo -e "\n${BOLD}━━━  Next Steps  ━━━${NC}\n"
echo -e "  1. ${CYAN}Reboot the VM to apply all updates:${NC}"
echo -e "     sudo reboot"
echo -e ""
echo -e "  2. ${CYAN}After reboot, log in and verify no pending upgrades:${NC}"
echo -e "     apt list --upgradable 2>/dev/null | grep -v 'Listing...'"
echo -e "     (should return nothing)"
echo -e ""
echo -e "  3. ${CYAN}Take the VirtualBox snapshot:${NC}"
echo -e "     Machine → Take Snapshot → Name: SNAP-01_Low"
echo -e ""
echo -e "  4. ${CYAN}Run the compliance agent:${NC}"
echo -e "     cd ~/agent && python3 agent.py"
echo -e ""
echo -e "  5. ${CYAN}Check dashboard at:${NC} http://localhost:8050"
echo -e "     Expected: Risk Level = Low  ·  Compliance ≥ 95%"
echo ""
echo -e "${GREEN}${BOLD}SNAP-01 preparation complete. Reboot when ready.${NC}"