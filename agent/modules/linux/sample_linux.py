from agent.utils.runner import run_cmd

def _read_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""

def _parse_sshd_value(conf_text: str, key: str) -> str:
    # Gets the last active (non-comment) occurrence
    value = "unknown"
    for line in conf_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0].lower() == key.lower():
            value = parts[1]
    return value

def _parse_ufw_enabled(ufw_text: str) -> str:
    # Common outputs:
    # "Status: active" or "Status: inactive"
    for line in (ufw_text or "").splitlines():
        line = line.strip().lower()
        if line.startswith("status:"):
            return line.split(":", 1)[1].strip()
    return "unknown"

def run() -> dict:
    # 1) Logging: rsyslog
    rsyslog = run_cmd(["systemctl", "is-active", "rsyslog"])

    # 2) Firewall: UFW
    ufw = run_cmd(["ufw", "status"])
    ufw_enabled = _parse_ufw_enabled(ufw["stdout"])

    # 3) Access control: SSH config
    sshd_text = _read_file("/etc/ssh/sshd_config")
    permit_root = _parse_sshd_value(sshd_text, "PermitRootLogin")
    password_auth = _parse_sshd_value(sshd_text, "PasswordAuthentication")

    return {
        "logging": {
            "rsyslog_is_active": rsyslog["stdout"],
            "raw": {"rsyslog": rsyslog},
        },
        "firewall": {
            "ufw_status": ufw_enabled,   # active/inactive/unknown
            "raw": {"ufw": ufw},
        },
        "access_control": {
            "ssh_permit_root_login": permit_root,              # yes/no/prohibit-password/unknown
            "ssh_password_authentication": password_auth,      # yes/no/unknown
            "raw": {"sshd_config_path": "/etc/ssh/sshd_config"},
        }
    }
