from agent.utils.runner import run_cmd
from agent.utils.result import make_check, make_error, cmd_to_check


def _read_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception as e:
        return ""


def _parse_sshd_value(conf_text: str, key: str) -> str:
    value = "unknown"
    for line in conf_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[0].lower() == key.lower():
            value = parts[1]
    return value


def _parse_ufw_enabled(stdout: str, stderr: str, rc: int) -> str:
    # Common outputs: "Status: active" or "Status: inactive"
    text = (stdout or "")
    for line in text.splitlines():
        line_l = line.strip().lower()
        if line_l.startswith("status:"):
            return line.split(":", 1)[1].strip().lower()

    # if sudo required or ufw not installed, reflect that clearly
    if "password is required" in (stderr or "").lower():
        return "unknown"
    if rc != 0 and not stdout:
        return "unknown"
    return "unknown"


def run() -> dict:
    # 1) Logging: rsyslog
    rsyslog_raw = run_cmd(["systemctl", "is-active", "rsyslog"])

    def rsyslog_transform(stdout: str, stderr: str, rc: int) -> bool:
        # systemctl is-active returns "active" if running
        return stdout.strip().lower() == "active" and rc == 0

    rsyslog_check = cmd_to_check(rsyslog_raw, transform=rsyslog_transform)

    # 2) Firewall: UFW
    # Try without sudo first (sometimes allowed), then sudo -n fallback
    ufw = run_cmd(["sudo", "-n", "ufw", "status"])
    if ufw_raw["returncode"] != 0 and "permission" in (ufw_raw["stderr"] or "").lower():
        ufw_raw = run_cmd(["sudo", "-n", "ufw", "status"])

    ufw_check = cmd_to_check(ufw_raw, transform=_parse_ufw_enabled)

    # 3) Access control: SSH config
    path = "/etc/ssh/sshd_config"
    sshd_text = _read_file(path)
    if not sshd_text:
        permit_root_check = make_error("cannot read sshd_config", path)
        password_auth_check = make_error("cannot read sshd_config", path)
    else:
        permit_root = _parse_sshd_value(sshd_text, "PermitRootLogin")
        password_auth = _parse_sshd_value(sshd_text, "PasswordAuthentication")

        permit_root_check = make_check(
            value=permit_root,
            evidence=f"PermitRootLogin {permit_root}",
            source=path
        )
        password_auth_check = make_check(
            value=password_auth,
            evidence=f"PasswordAuthentication {password_auth}",
            source=path
        )

    return {
        "logging": {
            "rsyslog_running": rsyslog_check
        },
        "firewall": {
            "ufw_status": ufw_check
        },
        "access_control": {
            "ssh_permit_root_login": permit_root_check,
            "ssh_password_authentication": password_auth_check
        }
    }
