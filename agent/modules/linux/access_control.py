from agent.utils.result import make_check, make_error


def _read_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
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


def run() -> dict:
    path = "/etc/ssh/sshd_config"
    sshd_text = _read_file(path)

    if not sshd_text:
        return {
            "ssh_permit_root_login": make_error("cannot read sshd_config", path),
            "ssh_password_authentication": make_error("cannot read sshd_config", path),
        }

    permit_root = _parse_sshd_value(sshd_text, "PermitRootLogin")
    password_auth = _parse_sshd_value(sshd_text, "PasswordAuthentication")

    return {
        "ssh_permit_root_login": make_check(
            value=permit_root,
            evidence=f"PermitRootLogin {permit_root}",
            source=path
        ),
        "ssh_password_authentication": make_check(
            value=password_auth,
            evidence=f"PasswordAuthentication {password_auth}",
            source=path
        ),
    }
