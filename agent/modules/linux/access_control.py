import subprocess
from agent.utils.result import make_check, make_error


def _read_file(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def _run_cmd(cmd: list[str], timeout: int = 5) -> tuple[bool, str]:
    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = (completed.stdout or completed.stderr or "").strip()
        return completed.returncode == 0, output
    except Exception as e:
        return False, str(e)


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


def _parse_sshd_t_value(output: str, key: str) -> str:
    value = "unknown"
    for line in output.splitlines():
        line = line.strip()
        parts = line.split()
        if len(parts) >= 2 and parts[0].lower() == key.lower():
            value = parts[1]
            break
    return value


def run() -> dict:
    path = "/etc/ssh/sshd_config"
    results = {}

    # Supporting validation: SSH service status
    ok_service, service_output = _run_cmd(["systemctl", "is-active", "ssh"])
    results["ssh_service_active"] = make_check(
        value=(service_output == "active"),
        evidence=service_output,
        source="systemctl is-active ssh",
    ) if ok_service or service_output else make_error(
        "cannot determine ssh service status",
        "systemctl is-active ssh",
    )

    # Primary evidence: effective runtime SSH settings
    ok_runtime, runtime_output = _run_cmd(["sudo", "-n", "sshd", "-T"])

    if ok_runtime and runtime_output and "permitrootlogin" in runtime_output.lower():
        permit_root_runtime = _parse_sshd_t_value(runtime_output, "permitrootlogin")
        password_auth_runtime = _parse_sshd_t_value(runtime_output, "passwordauthentication")

        results["ssh_permit_root_login_runtime"] = make_check(
            value=permit_root_runtime,
            evidence=f"permitrootlogin {permit_root_runtime}",
            source="sudo -n sshd -T",
        )

        results["ssh_password_authentication_runtime"] = make_check(
            value=password_auth_runtime,
            evidence=f"passwordauthentication {password_auth_runtime}",
            source="sudo -n sshd -T",
        )
    else:
        results["ssh_permit_root_login_runtime"] = make_error(
            runtime_output or "cannot collect runtime PermitRootLogin using sshd -T",
            "sudo -n sshd -T",
        )

        results["ssh_password_authentication_runtime"] = make_error(
            runtime_output or "cannot collect runtime PasswordAuthentication using sshd -T",
            "sudo -n sshd -T",
        )

    # Secondary evidence: sshd_config
    sshd_text = _read_file(path)

    if not sshd_text:
        results["ssh_permit_root_login"] = make_error("cannot read sshd_config", path)
        results["ssh_password_authentication"] = make_error("cannot read sshd_config", path)
        return results

    permit_root = _parse_sshd_value(sshd_text, "PermitRootLogin")
    password_auth = _parse_sshd_value(sshd_text, "PasswordAuthentication")

    results["ssh_permit_root_login"] = make_check(
        value=permit_root,
        evidence=f"PermitRootLogin {permit_root}",
        source=path,
    )

    results["ssh_password_authentication"] = make_check(
        value=password_auth,
        evidence=f"PasswordAuthentication {password_auth}",
        source=path,
    )

    return results