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

# ----------------------------------------------------------------
# AC-LNX-03: Inactive local accounts disabled
# AC-LNX-04: Account lockout policy configured
# Added checks — appended to module
# ----------------------------------------------------------------

def _run_ac_extra_checks() -> dict:
    """
    Extra access control checks for AC-LNX-03 and AC-LNX-04.
    Called from run_extra() which is imported by sample_linux.py via access_control.run_extra().
    """
    results = {}

    # AC-LNX-03: accounts that have never logged in (lastlog)
    ok_lastlog, lastlog_out = _run_cmd(["lastlog"], timeout=10)
    never_logged = []
    if ok_lastlog and lastlog_out:
        for line in lastlog_out.splitlines()[1:]:  # skip header
            parts = line.split()
            if not parts:
                continue
            username = parts[0]
            rest = " ".join(parts[1:]).lower()
            if "never logged in" in rest:
                never_logged.append(username)

    results["accounts_never_logged_in"] = make_check(
        value=never_logged,
        evidence=(
            f"Accounts with no login history: {', '.join(never_logged)}"
            if never_logged else "No accounts with 'Never logged in' status found"
        ),
        source="lastlog",
    )

    # Shell accounts from /etc/passwd (uid >= 1000, login shell)
    passwd_text = _read_file("/etc/passwd")
    shell_accounts = []
    no_login_shells = ["/sbin/nologin", "/bin/false", "/usr/sbin/nologin"]
    for line in passwd_text.splitlines():
        parts = line.split(":")
        if len(parts) < 7:
            continue
        username, _, uid_str, _, _, _, shell = parts[:7]
        try:
            uid = int(uid_str)
        except ValueError:
            continue
        if uid < 1000:
            continue
        if shell.strip() in no_login_shells:
            continue
        shell_accounts.append(username)

    results["shell_accounts_passwd"] = make_check(
        value=shell_accounts,
        evidence=(
            f"Human login accounts (uid>=1000, login shell): {', '.join(shell_accounts)}"
            if shell_accounts else "No human accounts with login shells found"
        ),
        source="/etc/passwd",
    )

    # AC-LNX-04: Account lockout via PAM
    pam_dirs = [
        "/etc/pam.d/common-auth",
        "/etc/pam.d/system-auth",
        "/etc/pam.d/password-auth",
    ]
    faillock_found = False
    tally2_found = False
    pam_evidence_lines = []

    for pam_path in pam_dirs:
        pam_text = _read_file(pam_path)
        if not pam_text:
            continue
        for line in pam_text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            low = stripped.lower()
            if "pam_faillock" in low:
                faillock_found = True
                pam_evidence_lines.append(f"{pam_path}: {stripped[:120]}")
            elif "pam_tally2" in low:
                tally2_found = True
                pam_evidence_lines.append(f"{pam_path}: {stripped[:120]}")

    faillock_conf_text = _read_file("/etc/security/faillock.conf")
    deny_value = "not_set"
    unlock_value = "not_set"
    if faillock_conf_text:
        for line in faillock_conf_text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if stripped.lower().startswith("deny"):
                deny_value = stripped
            if stripped.lower().startswith("unlock_time"):
                unlock_value = stripped

    lockout_mechanism = (
        "pam_faillock" if faillock_found
        else "pam_tally2" if tally2_found
        else "none"
    )

    results["account_lockout_pam"] = make_check(
        value=lockout_mechanism,
        evidence=(
            "\n".join(pam_evidence_lines[:6])
            if pam_evidence_lines
            else "No pam_faillock or pam_tally2 found in PAM configuration files"
        ),
        source=", ".join(pam_dirs),
    )

    results["faillock_conf_deny"] = make_check(
        value=deny_value,
        evidence=(
            f"deny={deny_value}, unlock_time={unlock_value}"
            if faillock_conf_text
            else "/etc/security/faillock.conf not found"
        ),
        source="/etc/security/faillock.conf",
    )

    return results


def run_extra() -> dict:
    """
    Returns additional access control evidence for AC-LNX-03 and AC-LNX-04.
    Merged into the access_control key by sample_linux.py.
    """
    return _run_ac_extra_checks()