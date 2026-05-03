import os
from agent.utils.runner import run_cmd
from agent.utils.result import make_check, cmd_to_check


def _file_exists(path: str) -> bool:
    return os.path.exists(path)


def _tail_grep(path: str, pattern: str) -> dict:
    # Safe small snippet only
    cmd = ["bash", "-lc", f"grep -F '{pattern}' {path} | tail -n 5"]
    return run_cmd(cmd)


def _snippet_or_none(raw: dict, label: str) -> dict:
    """
    If grep finds nothing, stdout will be empty (rc may be 0 or 1).
    We want clean audit output: explicit 'none' instead of empty strings.
    """
    stdout = (raw.get("stdout") or "").strip()
    cmd = raw.get("cmd", "unknown_cmd")

    if not stdout:
        return make_check(
            value="none",
            evidence=f"No {label} found",
            source=cmd
        )

    return make_check(
        value=stdout,
        evidence=stdout,
        source=cmd
    )

def _tail_file(path: str, lines: int = 5) -> dict:
    cmd = ["bash", "-lc", f"tail -n {lines} {path}"]
    return run_cmd(cmd)

def run() -> dict:
    results = {}

    # rsyslog running
    rsyslog_raw = run_cmd(["systemctl", "is-active", "rsyslog"])

    def rsyslog_transform(stdout: str, stderr: str, rc: int) -> bool:
        return stdout.strip().lower() == "active" and rc == 0

    results["rsyslog_running"] = cmd_to_check(rsyslog_raw, transform=rsyslog_transform)

    # log files exist
    auth_path = "/var/log/auth.log"
    syslog_path = "/var/log/syslog"

    results["auth_log_exists"] = make_check(
        value=_file_exists(auth_path),
        evidence=auth_path,
        source="os.path.exists"
    )

    results["syslog_exists"] = make_check(
        value=_file_exists(syslog_path),
        evidence=syslog_path,
        source="os.path.exists"
    )

    if _file_exists(syslog_path):
        syslog_tail_raw = _tail_file(syslog_path, 5)
        results["syslog_recent_entries"] = _snippet_or_none(
            syslog_tail_raw,
            "recent syslog entries"
        )
    else:
        results["syslog_recent_entries"] = make_check(
            value="n/a",
            evidence="syslog not found",
            source=syslog_path
        )

    # evidence snippets (only if auth.log exists)
    if _file_exists(auth_path):
        failed_raw = _tail_grep(auth_path, "Failed password")
        results["failed_ssh_logins_snippet"] = _snippet_or_none(failed_raw, "failed SSH logins")

        sudo_raw = _tail_grep(auth_path, "sudo")
        results["sudo_usage_snippet"] = _snippet_or_none(sudo_raw, "sudo usage")
    else:
        results["failed_ssh_logins_snippet"] = make_check(
            value="n/a",
            evidence="auth.log not found",
            source=auth_path
        )
        results["sudo_usage_snippet"] = make_check(
            value="n/a",
            evidence="auth.log not found",
            source=auth_path
        )

    return results


# ----------------------------------------------------------------
# LOG-LNX-03: Log rotation configured
# Check logrotate installation and configuration
# ----------------------------------------------------------------

def run_logrotate_check() -> dict:
    """
    Checks for logrotate installation and active configuration.
    Returns dict to be merged into logging results.
    """
    import os as _os
    results = {}

    # Is logrotate installed?
    logrotate_raw = run_cmd(["which", "logrotate"])
    logrotate_installed = logrotate_raw.get("returncode", -1) == 0
    logrotate_path = (logrotate_raw.get("stdout") or "").strip()

    results["logrotate_installed"] = make_check(
        value=logrotate_installed,
        evidence=logrotate_path if logrotate_installed else "logrotate not found in PATH",
        source=logrotate_raw.get("cmd", "which logrotate"),
    )

    # Count active config files in /etc/logrotate.d/
    logrotate_d = "/etc/logrotate.d"
    conf_count = 0
    conf_files = []
    if _os.path.isdir(logrotate_d):
        try:
            entries = [
                f for f in _os.listdir(logrotate_d)
                if _os.path.isfile(_os.path.join(logrotate_d, f))
            ]
            conf_count = len(entries)
            conf_files = entries[:10]  # first 10 for evidence
        except Exception:
            pass

    results["logrotate_d_configs"] = make_check(
        value=conf_count,
        evidence=(
            f"{conf_count} config files in {logrotate_d}: {', '.join(conf_files)}"
            if conf_count > 0
            else f"No config files found in {logrotate_d}"
        ),
        source=logrotate_d,
    )

    # Check main logrotate.conf exists and has a rotation interval
    main_conf_path = "/etc/logrotate.conf"
    rotation_interval = "not_set"
    try:
        with open(main_conf_path, "r", encoding="utf-8", errors="ignore") as f:
            conf_text = f.read()
        for line in conf_text.splitlines():
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue
            low = stripped.lower()
            if low in ("daily", "weekly", "monthly", "yearly"):
                rotation_interval = low
                break
    except Exception:
        conf_text = ""

    results["logrotate_conf_interval"] = make_check(
        value=rotation_interval,
        evidence=(
            f"Global rotation interval in {main_conf_path}: {rotation_interval}"
            if conf_text
            else f"{main_conf_path} not readable"
        ),
        source=main_conf_path,
    )

    # Check logrotate timer / cron (how it's triggered)
    timer_raw = run_cmd(["systemctl", "is-enabled", "logrotate.timer"])
    timer_enabled = (timer_raw.get("stdout") or "").strip().lower() == "enabled"

    cron_daily_exists = _os.path.isfile("/etc/cron.daily/logrotate")

    trigger = []
    if timer_enabled:
        trigger.append("systemd logrotate.timer enabled")
    if cron_daily_exists:
        trigger.append("/etc/cron.daily/logrotate exists")

    results["logrotate_trigger"] = make_check(
        value=trigger if trigger else [],
        evidence=(
            "; ".join(trigger)
            if trigger
            else "Neither systemd timer nor cron.daily/logrotate found"
        ),
        source="systemctl is-enabled logrotate.timer + /etc/cron.daily/logrotate",
    )

    return results