import os
from agent.utils.runner import run_cmd
from agent.utils.result import make_check, cmd_to_check


def _file_exists(path: str) -> bool:
    return os.path.exists(path)


def _tail_grep(path: str, pattern: str) -> dict:
    # Safe small snippet only
    cmd = ["bash", "-lc", f"grep -F '{pattern}' {path} | tail -n 5"]
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

    # evidence snippets (only if auth.log exists)
    if _file_exists(auth_path):
        failed_raw = _tail_grep(auth_path, "Failed password")
        results["failed_ssh_logins_snippet"] = cmd_to_check(failed_raw)

        sudo_raw = _tail_grep(auth_path, "sudo")
        results["sudo_usage_snippet"] = cmd_to_check(sudo_raw)
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
