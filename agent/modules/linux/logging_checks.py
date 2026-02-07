from agent.utils.runner import run_cmd
from agent.utils.result import cmd_to_check


def run() -> dict:
    rsyslog_raw = run_cmd(["systemctl", "is-active", "rsyslog"])

    def rsyslog_transform(stdout: str, stderr: str, rc: int) -> bool:
        return stdout.strip().lower() == "active" and rc == 0

    return {
        "rsyslog_running": cmd_to_check(rsyslog_raw, transform=rsyslog_transform)
    }
