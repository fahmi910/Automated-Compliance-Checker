from agent.utils.runner import run_cmd

def run() -> dict:
    rsyslog = run_cmd(["systemctl", "is-active", "rsyslog"])
    return {
        "logging": {
            "rsyslog_is_active": rsyslog["stdout"],
            "raw": rsyslog
        }
    }
