from agent.utils.runner import run_powershell

def run() -> dict:
    eventlog = run_powershell("(Get-Service EventLog).Status")
    return {
        "logging": {
            "eventlog_status": eventlog["stdout"],
            "raw": eventlog
        }
    }
