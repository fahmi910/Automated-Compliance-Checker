from agent.utils.runner import run_powershell
from agent.utils.parsers import safe_json_loads, parse_net_accounts

def run() -> dict:
    eventlog = run_powershell("(Get-Service EventLog).Status")

    fw = run_powershell("Get-NetFirewallProfile | Select Name,Enabled | ConvertTo-Json")
    fw_profiles = safe_json_loads(fw["stdout"], default=[])

    net_acc = run_powershell("net accounts")
    net_acc_parsed = parse_net_accounts(net_acc["stdout"])

    return {
        "logging": {
            "eventlog_status": eventlog["stdout"],
            "raw": {"eventlog": eventlog},
        },
        "firewall": {
            "profiles": fw_profiles,
            "raw": {"firewall_cmd": fw},
        },
        "access_control": {
            "password_policy": net_acc_parsed,
            "raw": {"net_accounts_cmd": net_acc},
        }
    }
