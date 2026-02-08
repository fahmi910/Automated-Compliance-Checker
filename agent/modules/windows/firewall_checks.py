import json
from agent.utils.runner import run_powershell
from agent.utils.result import cmd_to_check, make_error


def run() -> dict:
    results = {}

    ps = r"""
    try {
      Get-NetFirewallProfile |
        Select-Object Name, Enabled |
        ConvertTo-Json -Depth 3
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """

    raw = run_powershell(ps)

    def transform(stdout: str, stderr: str, rc: int):
        if rc != 0:
            return "error"
        # Keep as structured json if possible
        try:
            data = json.loads(stdout) if stdout else {}
            # If it returned {"error": "..."} treat as error
            if isinstance(data, dict) and data.get("error"):
                return "error"
            return data
        except Exception:
            return stdout if stdout else "error"

    results["firewall_profiles"] = cmd_to_check(
        raw,
        transform=transform,
        source_override="Get-NetFirewallProfile | Select Name, Enabled"
    )

    return {"firewall": results}
