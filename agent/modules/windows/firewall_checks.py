import json
from agent.utils.runner import run_powershell
from agent.utils.result import cmd_to_check


def run() -> dict:
    results = {}

    def obj_transform(stdout: str, stderr: str, rc: int):
        stdout = (stdout or "").strip()

        if stdout:
            try:
                data = json.loads(stdout)
                if isinstance(data, dict) and data.get("error"):
                    return "error"
                return data
            except Exception:
                pass

        if rc != 0:
            return "error"

        return stdout if stdout else "error"

    raw = run_powershell(r"""
    try {
      $profiles = Get-NetFirewallProfile |
        Select-Object Name, Enabled, DefaultInboundAction

      $profiles | ConvertTo-Json -Depth 4
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 4
    }
    """)

    results["windows_firewall_profiles"] = cmd_to_check(
        raw,
        transform=obj_transform,
        source_override="Get-NetFirewallProfile | Select Name, Enabled, DefaultInboundAction"
    )

    return results