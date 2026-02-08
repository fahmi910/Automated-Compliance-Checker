import json
from agent.utils.runner import run_powershell
from agent.utils.result import cmd_to_check


def run() -> dict:
    results = {}

    raw = run_powershell(r"""
    try {
      $s = Get-MpComputerStatus
      [PSCustomObject]@{
        AMServiceEnabled = $s.AMServiceEnabled
        AntivirusEnabled = $s.AntivirusEnabled
        RealTimeProtectionEnabled = $s.RealTimeProtectionEnabled
        AntivirusSignatureAge = $s.AntivirusSignatureAge
        NISEnabled = $s.NISEnabled
      } | ConvertTo-Json -Depth 3
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """)

    def transform(stdout: str, stderr: str, rc: int):
        if rc != 0:
            return "error"
        try:
            data = json.loads(stdout) if stdout else {}
            if isinstance(data, dict) and data.get("error"):
                return "error"
            return data
        except Exception:
            return stdout if stdout else "error"

    results["defender_status"] = cmd_to_check(
        raw,
        transform=transform,
        source_override="Get-MpComputerStatus"
    )

    return results
