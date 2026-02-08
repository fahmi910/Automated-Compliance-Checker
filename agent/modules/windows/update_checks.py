import json
from agent.utils.runner import run_powershell
from agent.utils.result import cmd_to_check


def run() -> dict:
    out = {}

    # 1) Windows Update service (wuauserv) as strings
    wua_raw = run_powershell(r"""
    try {
      $s = Get-Service wuauserv
      [PSCustomObject]@{
        Status = $s.Status.ToString()
        StartType = $s.StartType.ToString()
      } | ConvertTo-Json -Depth 3
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """)

    def obj_transform(stdout: str, stderr: str, rc: int):
        if rc != 0:
            return "error"
        try:
            data = json.loads(stdout) if stdout else {}
            if isinstance(data, dict) and data.get("error"):
                return "error"
            return data
        except Exception:
            return stdout if stdout else "error"

    out["windows_update_service"] = cmd_to_check(
        wua_raw,
        transform=obj_transform,
        source_override="Get-Service wuauserv (Status, StartType)"
    )

    # 2) Latest hotfix
    hotfix_raw = run_powershell(r"""
    try {
      Get-HotFix |
        Sort-Object InstalledOn -Descending |
        Select-Object -First 1 HotFixID, InstalledOn, Description |
        ConvertTo-Json -Depth 3
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """, timeout=60)

    out["latest_hotfix"] = cmd_to_check(
        hotfix_raw,
        transform=obj_transform,
        source_override="Get-HotFix | Sort InstalledOn desc | Select -First 1"
    )

    return out
