import json
from agent.utils.runner import run_powershell
from agent.utils.result import cmd_to_check


def run() -> dict:
    results = {}

    # Windows Update service
    wua_raw = run_powershell(r"""
    try {
      Get-Service wuauserv | Select-Object Status, StartType | ConvertTo-Json -Depth 3
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """)

    def obj_transform(stdout: str, stderr: str, rc: int):
        if rc != 0:
            return "error"
        try:
            return json.loads(stdout)
        except Exception:
            return stdout if stdout else "error"

    results["windows_update_service"] = cmd_to_check(
        wua_raw,
        transform=obj_transform,
        source_override="Get-Service wuauserv | Select Status, StartType"
    )

    # Latest hotfix
    hotfix_raw = run_powershell(r"""
    try {
      Get-HotFix |
        Sort-Object InstalledOn -Descending |
        Select-Object -First 1 HotFixID, InstalledOn, Description |
        ConvertTo-Json -Depth 3
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """)

    results["latest_hotfix"] = cmd_to_check(
        hotfix_raw,
        transform=obj_transform,
        source_override="Get-HotFix | Sort InstalledOn desc | Select -First 1"
    )

    return {"updates": results}
