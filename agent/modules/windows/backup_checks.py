import json
from agent.utils.runner import run_powershell
from agent.utils.result import cmd_to_check, make_check, make_error


def _obj_transform(stdout: str, stderr: str, rc: int):
    """Standard JSON object transform used across Windows checks."""
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


def _str_transform(stdout: str, stderr: str, rc: int):
    """Transform for plain string output."""
    if rc != 0 and not stdout:
        return "error"
    return (stdout or "").strip() or "error"


def run() -> dict:
    out = {}

    # ----------------------------------------------------------------
    # 1) Volume Shadow Copy Service (VSS) status
    #    VSS is the Windows backup infrastructure. Must be running.
    # ----------------------------------------------------------------
    vss_raw = run_powershell(r"""
    try {
      $s = Get-Service VSS
      [PSCustomObject]@{
        Status    = $s.Status.ToString()
        StartType = $s.StartType.ToString()
      } | ConvertTo-Json -Depth 3
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """)

    out["vss_service"] = cmd_to_check(
        vss_raw,
        transform=_obj_transform,
        source_override="Get-Service VSS (Status, StartType)",
    )

    # ----------------------------------------------------------------
    # 2) Existing shadow copies (proof that VSS has actually run)
    # ----------------------------------------------------------------
    shadows_raw = run_powershell(r"""
    try {
      $shadows = Get-WmiObject Win32_ShadowCopy | Select-Object ID, InstallDate, VolumeName
      if ($shadows) {
        $shadows | ConvertTo-Json -Depth 3
      } else {
        [PSCustomObject]@{ count = 0; note = "No shadow copies found" } | ConvertTo-Json -Depth 3
      }
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """, timeout=30)

    out["shadow_copies"] = cmd_to_check(
        shadows_raw,
        transform=_obj_transform,
        source_override="Get-WmiObject Win32_ShadowCopy",
    )

    # ----------------------------------------------------------------
    # 3) Windows Server Backup feature installed (wbadmin)
    #    Only meaningful on Windows Server; on W10 we check File History.
    # ----------------------------------------------------------------
    wbadmin_raw = run_powershell(r"""
    try {
      $cmd = Get-Command wbadmin -ErrorAction SilentlyContinue
      if ($cmd) {
        # Get last backup status summary
        $status = wbadmin get versions 2>&1 | Select-Object -First 10
        [PSCustomObject]@{
          wbadmin_available = $true
          status_snippet    = ($status -join "`n")
        } | ConvertTo-Json -Depth 3
      } else {
        [PSCustomObject]@{
          wbadmin_available = $false
          status_snippet    = "wbadmin not found on this system"
        } | ConvertTo-Json -Depth 3
      }
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """, timeout=30)

    out["wbadmin_status"] = cmd_to_check(
        wbadmin_raw,
        transform=_obj_transform,
        source_override="Get-Command wbadmin + wbadmin get versions",
    )

    # ----------------------------------------------------------------
    # 4) Windows 10 File History service status
    #    File History Service (fhsvc) is the W10 backup service.
    # ----------------------------------------------------------------
    fh_raw = run_powershell(r"""
    try {
      $s = Get-Service fhsvc -ErrorAction SilentlyContinue
      if ($s) {
        [PSCustomObject]@{
          Status    = $s.Status.ToString()
          StartType = $s.StartType.ToString()
        } | ConvertTo-Json -Depth 3
      } else {
        [PSCustomObject]@{ note = "File History service (fhsvc) not present on this system" } | ConvertTo-Json -Depth 3
      }
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """)

    out["file_history_service"] = cmd_to_check(
        fh_raw,
        transform=_obj_transform,
        source_override="Get-Service fhsvc (File History)",
    )

    # ----------------------------------------------------------------
    # 5) Scheduled backup tasks
    #    Look for any scheduled tasks with backup-related names.
    # ----------------------------------------------------------------
    tasks_raw = run_powershell(r"""
    try {
      $keywords = @('backup','shadow','wbadmin','history','restore','vss')
      $tasks = Get-ScheduledTask | Where-Object {
        $name = $_.TaskName.ToLower()
        $path = $_.TaskPath.ToLower()
        ($keywords | Where-Object { $name -like "*$_*" -or $path -like "*$_*" }).Count -gt 0
      } | Select-Object TaskName, TaskPath, State
      if ($tasks) {
        $tasks | ConvertTo-Json -Depth 3
      } else {
        [PSCustomObject]@{ count = 0; note = "No backup-related scheduled tasks found" } | ConvertTo-Json -Depth 3
      }
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """, timeout=30)

    out["backup_scheduled_tasks"] = cmd_to_check(
        tasks_raw,
        transform=_obj_transform,
        source_override="Get-ScheduledTask (backup/shadow/vss filter)",
    )

    return out