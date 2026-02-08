import json
from agent.utils.runner import run_powershell
from agent.utils.result import cmd_to_check


def run() -> dict:
    # 1) EventLog service status (as strings)
    svc_raw = run_powershell(r"""
    try {
      $s = Get-Service EventLog
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

    out = {}
    out["eventlog_service"] = cmd_to_check(
        svc_raw,
        transform=obj_transform,
        source_override="Get-Service EventLog (Status, StartType)"
    )

    # 2) Last Security log event (proof readable)
    last_raw = run_powershell(r"""
    try {
      $e = Get-WinEvent -LogName Security -MaxEvents 1
      [PSCustomObject]@{
        TimeCreated = $e.TimeCreated
        Id = $e.Id
        ProviderName = $e.ProviderName
        Message = ($e.Message.Substring(0, [Math]::Min(160, $e.Message.Length)))
      } | ConvertTo-Json -Depth 4
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """)

    out["last_security_event"] = cmd_to_check(
        last_raw,
        transform=obj_transform,
        source_override="Get-WinEvent -LogName Security -MaxEvents 1"
    )

    # Helper for 4624/4625 lists: return [] if no events
    def events_transform(stdout: str, stderr: str, rc: int):
        if rc != 0:
            # Sometimes PowerShell writes "No events were found" to stderr and rc != 0
            # Treat that as empty result, not an error.
            msg = (stderr or "").lower()
            if "no events were found" in msg or "nomatchingeventsfound" in msg:
                return []
            return "error"

        try:
            data = json.loads(stdout) if stdout else []
            if isinstance(data, dict) and data.get("error"):
                # Some errors still come through JSON
                emsg = str(data.get("error", "")).lower()
                if "no events" in emsg:
                    return []
                return "error"
            return data
        except Exception:
            return [] if not stdout else stdout

    # 3) Failed logins 4625 (empty list is OK)
    fail_raw = run_powershell(r"""
    try {
    $start = (Get-Date).AddDays(-7)
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=$start} -MaxEvents 3
    $events | Select-Object TimeCreated, Id, ProviderName | ConvertTo-Json -Depth 3
    } catch {
    throw
    }
    """, timeout=60)

    out["failed_logins_4625"] = cmd_to_check(
        fail_raw,
        transform=events_transform,
        source_override="Get-WinEvent Security Id=4625 (last 7 days) MaxEvents=3"
    )

    # 4) Success logins 4624
    ok_raw = run_powershell(r"""
    try {
    $start = (Get-Date).AddDays(-7)
    $events = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=$start} -MaxEvents 3
    $events | Select-Object TimeCreated, Id, ProviderName | ConvertTo-Json -Depth 3
    } catch {
    throw
    }
    """, timeout=60)

    out["success_logins_4624"] = cmd_to_check(
        ok_raw,
        transform=events_transform,
        source_override="Get-WinEvent Security Id=4624 (last 7 days) MaxEvents=3"
    )

    return out
