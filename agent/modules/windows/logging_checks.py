import json
from agent.utils.runner import run_powershell
from agent.utils.result import cmd_to_check


def run() -> dict:
    results = {}

    # 1) Event Log service status
    svc_raw = run_powershell(r"""
    try {
      Get-Service EventLog | Select-Object Status, StartType | ConvertTo-Json -Depth 3
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """)

    def svc_transform(stdout: str, stderr: str, rc: int):
        if rc != 0:
            return "error"
        try:
            return json.loads(stdout)
        except Exception:
            return stdout if stdout else "error"

    results["eventlog_service"] = cmd_to_check(
        svc_raw,
        transform=svc_transform,
        source_override="Get-Service EventLog | Select Status, StartType"
    )

    # 2) Last Security log event (proof Security log is readable)
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

    def last_transform(stdout: str, stderr: str, rc: int):
        if rc != 0:
            return "error"
        try:
            data = json.loads(stdout) if stdout else {}
            if isinstance(data, dict) and data.get("error"):
                return "error"
            return data
        except Exception:
            return stdout if stdout else "error"

    results["last_security_event"] = cmd_to_check(
        last_raw,
        transform=last_transform,
        source_override="Get-WinEvent -LogName Security -MaxEvents 1"
    )

    # 3) Failed logins 4625 (evidence sample)
    fail_raw = run_powershell(r"""
    try {
      Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 3 |
        Select-Object TimeCreated, Id, ProviderName |
        ConvertTo-Json -Depth 3
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """)

    def list_transform(stdout: str, stderr: str, rc: int):
        if rc != 0:
            return "error"
        try:
            data = json.loads(stdout) if stdout else {}
            if isinstance(data, dict) and data.get("error"):
                return "error"
            return data
        except Exception:
            return stdout if stdout else "error"

    results["failed_logins_4625"] = cmd_to_check(
        fail_raw,
        transform=list_transform,
        source_override="Get-WinEvent Security Id=4625 MaxEvents=3"
    )

    # 4) Successful logins 4624 (evidence sample)
    ok_raw = run_powershell(r"""
    try {
      Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624} -MaxEvents 3 |
        Select-Object TimeCreated, Id, ProviderName |
        ConvertTo-Json -Depth 3
    } catch {
      [PSCustomObject]@{ error = $_.Exception.Message } | ConvertTo-Json -Depth 3
    }
    """)

    results["success_logins_4624"] = cmd_to_check(
        ok_raw,
        transform=list_transform,
        source_override="Get-WinEvent Security Id=4624 MaxEvents=3"
    )

    return {"logging": results}
