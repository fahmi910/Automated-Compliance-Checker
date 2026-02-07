from typing import Any, Dict, Optional


def make_check(value: Any, evidence: str, source: str) -> Dict[str, Any]:
    """
    Standard audit check format for every check result.
    """
    return {
        "value": value,
        "evidence": (evidence or "").strip(),
        "source": source
    }


def make_error(message: str, source: str) -> Dict[str, Any]:
    """
    Use this when the check cannot be performed reliably.
    """
    return {
        "value": "error",
        "evidence": message.strip(),
        "source": source
    }


def cmd_to_check(raw: Dict[str, Any], transform=None, source_override: Optional[str] = None) -> Dict[str, Any]:
    """
    Convert run_cmd() or run_powershell() output into make_check() format.

    raw must contain: cmd, returncode, stdout, stderr
    transform: optional function(stdout, stderr, returncode) -> value
    """
    cmd = source_override or raw.get("cmd", "unknown_cmd")
    rc = raw.get("returncode", -999)
    stdout = (raw.get("stdout") or "").strip()
    stderr = (raw.get("stderr") or "").strip()

    evidence = stdout if stdout else stderr

    if transform:
        try:
            value = transform(stdout, stderr, rc)
        except Exception as e:
            return make_error(f"transform error: {e}", cmd)
    else:
        value = stdout

    return make_check(value=value, evidence=evidence, source=cmd)
