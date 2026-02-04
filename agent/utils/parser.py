import json
import re
from typing import Any, Dict, Optional

def safe_json_loads(text: str, default: Any = None) -> Any:
    """
    Safely parse JSON text. Returns default if parse fails.
    Useful for PowerShell ConvertTo-Json output.
    """
    if default is None:
        default = {}
    try:
        return json.loads(text)
    except Exception:
        return default

def parse_kv_lines(text: str) -> Dict[str, str]:
    """
    Parse outputs like:
      Key: Value
      Key = Value
      Key Value
    Returns dict of normalized keys.
    """
    out: Dict[str, str] = {}
    for raw in (text or "").splitlines():
        line = raw.strip()
        if not line:
            continue

        # Key: Value
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip().lower()] = v.strip()
            continue

        # Key = Value
        if "=" in line:
            k, v = line.split("=", 1)
            out[k.strip().lower()] = v.strip()
            continue

        # Key Value (fallback)
        parts = line.split(None, 1)
        if len(parts) == 2:
            out[parts[0].strip().lower()] = parts[1].strip()

    return out

def parse_net_accounts(text: str) -> Dict[str, Optional[str]]:
    """
    Parse 'net accounts' output into structured fields.
    We keep it tolerant because Windows output wording can vary.
    """
    result: Dict[str, Optional[str]] = {
        "min_password_length": None,
        "max_password_age": None,
        "lockout_threshold": None,
        "lockout_duration": None,
        "lockout_window": None,
        "raw": text.strip() if text else ""
    }

    lines = (text or "").splitlines()
    for line in lines:
        s = line.strip()

        # Examples (may vary):
        # "Minimum password length: 8"
        # "Maximum password age (days): 90"
        # "Lockout threshold: Never" or "Lockout threshold: 5"
        if s.lower().startswith("minimum password length"):
            result["min_password_length"] = _last_number_or_text(s)

        elif s.lower().startswith("maximum password age"):
            result["max_password_age"] = _last_number_or_text(s)

        elif s.lower().startswith("lockout threshold"):
            result["lockout_threshold"] = _last_number_or_text(s)

        elif s.lower().startswith("lockout duration"):
            result["lockout_duration"] = _last_number_or_text(s)

        elif "lockout observation window" in s.lower():
            result["lockout_window"] = _last_number_or_text(s)

    return result

def _last_number_or_text(line: str) -> str:
    """
    Return last number in a line if present, else last token text.
    """
    nums = re.findall(r"\d+", line)
    if nums:
        return nums[-1]
    # fallback to last chunk after colon if available
    if ":" in line:
        return line.split(":", 1)[1].strip()
    return line.strip()
