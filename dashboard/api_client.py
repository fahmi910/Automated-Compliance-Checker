import os
import requests
from typing import Any, Dict, Optional

DEFAULT_BASE_URL = "http://127.0.0.1:8000"

def get_base_url() -> str:
    return os.environ.get("AUDIT_API_BASE_URL", DEFAULT_BASE_URL).rstrip("/")

def _get(url: str, params: Optional[Dict[str, Any]] = None, timeout: int = 10) -> Dict[str, Any]:
    r = requests.get(url, params=params, timeout=timeout)
    try:
        data = r.json()
    except Exception:
        data = {"error": "Non-JSON response", "status_code": r.status_code, "text": r.text}

    if r.status_code >= 400:
        # Normalize error
        if isinstance(data, dict) and "error" in data:
            raise RuntimeError(f"{r.status_code}: {data.get('error')}")
        raise RuntimeError(f"{r.status_code}: Request failed")
    return data

def health() -> Dict[str, Any]:
    return _get(f"{get_base_url()}/health")

def list_hosts() -> Dict[str, Any]:
    return _get(f"{get_base_url()}/hosts")

def latest_audit(hostname: str) -> Dict[str, Any]:
    return _get(f"{get_base_url()}/audits/latest", params={"hostname": hostname})

def latest_evaluated(hostname: str) -> Dict[str, Any]:
    return _get(f"{get_base_url()}/audits/latest/evaluated", params={"hostname": hostname})

def list_audits(hostname: str, limit: int = 20) -> Dict[str, Any]:
    return _get(f"{get_base_url()}/audits", params={"hostname": hostname, "limit": limit})

def evaluated_audit(audit_id: int) -> Dict[str, Any]:
    return _get(f"{get_base_url()}/audits/{audit_id}/evaluated")