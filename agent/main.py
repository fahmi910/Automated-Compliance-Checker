import json
import os
import argparse
from pathlib import Path
from typing import Callable, Dict, Any, List, Tuple

import requests
from dotenv import load_dotenv

from agent.utils.system_info import (
    get_hostname,
    get_os_type,
    get_os_version,
    get_primary_ip,
    get_timestamp_utc,
)
from agent.utils.logger import get_logger

logger = get_logger("agent.main")

# Always load agent/.env reliably (works with: python3 -m agent.main ...)
AGENT_DIR = Path(__file__).resolve().parent
load_dotenv(AGENT_DIR / ".env")


def merge_dict(base: dict, extra: dict) -> dict:
    """
    Deep-merge dictionaries. If both values are dicts, merge recursively.
    Otherwise, extra overwrites base.
    """
    for k, v in extra.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            base[k] = merge_dict(base[k], v)
        else:
            base[k] = v
    return base


def run_modules(os_type: str, only: str = "") -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    """
    Runs OS-specific modules.
    Always returns (results, errors) without crashing the agent.
    If 'only' is provided, returns only that top-level module group.
    """
    results: Dict[str, Any] = {}
    errors: List[Dict[str, str]] = []

    logger.info(f"Detected OS: {os_type}")

    modules: List[Tuple[str, Callable[[], Dict[str, Any]]]] = []

    # Make OS check more robust (handles 'Linux', 'linux', 'Windows_NT', etc.)
    os_key = (os_type or "").strip().lower()

    if os_key == "linux":
        from agent.modules.linux import sample_linux

        def run_filtered_linux() -> Dict[str, Any]:
            data = sample_linux.run()
            if only:
                return {only: data.get(only, {})}
            return data

        modules = [("linux.sample_linux", run_filtered_linux)]

    elif os_key == "windows":
        from agent.modules.windows import sample_windows

        def run_filtered_windows() -> Dict[str, Any]:
            data = sample_windows.run()
            if only:
                return {only: data.get(only, {})}
            return data

        modules = [("windows.sample_windows", run_filtered_windows)]

    else:
        msg = f"unsupported os_type: {os_type}"
        logger.error(msg)
        errors.append({"module": "agent", "error": msg})

    logger.info(f"Modules scheduled: {[m[0] for m in modules]} | only={only or 'ALL'}")

    for name, fn in modules:
        logger.info(f"Module start: {name}")
        try:
            out = fn()
            if isinstance(out, dict):
                merge_dict(results, out)
                logger.info(f"Module success: {name}")
            else:
                msg = "module did not return dict"
                errors.append({"module": name, "error": msg})
                logger.error(f"Module bad return: {name} | {msg}")
        except Exception as e:
            msg = str(e)
            errors.append({"module": name, "error": msg})
            logger.exception(f"Module failed: {name} | {msg}")

    return results, errors


def build_payload(only: str = "") -> Dict[str, Any]:
    """
    Build the final JSON payload.
    Agent must still produce output even if a module fails.
    """
    os_type_raw = get_os_type()
    results, errors = run_modules(os_type_raw, only=only)

    payload: Dict[str, Any] = {
        "hostname": get_hostname(),
        "ip_address": get_primary_ip(),
        # Keep a nice label for server/db (matches your Week 4 outputs)
        "os_type": (os_type_raw or "").strip(),
        "os_version": get_os_version(),
        "timestamp_utc": get_timestamp_utc(),
        "results": results,
        "errors": errors,
    }

    logger.info(f"Payload built | errors={len(errors)} | top_keys={list(results.keys())}")
    return payload


def submit_payload(payload: Dict[str, Any]) -> Tuple[int, str]:
    """
    Submit payload to audit server using API key header.
    Returns (status_code, response_text).
    """
    url = os.environ.get("SERVER_URL", "http://192.168.56.1:8000/submit").strip()
    api_key = os.environ.get("AGENT_API_KEY", "").strip()

    headers = {"X-API-Key": api_key} if api_key else {}

    logger.info(f"Submitting to: {url} | api_key_set={bool(api_key)}")

    try:
        r = requests.post(url, json=payload, headers=headers, timeout=20)
        return r.status_code, r.text
    except Exception as e:
        return 0, f"submit_failed: {e}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="output.json")
    parser.add_argument(
        "--only",
        default="",
        choices=["", "logging", "firewall", "access_control", "updates", "antivirus", "assets"],
        help="Run only one module group",
    )
    args = parser.parse_args()

    payload = build_payload(only=args.only)
    out_path = os.path.abspath(args.out)

    # Ensure output directory exists if user points to a folder that doesn't exist
    out_dir = os.path.dirname(out_path)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    logger.info(f"Saved output JSON: {out_path}")
    print(f"[OK] Saved: {out_path}")

    status, resp = submit_payload(payload)
    if status == 200:
        logger.info(f"Submitted to server OK | {resp}")
        print(f"[OK] Submitted: {status}")
    elif status == 401:
        logger.error(f"Unauthorized | resp={resp}")
        print("[FAIL] Unauthorized. Check AGENT_API_KEY in agent/.env")
        print(f"[FAIL] Submit status={status} resp={resp}")
    else:
        logger.error(f"Submit failed | status={status} | resp={resp}")
        print(f"[FAIL] Submit status={status} resp={resp}")


if __name__ == "__main__":
    main()
