import json
import os
import argparse
from typing import Callable, Dict, Any, List, Tuple

from agent.utils.system_info import (
    get_hostname, get_os_type, get_os_version, get_primary_ip, get_timestamp_utc
)
from agent.utils.logger import get_logger

logger = get_logger("agent.main")


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


def run_modules(os_type: str) -> Tuple[Dict[str, Any], List[Dict[str, str]]]:
    """
    Runs OS-specific modules.
    Always returns (results, errors) without crashing the agent.
    Logs:
    - Which modules ran
    - Success/failure per module
    """
    results: Dict[str, Any] = {}
    errors: List[Dict[str, str]] = []

    logger.info(f"Detected OS: {os_type}")

    modules: List[Tuple[str, Callable[[], Dict[str, Any]]]] = []

    if os_type == "Linux":
        from agent.modules.linux import sample_linux
        modules = [("linux.sample_linux", sample_linux.run)]
    elif os_type == "Windows":
        from agent.modules.windows import sample_windows
        modules = [("windows.sample_windows", sample_windows.run)]
    else:
        logger.error(f"Unsupported OS type: {os_type}")
        errors.append({"module": "agent", "error": f"unsupported os_type: {os_type}"})

    logger.info(f"Modules scheduled: {[m[0] for m in modules]}")

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


def build_payload() -> Dict[str, Any]:
    """
    Build the final JSON payload.
    Agent must still produce output even if a module fails.
    """
    os_type = get_os_type()
    results, errors = run_modules(os_type)

    payload = {
        "hostname": get_hostname(),
        "ip_address": get_primary_ip(),
        "os_type": os_type,
        "os_version": get_os_version(),
        "timestamp_utc": get_timestamp_utc(),
        "results": results,
        "errors": errors
    }

    logger.info(
        f"Payload built | errors={len(errors)} | top_keys={list(results.keys())}"
    )
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="output.json")
    args = parser.parse_args()

    payload = build_payload()
    out_path = os.path.abspath(args.out)

    # Ensure output directory exists if user points to a folder that doesn't exist
    out_dir = os.path.dirname(out_path)
    if out_dir and not os.path.exists(out_dir):
        os.makedirs(out_dir, exist_ok=True)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    logger.info(f"Saved output JSON: {out_path}")
    print(f"[OK] Saved: {out_path}")


if __name__ == "__main__":
    main()
