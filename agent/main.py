import json
import os
import argparse

from agent.utils.system_info import (
    get_hostname, get_os_type, get_os_version, get_primary_ip, get_timestamp_utc
)

def merge_dict(base: dict, extra: dict) -> dict:
    for k, v in extra.items():
        if k in base and isinstance(base[k], dict) and isinstance(v, dict):
            base[k] = merge_dict(base[k], v)
        else:
            base[k] = v
    return base

def run_modules(os_type: str) -> tuple[dict, list]:
    results = {}
    errors = []

    if os_type == "Linux":
        from agent.modules.linux import sample_linux
        modules = [("linux.sample_linux", sample_linux.run)]
    elif os_type == "Windows":
        from agent.modules.windows import sample_windows
        modules = [("windows.sample_windows", sample_windows.run)]
    else:
        modules = []

    for name, fn in modules:
        try:
            out = fn()
            if isinstance(out, dict):
                merge_dict(results, out)
            else:
                errors.append({"module": name, "error": "module did not return dict"})
        except Exception as e:
            errors.append({"module": name, "error": str(e)})

    return results, errors

def build_payload() -> dict:
    os_type = get_os_type()
    results, errors = run_modules(os_type)

    return {
        "hostname": get_hostname(),
        "ip_address": get_primary_ip(),
        "os_type": os_type,
        "os_version": get_os_version(),
        "timestamp_utc": get_timestamp_utc(),
        "results": results,
        "errors": errors
    }

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="output.json")
    args = parser.parse_args()

    payload = build_payload()
    out_path = os.path.abspath(args.out)

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    print(f"[OK] Saved: {out_path}")

if __name__ == "__main__":
    main()
