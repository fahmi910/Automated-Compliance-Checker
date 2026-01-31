import subprocess
from typing import Dict, Any, List

def run_cmd(cmd: List[str], timeout: int = 15) -> Dict[str, Any]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return {"cmd": " ".join(cmd), "returncode": p.returncode,
                "stdout": (p.stdout or "").strip(), "stderr": (p.stderr or "").strip()}
    except subprocess.TimeoutExpired:
        return {"cmd": " ".join(cmd), "returncode": -1, "stdout": "", "stderr": f"timeout after {timeout}s"}
    except Exception as e:
        return {"cmd": " ".join(cmd), "returncode": -2, "stdout": "", "stderr": f"exception: {e}"}

def run_powershell(ps_command: str, timeout: int = 20) -> Dict[str, Any]:
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_command],
            capture_output=True, text=True, timeout=timeout
        )
        return {"cmd": f"powershell -Command {ps_command}", "returncode": p.returncode,
                "stdout": (p.stdout or "").strip(), "stderr": (p.stderr or "").strip()}
    except subprocess.TimeoutExpired:
        return {"cmd": f"powershell -Command {ps_command}", "returncode": -1, "stdout": "", "stderr": f"timeout after {timeout}s"}
    except Exception as e:
        return {"cmd": f"powershell -Command {ps_command}", "returncode": -2, "stdout": "", "stderr": f"exception: {e}"}
