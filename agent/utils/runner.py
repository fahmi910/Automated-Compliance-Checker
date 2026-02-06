import subprocess
from typing import Dict, Any, List

from agent.utils.logger import get_logger

logger = get_logger("agent.runner")


def run_cmd(cmd: List[str], timeout: int = 15) -> Dict[str, Any]:
    """
    Run a normal shell command (Linux commands, etc).
    Returns a standard dict: cmd, returncode, stdout, stderr.
    Logs the command + rc + stderr/exception.
    """
    cmd_str = " ".join(cmd)
    logger.info(f"LINUX_CMD: {cmd_str}")

    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

        stdout = (p.stdout or "").strip()
        stderr = (p.stderr or "").strip()

        logger.info(f"LINUX_RC: {p.returncode}")
        if stderr:
            logger.error(f"LINUX_STDERR: {stderr}")

        return {
            "cmd": cmd_str,
            "returncode": p.returncode,
            "stdout": stdout,
            "stderr": stderr,
        }

    except subprocess.TimeoutExpired:
        msg = f"timeout after {timeout}s"
        logger.error(f"LINUX_TIMEOUT: {cmd_str} | {msg}")
        return {
            "cmd": cmd_str,
            "returncode": -1,
            "stdout": "",
            "stderr": msg,
        }

    except Exception as e:
        msg = f"exception: {e}"
        logger.exception(f"LINUX_EXCEPTION: {cmd_str} | {msg}")
        return {
            "cmd": cmd_str,
            "returncode": -2,
            "stdout": "",
            "stderr": msg,
        }


def run_powershell(ps_command: str, timeout: int = 20) -> Dict[str, Any]:
    """
    Run a PowerShell command on Windows.
    Returns a standard dict: cmd, returncode, stdout, stderr.
    Logs the command + rc + stderr/exception.
    """
    logger.info(f"POWERSHELL_CMD: {ps_command}")

    full_cmd = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        ps_command,
    ]

    try:
        p = subprocess.run(full_cmd, capture_output=True, text=True, timeout=timeout)

        stdout = (p.stdout or "").strip()
        stderr = (p.stderr or "").strip()

        logger.info(f"POWERSHELL_RC: {p.returncode}")
        if stderr:
            logger.error(f"POWERSHELL_STDERR: {stderr}")

        return {
            "cmd": f"powershell -Command {ps_command}",
            "returncode": p.returncode,
            "stdout": stdout,
            "stderr": stderr,
        }

    except subprocess.TimeoutExpired:
        msg = f"timeout after {timeout}s"
        logger.error(f"POWERSHELL_TIMEOUT: {ps_command} | {msg}")
        return {
            "cmd": f"powershell -Command {ps_command}",
            "returncode": -1,
            "stdout": "",
            "stderr": msg,
        }

    except Exception as e:
        msg = f"exception: {e}"
        logger.exception(f"POWERSHELL_EXCEPTION: {ps_command} | {msg}")
        return {
            "cmd": f"powershell -Command {ps_command}",
            "returncode": -2,
            "stdout": "",
            "stderr": msg,
        }
