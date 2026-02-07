from agent.utils.runner import run_cmd
from agent.utils.result import cmd_to_check


def run() -> dict:
    ports_raw = run_cmd(["ss", "-tuln"])
    return {
        "listening_ports": cmd_to_check(ports_raw)
    }
