from agent.modules.linux import logging_checks, firewall_checks, access_control


def run() -> dict:
    results = {}
    results["logging"] = logging_checks.run()
    results["firewall"] = firewall_checks.run()
    results["access_control"] = access_control.run()
    return results
