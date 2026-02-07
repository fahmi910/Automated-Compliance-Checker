from agent.modules.linux import (
    logging_checks,
    firewall_checks,
    access_control,
    ports_checks,
    asset_config,
    crypto_checks,
)

def run() -> dict:
    return {
        "logging": logging_checks.run(),
        "firewall": firewall_checks.run(),
        "access_control": access_control.run(),
        "ports": ports_checks.run(),
        "asset": asset_config.run(),
        "crypto": crypto_checks.run(),
    }
