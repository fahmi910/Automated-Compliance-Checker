from agent.modules.windows import (
    firewall_checks,
    logging_checks,
    access_control,
    update_checks,
    av_checks,
    asset_checks,
)

def run() -> dict:
    return {
        "firewall": firewall_checks.run(),
        "logging": logging_checks.run(),
        "access_control": access_control.run(),
        "updates": update_checks.run(),
        "antivirus": av_checks.run(),
        "assets": asset_checks.run(),
    }
