import logging
import os
from logging.handlers import RotatingFileHandler


def get_logger(name: str = "agent") -> logging.Logger:
    logger = logging.getLogger(name)

    # Prevent duplicate handlers if imported multiple times
    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)

    # logs folder inside agent/
    base_dir = os.path.dirname(os.path.dirname(__file__))  # .../agent
    logs_dir = os.path.join(base_dir, "logs")
    os.makedirs(logs_dir, exist_ok=True)

    log_path = os.path.join(logs_dir, "agent.log")

    handler = RotatingFileHandler(
        log_path,
        maxBytes=1_000_000,   # 1MB
        backupCount=3,
        encoding="utf-8"
    )

    formatter = logging.Formatter("%(asctime)sZ | %(levelname)s | %(name)s | %(message)s")
    handler.setFormatter(formatter)

    logger.addHandler(handler)
    logger.propagate = False
    return logger
