import platform
import socket
from datetime import datetime, timezone

try:
    import psutil
except Exception:
    psutil = None

def get_hostname() -> str:
    return socket.gethostname()

def get_os_type() -> str:
    return platform.system()

def get_os_version() -> str:
    return platform.platform()

def get_timestamp_utc() -> str:
    return datetime.now(timezone.utc).isoformat()

def get_primary_ip() -> str:
    if psutil:
        for _, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if getattr(a, "family", None) == socket.AF_INET:
                    ip = a.address
                    if ip and not ip.startswith("127."):
                        return ip
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "unknown"
    finally:
        s.close()
