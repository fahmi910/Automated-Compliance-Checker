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
    """
    Prefer the lab Host-Only network IP (e.g. 192.168.56.x).
    Fallback to other non-loopback IPv4 addresses.
    Final fallback uses UDP socket trick.
    """
    preferred_prefixes = ("192.168.56.",)  # your host-only subnet
    avoid_prefixes = ("127.", "169.254.")  # loopback, APIPA

    if psutil:
        ipv4_candidates = []
        preferred_hits = []

        # Collect all IPv4 addresses from all interfaces
        for ifname, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if getattr(a, "family", None) == socket.AF_INET:
                    ip = getattr(a, "address", None)
                    if not ip:
                        continue

                    # Skip loopback/APIPA
                    if ip.startswith(avoid_prefixes):
                        continue

                    # Preferred: host-only subnet
                    if ip.startswith(preferred_prefixes):
                        preferred_hits.append((ifname, ip))
                    else:
                        ipv4_candidates.append((ifname, ip))

        # Return preferred host-only IP first
        if preferred_hits:
            # If multiple, return first one
            return preferred_hits[0][1]

        # Otherwise return first non-loopback IPv4
        if ipv4_candidates:
            return ipv4_candidates[0][1]

    # Fallback: UDP socket trick (often returns NAT IP)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        if ip and not ip.startswith(avoid_prefixes):
            return ip
        return "unknown"
    except Exception:
        return "unknown"
    finally:
        s.close()

