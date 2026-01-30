import socket
import re

def validate_target(target: str) -> str:
    # Simple IP regex
    ip_regex = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    try:
        if re.match(ip_regex, target):
            return target 

        # Resolve domain
        return socket.gethostbyname(target)

    except Exception:
        raise ValueError(f"Invalid or unreachable host: {target}")
