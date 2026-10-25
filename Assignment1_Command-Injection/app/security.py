"""
WEB404 Assignment 1 — Security Module
=======================================
- validate_hostname()   — allowlist-based input validation
- safe_lookup()         — SECURE: uses Python socket library (no shell)
- safe_ping()           — SECURE: subprocess with shell=False + argument list
- vulnerable_lookup()   — UNSAFE: shell=True with string concatenation (demo only)
"""

import logging
import re
import socket
import subprocess

logger = logging.getLogger(__name__)

# Allowlist: hostname must be alphanumeric with dots/hyphens, 1–253 chars,
# each label 1–63 chars, no leading/trailing hyphens per label.
HOSTNAME_REGEX = re.compile(
    r"^(?!-)"                         # no leading hyphen
    r"[a-zA-Z0-9]"                    # starts with alnum
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"  # middle of first label
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"  # subsequent labels
    r"$"
)

MAX_HOSTNAME_LENGTH = 253


def validate_hostname(hostname: str) -> tuple[bool, str]:
    """Validate a hostname against a strict allowlist.

    Returns (is_valid, error_message).
    """
    if not hostname or not hostname.strip():
        return False, "Hostname cannot be empty."

    hostname = hostname.strip()

    if len(hostname) > MAX_HOSTNAME_LENGTH:
        return False, f"Hostname exceeds {MAX_HOSTNAME_LENGTH} characters."

    if not HOSTNAME_REGEX.match(hostname):
        return False, (
            "Invalid hostname. Only letters, digits, dots, "
            "and hyphens are allowed."
        )

    return True, ""


def safe_lookup(hostname: str) -> dict:
    """SECURE implementation — uses Python's socket library.

    No subprocess, no shell, no injection surface.
    This is the PREFERRED approach: use a library instead of
    shelling out to an OS command.
    """
    valid, error = validate_hostname(hostname)
    if not valid:
        logger.warning("Rejected hostname: %s — %s", hostname, error)
        return {"success": False, "error": error}

    try:
        ip = socket.gethostbyname(hostname)
        logger.info("Resolved %s → %s", hostname, ip)
        return {"success": True, "hostname": hostname, "ip": ip}
    except socket.gaierror:
        return {"success": False, "error": f"Could not resolve '{hostname}'."}
    except socket.timeout:
        return {"success": False, "error": "DNS lookup timed out."}
    except Exception:
        logger.exception("Unexpected error during DNS lookup")
        return {"success": False, "error": "An unexpected error occurred."}


def safe_ping(hostname: str, count: int = 1) -> dict:
    """SECURE implementation — subprocess with shell=False.

    When a subprocess IS necessary, this shows the safe pattern:
    1. Validate input first.
    2. Use an argument LIST (never a string).
    3. Set shell=False (the default, but explicit here for clarity).
    4. Apply a timeout.

    WHY INPUT VALIDATION ALONE IS NOT ENOUGH:
    Even with validation, using shell=True would still be dangerous
    because shell metacharacters not covered by a regex could slip
    through.  shell=False removes the shell interpreter entirely,
    so metacharacters like ; | & $ ` have no special meaning.
    """
    valid, error = validate_hostname(hostname)
    if not valid:
        return {"success": False, "error": error}

    try:
        result = subprocess.run(
            ["ping", "-c", str(count), hostname],  # argument LIST
            capture_output=True,
            text=True,
            timeout=10,          # prevent hanging
            shell=False,         # explicit — no shell interpreter
        )
        if result.returncode == 0:
            return {
                "success": True,
                "hostname": hostname,
                "output": result.stdout[:500],  # limit output size
            }
        return {
            "success": False,
            "error": f"Ping to '{hostname}' failed.",
        }
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Ping timed out."}
    except FileNotFoundError:
        return {"success": False, "error": "Ping command not available."}


# ===================================================================
# VULNERABLE — educational demonstration ONLY
# ===================================================================

def vulnerable_lookup(hostname: str) -> dict:
    """VULNERABLE: passes user input directly to a shell command.

    WARNING: This function exists ONLY for controlled testing.
    It is NOT exposed as a web route.

    The danger: with shell=True, the hostname string is interpreted
    by /bin/sh.  An attacker can append shell metacharacters:
        google.com; cat /etc/passwd
        google.com && whoami
        google.com | ls
    and the shell will execute the injected command.
    """
    try:
        result = subprocess.run(
            f"nslookup {hostname}",   # string, not list
            capture_output=True,
            text=True,
            timeout=10,
            shell=True,               # ← DANGEROUS
        )
        return {"success": True, "output": result.stdout[:500]}
    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Timed out."}
