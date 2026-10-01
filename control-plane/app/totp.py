"""Time-based one-time passwords (RFC 6238) — compatible with Google Authenticator and similar apps."""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

PERIOD = 30  # seconds a code is valid
DIGITS = 6
ISSUER = "MCP Platform"


def generate_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def current_step(now: float | None = None) -> int:
    return int((time.time() if now is None else now) // PERIOD)


def code_at(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10 ** DIGITS).zfill(DIGITS)


def verify(secret: str, code: str, last_step: int = 0, window: int = 1, now: float | None = None) -> int | None:
    """
    Returns the time step the code belongs to, or None when it is wrong.
    Steps <= last_step are refused, so a code cannot be used twice.
    `window` tolerates clock drift of that many periods in both directions.
    """
    if not secret or not code.isdigit() or len(code) != DIGITS:
        return None
    step_now = current_step(now)
    for step in range(step_now - window, step_now + window + 1):
        if step > last_step and hmac.compare_digest(code_at(secret, step), code):
            return step
    return None


def provisioning_uri(secret: str, username: str) -> str:
    """otpauth:// URI encoded in the QR code scanned by the authenticator app."""
    label = quote(f"{ISSUER}:{username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER)}&digits={DIGITS}&period={PERIOD}"
