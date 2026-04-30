import re
import urllib.parse


ALLOWED_TARGET_PATTERN = re.compile(
    r'^(https?://)?'
    r'('
    r'(\d{1,3}\.){3}\d{1,3}'
    r'|'
    r'([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    r'|'
    r'localhost'
    r')'
    r'(:\d{1,5})?'
    r'(/[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]*)?$'
)

DANGEROUS_CHARS = re.compile(r'[;&|`$<>\\\'"{}]')


def sanitize_target(target: str) -> str:
    target = target.strip()
    if len(target) > 500:
        raise ValueError("Target too long")
    if DANGEROUS_CHARS.search(target):
        raise ValueError("Target contains invalid characters")
    if not ALLOWED_TARGET_PATTERN.match(target):
        raise ValueError("Invalid target format. Use IP, domain, or URL.")
    return target


def sanitize_options(options: str) -> str:
    options = options.strip()
    # Bumped from 200 -> 1500 so long cookie values (e.g. PortSwigger
    # `session=...` tokens) can be passed through alongside other flags.
    if len(options) > 1500:
        raise ValueError("Options string too long")
    if DANGEROUS_CHARS.search(options):
        raise ValueError("Options contain invalid characters")
    return options


def sanitize_cookie(cookie: str) -> str:
    """
    Sanitize a HTTP cookie string supplied by the user. Cookies are
    normally `name=value; name2=value2` — alphanumerics plus a small
    set of separators. We reject shell metacharacters but allow the
    spaces and semicolons that real cookie strings need.
    """
    cookie = (cookie or "").strip()
    if not cookie:
        return ""
    if len(cookie) > 4000:
        raise ValueError("Cookie string too long")
    # Block shell metacharacters but keep `=`, `;`, `,`, spaces, and
    # the URL-safe characters typical session tokens use.
    if re.search(r'[`$<>\\\'"{}|&]', cookie):
        raise ValueError("Cookie contains invalid characters")
    return cookie


def extract_hostname(target: str) -> str:
    target = target.strip()
    parsed = urllib.parse.urlparse(target if "://" in target else f"http://{target}")
    return parsed.hostname or target
