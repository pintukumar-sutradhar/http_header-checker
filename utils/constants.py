"""
utils/constants.py
===================
Application-wide constants: theme colors, version info, user-agent pool,
and shared reference data (OWASP / Mozilla links, weak cipher/protocol
lists, etc.).
"""

APP_NAME = "HTTP Header Checker"
APP_VERSION = "1.0.0"
ORG_NAME = "HTTP Header Checker Security Labs"

# --------------------------------------------------------------------------- #
# Theme - dark cybersecurity palette
# --------------------------------------------------------------------------- #
COLOR_BACKGROUND = "#0B0F14"
COLOR_PANEL = "#111827"
COLOR_CARD = "#1E293B"
COLOR_BORDER = "#243244"
COLOR_TEXT = "#E5E7EB"
COLOR_TEXT_MUTED = "#94A3B8"
COLOR_GREEN = "#22C55E"
COLOR_ORANGE = "#F59E0B"
COLOR_RED = "#EF4444"
COLOR_BLUE = "#3B82F6"
COLOR_PURPLE = "#8B5CF6"

# --------------------------------------------------------------------------- #
# Networking
# --------------------------------------------------------------------------- #
DEFAULT_TIMEOUT = 15
DEFAULT_RETRIES = 1

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) "
    "Version/17.4 Mobile/15E148 Safari/604.1",
]

DEFAULT_USER_AGENT = f"{APP_NAME}/{APP_VERSION} (+SecurityHeaderScanner)"

# Weak / deprecated TLS protocol versions and cipher name fragments
WEAK_TLS_VERSIONS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
WEAK_CIPHER_KEYWORDS = ("RC4", "DES", "3DES", "MD5", "NULL", "EXPORT", "anon", "IDEA")

OWASP_HEADERS_URL = "https://owasp.org/www-project-secure-headers/"
MOZILLA_OBSERVATORY_URL = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"
