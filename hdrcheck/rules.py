"""Definition of the security header rules.

Rules are plain data. Adding a new check should mean adding an entry
to RULES, not writing a new if-statement somewhere else.
"""

from dataclasses import dataclass
from enum import Enum


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass(frozen=True)
class Rule:
    header: str          # header name, as it appears in the HTTP response
    severity: Severity   # how serious it is if the header is missing
    why: str             # one-line explanation shown to the user


RULES: list[Rule] = [
    Rule(
        header="Strict-Transport-Security",
        severity=Severity.HIGH,
        why="Forces browsers to use HTTPS, protecting against downgrade attacks.",
    ),
    Rule(
        header="Content-Security-Policy",
        severity=Severity.HIGH,
        why="Restricts where scripts and resources can load from; mitigates XSS.",
    ),
    Rule(
        header="X-Content-Type-Options",
        severity=Severity.MEDIUM,
        why="Stops browsers from MIME-sniffing responses into a different type.",
    ),
    Rule(
        header="X-Frame-Options",
        severity=Severity.MEDIUM,
        why="Prevents the page from being framed by other sites (clickjacking).",
    ),
    Rule(
        header="Referrer-Policy",
        severity=Severity.LOW,
        why="Controls how much URL information is sent to other sites.",
    ),
    Rule(
        header="Permissions-Policy",
        severity=Severity.LOW,
        why="Limits which browser features (camera, geolocation...) the page can use.",
    ),
]

# Headers that should NOT be present because they leak server details.
INFO_LEAK_HEADERS: list[str] = ["Server", "X-Powered-By"]
