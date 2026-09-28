"""Evaluate response headers against the rules."""

from dataclasses import dataclass
from enum import Enum

from hdrcheck.rules import INFO_LEAK_HEADERS, RULES, Rule, Severity


class Status(str, Enum):
    OK = "ok"                        # header present and looks fine
    MISSING = "missing"              # header not present
    MISCONFIGURED = "misconfigured"  # header present but with a weak value
    LEAK = "leak"                    # header reveals server information


@dataclass
class Finding:
    header: str
    status: Status
    severity: Severity
    detail: str


def evaluate(headers: dict[str, str]) -> list[Finding]:
    """Return one Finding per rule, plus one per information-leaking header.

    Steps:
    1. Header names are case-insensitive: normalise them first.
    2. For each rule in RULES:
       - missing  -> Finding(status=MISSING, severity=rule.severity, detail=rule.why)
       - present  -> call check_value(rule, value) to decide OK or MISCONFIGURED
    3. For each header in INFO_LEAK_HEADERS that is present:
       -> Finding(status=LEAK, severity=Severity.INFO, detail=<its value>)
    """
    # 1. Normalise header names to lowercase so lookups are case-insensitive.
    normalised = {name.strip().lower(): value for name, value in headers.items()}

    findings: list[Finding] = []

    # 2. One Finding per rule: MISSING if absent, otherwise let check_value decide.
    for rule in RULES:
        value = normalised.get(rule.header.lower())
        if value is None:
            findings.append(
                Finding(
                    header=rule.header,
                    status=Status.MISSING,
                    severity=rule.severity,
                    detail=rule.why,
                )
            )
        else:
            findings.append(check_value(rule, value))

    # 3. One Finding per information-leaking header that is present.
    for header in INFO_LEAK_HEADERS:
        value = normalised.get(header.lower())
        if value is not None:
            findings.append(
                Finding(
                    header=header,
                    status=Status.LEAK,
                    severity=Severity.INFO,
                    detail=value,
                )
            )

    return findings


def check_value(rule: Rule, value: str) -> Finding:
    name = rule.header.lower()
    status = Status.OK
    detail = value

    if name == "strict-transport-security":
        # HSTS: max-age must be at least 15552000 seconds (180 days).
        max_age = None
        for directive in value.split(";"):
            key, _, val = directive.strip().partition("=")
            if key.strip().lower() == "max-age":
                val = val.strip().strip('"')
                try:
                    max_age = int(val)
                except ValueError:
                    max_age = None
        if max_age is None:
            status = Status.MISCONFIGURED
            detail = "max-age is missing or invalid."
        elif max_age < 15552000:
            status = Status.MISCONFIGURED
            detail = f"max-age={max_age} is below 15552000 (180 days)."

    elif name == "x-content-type-options":
        # Only valid value is "nosniff".
        if value.strip().lower() != "nosniff":
            status = Status.MISCONFIGURED
            detail = f'expected "nosniff", got "{value}".'

    # Any other header: present is treated as OK for now.
    return Finding(header=rule.header, status=status, severity=rule.severity, detail=detail)
