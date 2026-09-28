"""Command-line interface."""

import argparse
import json
import sys
from dataclasses import asdict

from hdrcheck import __version__
from hdrcheck.checker import Finding, Status, evaluate
from hdrcheck.fetcher import FetchError, fetch_headers
from hdrcheck.rules import Severity

EXIT_OK = 0
EXIT_FINDINGS = 1   # at least one HIGH severity problem
EXIT_ERROR = 2      # could not fetch the URL


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hdrcheck",
        description="Check a URL for common HTTP security headers.",
    )
    parser.add_argument("url", help="URL to check, e.g. https://example.com")
    parser.add_argument("--json", action="store_true", help="output results as JSON")
    parser.add_argument("--timeout", type=float, default=10.0, help="request timeout in seconds")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def print_table(url: str, findings: list[Finding]) -> None:
    print(f"\nSecurity headers for {url}\n")
    print(f"{'HEADER':<28} {'STATUS':<14} {'SEVERITY':<9} DETAIL")
    print("-" * 90)
    for f in findings:
        print(f"{f.header:<28} {f.status.value:<14} {f.severity.value:<9} {f.detail}")
    print()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        headers = fetch_headers(args.url, timeout=args.timeout)
    except FetchError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_ERROR

    findings = evaluate(headers)

    if args.json:
        print(json.dumps([asdict(f) for f in findings], indent=2))
    else:
        print_table(args.url, findings)

    has_high = any(
        f.severity == Severity.HIGH and f.status in (Status.MISSING, Status.MISCONFIGURED)
        for f in findings
    )
    return EXIT_FINDINGS if has_high else EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
