# security-headers-checker

A small command-line tool that checks a URL for common HTTP security headers and explains what is missing or misconfigured.

> Status: v0.1, built as a learning project.

## Overview

Many websites ship without basic HTTP security headers, and the gaps are easy to miss because the site still works. This tool sends a single request to a URL, reads the response headers and reports which recommended headers are missing, which look misconfigured, and which reveal information about the server.

I built it to learn how these headers work in practice and to practise structuring a small Python project with a CLI and tests.

## Features

- Checks for `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` and `Permissions-Policy`
- Validates some values:
  - `Strict-Transport-Security`: `max-age` must be a valid number of at least 15552000 seconds (180 days)
  - `X-Content-Type-Options`: must be `nosniff`
- Flags headers that leak server details (`Server`, `X-Powered-By`)
- Human-readable table or `--json` output
- Non-zero exit code when high-severity headers are missing or misconfigured, so it can be used in CI

## Installation

Requires Python 3.10 or later.

```bash
git clone https://github.com/Goco36/security-headers-checker.git
cd security-headers-checker
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

```bash
python -m hdrcheck https://example.com
python -m hdrcheck https://example.com --json
python -m hdrcheck https://example.com --timeout 5
```

Example output against a local Python development server:

```
Security headers for http://localhost:8000

HEADER                       STATUS         SEVERITY  DETAIL
------------------------------------------------------------------------------------------
Strict-Transport-Security    missing        high      Forces browsers to use HTTPS, protecting against downgrade attacks.
Content-Security-Policy      missing        high      Restricts where scripts and resources can load from; mitigates XSS.
X-Content-Type-Options       missing        medium    Stops browsers from MIME-sniffing responses into a different type.
X-Frame-Options              missing        medium    Prevents the page from being framed by other sites (clickjacking).
Referrer-Policy              missing        low       Controls how much URL information is sent to other sites.
Permissions-Policy           missing        low       Limits which browser features (camera, geolocation...) the page can use.
Server                       leak           info      SimpleHTTP/0.6 Python/3.11.15
```

To try it locally, run `python -m http.server 8000` in one terminal and `python -m hdrcheck http://localhost:8000` in another.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | No high-severity issues |
| 1 | At least one high-severity header missing or misconfigured |
| 2 | The URL could not be fetched |

## Running the tests

```bash
python -m pytest -v
```

The tests use fixed header dictionaries, so they do not need network access.

## Project Structure

```
hdrcheck/
  rules.py     # which headers are checked, defined as data
  fetcher.py   # sends one GET request and returns the final response headers
  checker.py   # evaluates headers against the rules
  cli.py       # command-line interface, output and exit codes
tests/
  test_checker.py
```

Rules are plain data in `rules.py`, so adding a new header check does not require changing the evaluation loop.

## Limitations

- Analyses the response of a single URL, not the whole site.
- Only `Strict-Transport-Security` and `X-Content-Type-Options` have their values validated; other headers are only checked for presence.
- Does not assess the quality of a `Content-Security-Policy`.
- Known false positive: a site that prevents framing with `frame-ancestors` in its CSP, instead of `X-Frame-Options`, is still reported as missing `X-Frame-Options`.
- A duplicated `Strict-Transport-Security` header is reported as "max-age is missing or invalid", which is correct as a status but a misleading message.
- Does not execute JavaScript or follow authenticated flows.
- A clean result does not mean a site is secure.

## Responsible use

The tool sends a single GET request, like opening the page in a browser. Only run it against sites you own or have permission to test, and do not run it in loops against third-party sites.

## Roadmap

- [ ] Recognise `frame-ancestors` in CSP as an alternative to `X-Frame-Options`
- [ ] Detect duplicated headers and report them clearly
- [ ] Cookie flag checks (`Secure`, `HttpOnly`, `SameSite`)
- [ ] Basic CSP weakness detection (`unsafe-inline`, wildcard sources)
- [ ] Check several URLs from a file
- [ ] GitHub Actions workflow running the tests

## What I learned

- What each of these security headers protects against, and that a header being present is not the same as it being configured correctly.
- HTTP header names are case-insensitive, so they have to be normalised before comparing.
- Server input cannot be trusted: a malformed `max-age` value crashed an early version of the tool, which I fixed and covered with a regression test.
- Why a network request always needs a timeout, and how redirects affect which response is analysed.
- Wrapping library-specific errors in a custom exception keeps the rest of the program independent of the HTTP library.

## License

MIT - see [LICENSE](LICENSE).

## Author

Guillermo Gómez Conejero - Computer Engineering student