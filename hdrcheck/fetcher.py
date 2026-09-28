"""Fetch the HTTP response headers for a URL."""

from libs import requests


class FetchError(Exception):
    """Raised when the URL cannot be fetched (invalid URL, timeout, TLS error...)."""


def fetch_headers(url: str, timeout: float = 10.0) -> dict[str, str]:
    """Send one GET request to `url` and return the final response headers."""
    if not url.startswith(("http://", "https://")):
        raise FetchError(f"URL must start with http:// or https:// (got {url!r})")

    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        raise FetchError(f"could not fetch {url}: {exc}") from exc

    return dict(response.headers)