"""Strict parser for Library Genesis download landing pages."""

import re
from urllib.parse import parse_qs, urljoin, urlparse

from bs4 import BeautifulSoup


LIBGEN_HOSTS = frozenset({
    "libgen.li",
    "www.libgen.li",
})
MD5_PATTERN = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)


def is_libgen_domain(url):
    """Return whether a URL belongs to an explicitly supported LibGen host."""
    try:
        parsed = urlparse(url)
        port = parsed.port
    except (TypeError, ValueError):
        return False

    scheme = parsed.scheme.lower()
    expected_port = 80 if scheme == "http" else 443
    return (
        scheme in ("http", "https")
        and (parsed.hostname or "").lower().rstrip(".") in LIBGEN_HOSTS
        and parsed.username is None
        and parsed.password is None
        and port in (None, expected_port)
    )


def is_libgen_landing_url(url):
    """Return whether URL is a supported LibGen ads.php landing page."""
    if not is_libgen_domain(url):
        return False

    parsed = urlparse(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    md5_values = query.get("md5", [])
    return (
        parsed.path.lower() == "/ads.php"
        and len(md5_values) == 1
        and MD5_PATTERN.fullmatch(md5_values[0].strip()) is not None
    )


def _validated_get_url(raw_url, mirror_url, expected_md5):
    resolved_url = urljoin(mirror_url, raw_url)
    parsed = urlparse(resolved_url)

    if not is_libgen_domain(resolved_url):
        return None
    if parsed.path.lower() != "/get.php":
        return None

    query = parse_qs(parsed.query, keep_blank_values=True)
    md5_values = query.get("md5", [])
    key_values = query.get("key", [])
    if len(md5_values) != 1 or len(key_values) != 1:
        return None

    candidate_md5 = md5_values[0].strip().lower()
    key = key_values[0].strip()
    expected_md5 = (expected_md5 or "").strip().lower()

    if not MD5_PATTERN.fullmatch(expected_md5):
        return None
    if not MD5_PATTERN.fullmatch(candidate_md5) or not key:
        return None
    if candidate_md5 != expected_md5:
        return None

    return resolved_url


def parse_libgen_download_link(d, html_content, mirror_url, expected_md5=None):
    """Extract the keyed GET URL without following or executing page ads."""
    if not is_libgen_landing_url(mirror_url):
        return None

    expected_md5 = (expected_md5 or "").strip().lower()
    landing_query = parse_qs(
        urlparse(mirror_url).query,
        keep_blank_values=True,
    )
    landing_md5 = landing_query["md5"][0].strip().lower()
    if (
        not MD5_PATTERN.fullmatch(expected_md5)
        or landing_md5 != expected_md5
    ):
        return None

    soup = BeautifulSoup(html_content, "html.parser")
    candidates = []

    # The saved LibGen layout places the real GET link in table#main.
    candidates.extend(soup.select("table#main a[href]"))

    # Retain a conservative fallback for minor layout changes.
    candidates.extend(
        link
        for link in soup.find_all("a", href=True)
        if link.get_text(" ", strip=True).upper() == "GET"
    )

    seen_hrefs = set()
    for link in candidates:
        href = link.get("href", "")
        if href in seen_hrefs:
            continue
        seen_hrefs.add(href)

        download_url = _validated_get_url(href, mirror_url, expected_md5)
        if download_url:
            d.logger.debug("Found validated LibGen GET link")
            return download_url

    d.logger.warning("Could not find a valid LibGen GET link in HTML")
    return None
