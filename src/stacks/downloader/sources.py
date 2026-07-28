"""Helpers for selecting which download sources Stacks may use."""

from urllib.parse import urlparse

from stacks.downloader.sites.libgen import is_libgen_landing_url
from stacks.utils.domainutils import get_all_domains


def is_slow_download_mirror(mirror: dict) -> bool:
    """Return True when a mirror points at Anna's Archive slow_download."""
    if not isinstance(mirror, dict) or mirror.get('type') != 'slow_download':
        return False

    try:
        parsed = urlparse(mirror.get('url', ''))
        port = parsed.port
    except (TypeError, ValueError):
        return False

    scheme = parsed.scheme.lower()
    expected_port = 80 if scheme == 'http' else 443
    anna_domains = {
        domain.lower().rstrip('.') for domain in get_all_domains()
    }
    return (
        scheme in ('http', 'https')
        and (parsed.hostname or '').lower().rstrip('.') in anna_domains
        and parsed.username is None
        and parsed.password is None
        and port in (None, expected_port)
        and parsed.path.startswith('/slow_download/')
    )


def is_supported_external_mirror(mirror: dict) -> bool:
    """Return whether Stacks has a strict adapter for this external source."""
    return (
        isinstance(mirror, dict)
        and mirror.get('type') == 'external_mirror'
        and is_libgen_landing_url(mirror.get('url', ''))
    )


def filter_mirrors_for_policy(mirrors: list, allow_external_mirrors: bool = False) -> list:
    """Filter mirrors according to the configured external mirror policy."""
    slow_downloads = [
        mirror for mirror in mirrors if is_slow_download_mirror(mirror)
    ]
    if not allow_external_mirrors:
        return slow_downloads

    # Ignore arbitrary external links, advertisements, and torrents. Sources
    # can be added here only after they have a strict, same-origin adapter.
    libgen = [
        mirror
        for mirror in mirrors
        if is_supported_external_mirror(mirror)
    ]
    return slow_downloads + libgen
