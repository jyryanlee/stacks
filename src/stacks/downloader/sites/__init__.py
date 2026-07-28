"""Site-specific scrapers for different mirror sites."""

from .libgen import (
    is_libgen_domain,
    is_libgen_landing_url,
    parse_libgen_download_link,
)
from .zlib import parse_zlib_download_link

__all__ = [
    'is_libgen_domain',
    'is_libgen_landing_url',
    'parse_libgen_download_link',
    'parse_zlib_download_link',
]
