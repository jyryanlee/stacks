"""Helpers for recognising unresolved browser-protection pages."""


PROTECTION_STATUS_CODES = frozenset({403, 429, 503})
HTML_CONTENT_TYPES = ("text/html", "application/xhtml+xml")
PROTECTION_MARKERS = (
    "ddos-guard",
    "check.ddos-guard.net",
    "__ddg",
    "just a moment",
    "cf-chl",
    "cf-browser-verification",
    "challenge-platform",
    "checking your browser",
)


class _ReplayPrefix:
    """Replay bytes inspected from a streamed response before its remaining raw body."""

    def __init__(self, prefix, raw):
        self._prefix = memoryview(prefix)
        self._raw = raw

    def _take_prefix(self, amount=None):
        if not self._prefix:
            return b""
        if amount is None or amount < 0:
            amount = len(self._prefix)
        amount = min(amount, len(self._prefix))
        chunk = self._prefix[:amount].tobytes()
        self._prefix = self._prefix[amount:]
        return chunk

    def read(self, amount=None, decode_content=None, **kwargs):
        prefix = self._take_prefix(amount)
        if amount is not None and amount >= 0:
            remaining = amount - len(prefix)
            if remaining <= 0:
                return prefix
        else:
            remaining = amount

        try:
            suffix = self._raw.read(
                remaining,
                decode_content=decode_content,
                **kwargs,
            )
        except TypeError:
            suffix = self._raw.read(remaining)
        return prefix + (suffix or b"")

    def stream(self, amount=65536, decode_content=None):
        while self._prefix:
            yield self._take_prefix(amount)

        if hasattr(self._raw, "stream"):
            yield from self._raw.stream(amount, decode_content=decode_content)
            return

        while True:
            try:
                chunk = self._raw.read(amount, decode_content=decode_content)
            except TypeError:
                chunk = self._raw.read(amount)
            if not chunk:
                break
            yield chunk

    def __getattr__(self, name):
        return getattr(self._raw, name)


def is_protection_status(status_code):
    """Return whether an HTTP status commonly represents a challenge page."""
    try:
        return int(status_code) in PROTECTION_STATUS_CODES
    except (TypeError, ValueError):
        return False


def html_looks_like_protection(content):
    """Inspect a bounded HTML prefix for known Cloudflare/DDoS-Guard markers."""
    if content is None:
        return False
    if isinstance(content, bytes):
        content = content.decode("utf-8", errors="ignore")
    elif not isinstance(content, str):
        content = str(content)

    text = content[:4000].lower()
    return any(marker in text for marker in PROTECTION_MARKERS)


def response_looks_like_protection(response):
    """Recognise status-code and HTTP-200 HTML challenge responses."""
    if is_protection_status(getattr(response, "status_code", None)):
        return True

    content_type = response.headers.get("Content-Type", "").lower()
    if not any(kind in content_type for kind in HTML_CONTENT_TYPES):
        return False

    return html_looks_like_protection(response.text)


def streamed_response_looks_like_protection(response, inspect_bytes=4000):
    """Inspect a streamed HTML prefix without consuming it for the downloader."""
    if is_protection_status(getattr(response, "status_code", None)):
        return True

    content_type = response.headers.get("Content-Type", "").lower()
    if not any(kind in content_type for kind in HTML_CONTENT_TYPES):
        return False

    cached_content = getattr(response, "_content", False)
    if cached_content is not False and cached_content is not None:
        return html_looks_like_protection(cached_content[:inspect_bytes])

    raw = getattr(response, "raw", None)
    if raw is None:
        return html_looks_like_protection(response.text)

    try:
        prefix = raw.read(inspect_bytes, decode_content=True)
    except TypeError:
        prefix = raw.read(inspect_bytes)
    prefix = prefix or b""
    response.raw = _ReplayPrefix(prefix, raw)
    return html_looks_like_protection(prefix)
