import json
import os
import tempfile
import time
from contextlib import contextmanager
from urllib.parse import urlparse

from stacks.constants import COOKIE_CACHE_DIR, KNOWN_MD5
from stacks.utils.domainutils import get_working_domain, try_domains_until_success

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None


def _actual_domain(domain_or_url):
    if '://' in domain_or_url:
        return urlparse(domain_or_url).netloc.split(':')[0]
    return domain_or_url.split(':')[0]


def _normalise_expiry(value):
    if value in (None, '', -1, '-1'):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def _normalise_cookie(cookie, default_domain):
    if not isinstance(cookie, dict) or not cookie.get('name'):
        return None

    normalised = {
        'name': str(cookie['name']),
        'value': str(cookie.get('value', '')),
        'domain': cookie.get('domain') or default_domain,
        'path': cookie.get('path') or '/',
    }

    expires = _normalise_expiry(cookie.get('expires', cookie.get('expiry')))
    if expires is not None:
        normalised['expires'] = expires

    for key in ('secure', 'httpOnly', 'sameSite', 'session', 'hostOnly'):
        if key in cookie and cookie[key] is not None:
            normalised[key] = cookie[key]

    return normalised


def _normalise_cookies(cookies, default_domain):
    if isinstance(cookies, dict):
        if 'name' in cookies:
            raw_cookies = [cookies]
        else:
            raw_cookies = [
                {'name': name, 'value': value}
                for name, value in cookies.items()
            ]
    elif isinstance(cookies, (list, tuple)):
        raw_cookies = cookies
    else:
        raw_cookies = []

    result = []
    for cookie in raw_cookies:
        normalised = _normalise_cookie(cookie, default_domain)
        if normalised:
            result.append(normalised)
    return result


def _cookie_key(cookie):
    return (
        cookie['name'],
        cookie.get('domain', '').lstrip('.').lower(),
        cookie.get('path') or '/',
    )


def _cookie_is_expired(cookie):
    expires = _normalise_expiry(cookie.get('expires'))
    return expires is not None and expires <= int(time.time())


def _read_cookie_cache(cookie_file, default_domain):
    with open(cookie_file, 'r') as f:
        data = json.load(f)

    if isinstance(data, dict) and 'cookies' in data:
        cookies = _normalise_cookies(data.get('cookies', []), default_domain)
        return cookies, data.get('user_agent'), data.get('timestamp', 0), True

    cookies = _normalise_cookies(data, default_domain)
    return cookies, None, 0, False


@contextmanager
def _cookie_cache_lock(cookie_file):
    """Serialize cache read/merge/write cycles when POSIX file locks exist."""
    lock_file = open(cookie_file.with_suffix(cookie_file.suffix + '.lock'), 'a+')
    try:
        if fcntl is not None:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
        lock_file.close()


def _atomic_write_json(path, payload):
    """Replace a cache file atomically so readers never observe partial JSON."""
    file_descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f'.{path.name}.',
        suffix='.tmp',
        text=True,
    )
    try:
        with os.fdopen(file_descriptor, 'w') as temporary_file:
            json.dump(payload, temporary_file, indent=2)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
        os.replace(temporary_name, path)
    except Exception:
        try:
            os.close(file_descriptor)
        except OSError:
            pass
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def _apply_cookie_to_session(d, cookie):
    domain = cookie.get('domain') or ''
    path = cookie.get('path') or '/'
    expires = _normalise_expiry(cookie.get('expires'))
    rest = {}
    if isinstance(cookie.get('httpOnly'), bool):
        rest['HttpOnly'] = cookie['httpOnly']
    if cookie.get('sameSite') in ('Strict', 'Lax', 'None'):
        rest['SameSite'] = cookie['sameSite']

    d.session.cookies.set(
        cookie['name'],
        cookie.get('value', ''),
        domain=domain,
        path=path,
        secure=bool(cookie.get('secure', False)),
        expires=expires,
        rest=rest,
    )

def _get_cookie_filename(domain_or_url):
    """Convert domain/URL to a safe cookie filename.

    Examples:
        annas-archive.gl -> cookie-annas-archive-gl.json
        https://libgen.li/some/path -> cookie-libgen-li.json
        library.lol -> cookie-library-lol.json
    """
    domain = _actual_domain(domain_or_url)

    # Convert to safe filename: dots to dashes
    safe_name = domain.replace('.', '-')

    return f"cookie-{safe_name}.json"

def _load_cached_cookies(d, domain=None):
    """Load cookies from domain-specific cache file.

    Args:
        d: Downloader instance
        domain: Domain or URL to load cookies for (default: current working domain)

    Supports three formats:
    1. Metadata format: {"timestamp": 123456, "cookies": [{"name": "...", ...}], "user_agent": "..."}
    2. Legacy JSON format: {"timestamp": 123456, "cookies": {"name": "value", ...}, "user_agent": "..."}
    3. Simple dict format: {"name": "value", ...}

    If timestamp is present and cookies are >24h old, they're still loaded but marked as potentially stale.
    """
    if domain is None:
        domain = get_working_domain()

    cookie_filename = _get_cookie_filename(domain)
    cookie_file = COOKIE_CACHE_DIR / cookie_filename

    if cookie_file.exists():
        try:
            actual_domain = _actual_domain(domain)
            cookies, user_agent, cached_time, full_format = _read_cookie_cache(
                cookie_file,
                actual_domain,
            )
            active_cookies = [cookie for cookie in cookies if not _cookie_is_expired(cookie)]

            if full_format:
                if time.time() - cached_time < 86400:
                    d.logger.info(f"Loaded {len(active_cookies)} fresh cached cookies for {domain}")
                else:
                    d.logger.info(f"Loaded {len(active_cookies)} cached cookies for {domain} (potentially stale)")
            else:
                d.logger.info(f"Loaded {len(active_cookies)} manually cached cookies for {domain}")

            for cookie in active_cookies:
                _apply_cookie_to_session(d, cookie)

            if user_agent:
                d.session.headers.update({'User-Agent': user_agent})
                d.logger.debug(f"Loaded cached User-Agent for {domain}")

            return True
        except Exception as e:
            d.logger.debug(f"Failed to load cached cookies for {domain}: {e}")
    return False

def _save_cookies_to_cache(d, cookies_dict, domain=None, user_agent=None, replace=False):
    """Save cookies to domain-specific cache file.

    Args:
        d: Downloader instance
        cookies_dict: Dictionary of cookie name-value pairs
        domain: Domain or URL these cookies are for (default: current working domain)
        user_agent: User-Agent that produced the cookies, if known
        replace: Treat cookies as an authoritative browser jar instead of a delta
    """
    if domain is None:
        domain = get_working_domain()
    try:
        actual_domain = _actual_domain(domain)
        cookie_filename = _get_cookie_filename(domain)
        cookie_file = COOKIE_CACHE_DIR / cookie_filename

        COOKIE_CACHE_DIR.mkdir(parents=True, exist_ok=True)

        with _cookie_cache_lock(cookie_file):
            existing_cookies = []
            existing_user_agent = None
            if cookie_file.exists():
                try:
                    existing_cookies, existing_user_agent, _, _ = _read_cookie_cache(
                        cookie_file,
                        actual_domain,
                    )
                except Exception as e:
                    d.logger.debug(f"Failed to merge existing cookie cache for {domain}: {e}")

            merged = {} if replace else {
                _cookie_key(cookie): cookie
                for cookie in existing_cookies
                if not _cookie_is_expired(cookie)
            }
            for cookie in _normalise_cookies(cookies_dict, actual_domain):
                key = _cookie_key(cookie)
                if _cookie_is_expired(cookie):
                    merged.pop(key, None)
                    continue
                # A value-only update must not discard existing expiry/security data.
                combined = dict(merged.get(key, {}))
                combined.update(cookie)
                merged[key] = combined

            cookies = list(merged.values())
            cached_user_agent = user_agent or existing_user_agent
            payload = {
                'timestamp': time.time(),
                'cookies': cookies
            }
            if cached_user_agent:
                payload['user_agent'] = cached_user_agent
            _atomic_write_json(cookie_file, payload)

        d.logger.info(f"Cached {len(cookies)} cookies for {domain} -> {cookie_filename}")
    except Exception as e:
        d.logger.debug(f"Failed to cache cookies for {domain}: {e}")

def _prewarm_cookies_single_domain(d, domain):
    """Pre-warm cookies using FlareSolverr for a specific domain."""
    if not d.flaresolverr_url:
        return False

    d.logger.debug(f"Pre-warming cookies for {domain} with FlareSolverr...")

    # Use a slow_download URL to trigger DDG challenge and get all cookies
    # This ensures we get __ddg* cookies needed for slow_download access
    test_url = f"https://{domain}/slow_download/{KNOWN_MD5}/0/0"

    success, cookies, _ = d.solve_with_flaresolverr(test_url)

    if success and cookies:
        # solve_with_flaresolverr already cached the full browser cookie records.
        d.logger.info(f"Cookies pre-warmed and cached for {domain}")
        return True

    raise Exception(f"Failed to pre-warm cookies for {domain}")


def _prewarm_cookies(d):
    """
    Pre-warm cookies using FlareSolverr with automatic domain rotation.

    Uses a slow_download URL to ensure we get all DDG cookies.
    """
    if not d.flaresolverr_url:
        return False

    d.logger.info("Pre-warming cookies with FlareSolverr...")

    try:
        return try_domains_until_success(_prewarm_cookies_single_domain, d)
    except Exception as e:
        d.logger.warning(f"Failed to pre-warm cookies on all domains: {e}")
        return False
