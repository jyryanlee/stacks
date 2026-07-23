from urllib.parse import quote, unquote, urlparse, urlunparse

import requests
from requests import Timeout

from stacks.downloader.cookies import _apply_cookie_to_session, _normalise_cookies
from stacks.downloader.protection import html_looks_like_protection
from stacks.downloader.proxy import isolate_session_from_environment_proxies


def _cookies_for_domain(session, domain):
    cookies = []
    for cookie in session.cookies:
        if cookie.is_expired():
            continue
        cookie_domain = cookie.domain.lstrip('.') if cookie.domain else ''
        if cookie_domain and not (domain == cookie_domain or domain.endswith(f".{cookie_domain}")):
            continue
        result = {
            "name": cookie.name,
            "value": cookie.value,
            "domain": cookie.domain or domain,
            "path": cookie.path or "/",
            "secure": bool(cookie.secure),
        }
        if cookie.expires is not None:
            # Selenium's add_cookie() input uses `expiry`; the cache schema uses
            # `expires` and normalises both spellings when loading.
            result["expiry"] = cookie.expires
        http_only = cookie._rest.get("HttpOnly")
        if isinstance(http_only, bool):
            result["httpOnly"] = http_only
        same_site = cookie._rest.get("SameSite")
        if same_site in ("Strict", "Lax", "None"):
            result["sameSite"] = same_site
        cookies.append(result)
    return cookies


def _clear_cookies_for_domain(session, domain):
    """Remove the target cookies that the browser jar authoritatively replaces."""
    for cookie in list(session.cookies):
        cookie_domain = cookie.domain.lstrip('.') if cookie.domain else ''
        if cookie_domain and not (
            domain == cookie_domain or domain.endswith(f".{cookie_domain}")
        ):
            continue
        session.cookies.clear(cookie.domain, cookie.path, cookie.name)


def _normalised_proxy_payload(session):
    """Build FlareSolverr's proxy object without credentials in its URL."""
    proxy_url = session.proxies.get('https') or session.proxies.get('http')
    if not proxy_url:
        return None

    parsed = urlparse(proxy_url)
    if not parsed.scheme or not parsed.hostname:
        return None

    hostname = parsed.hostname
    if ':' in hostname and not hostname.startswith('['):
        hostname = f'[{hostname}]'
    netloc = f"{hostname}:{parsed.port}" if parsed.port else hostname
    clean_url = urlunparse((parsed.scheme, netloc, parsed.path, '', '', ''))
    proxy = {"url": clean_url}
    if parsed.username is not None:
        proxy["username"] = unquote(parsed.username)
    if parsed.password is not None:
        proxy["password"] = unquote(parsed.password)
    return proxy


def _redact_proxy_secrets(value, proxy):
    text = str(value)
    if proxy:
        for key in ('username', 'password'):
            secret = proxy.get(key)
            if secret:
                text = text.replace(secret, '***')
                text = text.replace(quote(secret, safe=''), '***')
    return text


def _control_session(d):
    session = getattr(d, 'flaresolverr_control_session', None)
    if session is None:
        session = isolate_session_from_environment_proxies(requests.Session())
        d.flaresolverr_control_session = session
    return session


def _valid_solution(d, solution):
    status = solution.get('status')
    try:
        status = int(status)
    except (TypeError, ValueError):
        d.logger.error("FlareSolverr returned no valid target status")
        return False

    if status < 200 or status >= 400:
        d.logger.error(f"FlareSolverr target remained blocked with HTTP {status}")
        return False

    if html_looks_like_protection(solution.get('response')):
        d.logger.error("FlareSolverr returned an unresolved protection page")
        return False

    return True

def solve_with_flaresolverr(d, url):
    """Use FlareSolverr to bypass DDoS-Guard/Cloudflare protection."""
    if not d.flaresolverr_url:
        return False, {}, None

    d.logger.info("Using FlareSolverr to solve protection challenge...")

    try:
        actual_domain = urlparse(url).netloc.split(':')[0]
        payload = {
            "cmd": "request.get",
            "url": url,
            "maxTimeout": d.flaresolverr_timeout,
            "waitInSeconds": 2,
        }
        cookies = _cookies_for_domain(d.session, actual_domain)
        if cookies:
            payload["cookies"] = cookies
        proxy = _normalised_proxy_payload(d.session)
        if proxy:
            payload["proxy"] = proxy

        response = _control_session(d).post(
            f"{d.flaresolverr_url}/v1",
            json=payload,
            timeout=d.flaresolverr_timeout / 1000 + 10
        )
        try:
            data = response.json()
        except ValueError:
            data = {}

        if not response.ok:
            error_msg = data.get('message') or response.text or response.reason
            error_msg = _redact_proxy_secrets(error_msg, proxy)
            d.logger.error(f"FlareSolverr HTTP {response.status_code}: {error_msg}")
            return False, {}, None
        
        if data.get('status') == 'ok':
            solution = data.get('solution', {})
            if not _valid_solution(d, solution):
                return False, {}, None

            cookies_list = _normalise_cookies(solution.get('cookies', []), actual_domain)
            cookies_dict = {cookie['name']: cookie['value'] for cookie in cookies_list}
            html_content = solution.get('response')
            user_agent = solution.get('userAgent')
            
            d.logger.info(f"FlareSolverr: Success - got {len(cookies_dict)} cookies")

            # get_cookies() is the browser's complete jar for the active target.
            # Remove input cookies the browser discarded before applying it.
            _clear_cookies_for_domain(d.session, actual_domain)
            for cookie in cookies_list:
                _apply_cookie_to_session(d, cookie)

            if user_agent:
                d.session.headers.update({'User-Agent': user_agent})
                d.logger.debug("Using FlareSolverr User-Agent for solved cookies")

            # Cache cookies for this domain (for reuse on retry/future downloads)
            d.save_cookies_to_cache(
                cookies_list,
                domain=url,
                user_agent=user_agent,
                replace=True,
            )

            return True, cookies_dict, html_content
        else:
            error_msg = _redact_proxy_secrets(data.get('message', 'Unknown error'), proxy)
            d.logger.error(f"FlareSolverr failed: {error_msg}")
            return False, {}, None
            
    except Timeout:
        d.logger.error("FlareSolverr timeout")
        return False, {}, None
    except Exception as e:
        proxy = locals().get('proxy')
        d.logger.error(f"FlareSolverr error: {_redact_proxy_secrets(e, proxy)}")
        return False, {}, None
