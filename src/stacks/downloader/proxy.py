"""Proxy URL helpers shared by downloader and browser-proxy paths."""

import os
from urllib.parse import quote, urlparse, urlunparse


def add_proxy_credentials(proxy_url, username=None, password=None):
    """Return *proxy_url* with safely encoded, replacement credentials."""
    if not (username and password):
        return proxy_url

    parsed = urlparse(proxy_url)
    if not parsed.scheme or not parsed.hostname:
        raise ValueError("Proxy URL must include a scheme and hostname")

    hostname = parsed.hostname
    if ':' in hostname and not hostname.startswith('['):
        hostname = f'[{hostname}]'
    host_port = f"{hostname}:{parsed.port}" if parsed.port else hostname
    userinfo = f"{quote(str(username), safe='')}:{quote(str(password), safe='')}"
    return urlunparse(parsed._replace(netloc=f"{userinfo}@{host_port}"))


def isolate_session_from_environment_proxies(session):
    """Disable ambient proxies while retaining Requests' custom CA bundle."""
    ca_bundle = os.environ.get('REQUESTS_CA_BUNDLE') or os.environ.get('CURL_CA_BUNDLE')
    session.trust_env = False
    if ca_bundle:
        session.verify = ca_bundle
    return session
