#!/usr/bin/env python3
"""Deterministically harden FlareSolverr v3.5.0 for current DDoS-Guard.

The transformations deliberately match exact upstream source anchors. A base
image update must therefore be reviewed instead of receiving a partial patch.
"""

from __future__ import annotations

import argparse
import ast
from pathlib import Path


MARKER = "STACKS_DDOS_GUARD_PATCH_V1"


def replace_once(source: str, old: str, new: str, description: str) -> str:
    count = source.count(old)
    if count != 1:
        raise RuntimeError(f"expected one {description} anchor, found {count}")
    return source.replace(old, new, 1)


def patch_service(source: str) -> str:
    source = replace_once(
        source,
        "import logging\n",
        "import json\nimport logging\nfrom urllib.parse import urlsplit, urlunsplit\n",
        "service import",
    )
    source = replace_once(
        source,
        "    '#cf-challenge-running', '.ray_id', '.attack-box', '#cf-please-wait', '#challenge-spinner', '#trk_jschal_js', '#turnstile-wrapper', '.lds-ring',\n",
        "    '#cf-challenge-running', '.ray_id', '.attack-box', '#cf-please-wait', '#challenge-spinner', '#trk_jschal_js', '#turnstile-wrapper',\n"
        "    # Current DDoS-Guard challenge document; unlike .lds-ring this is provider-specific.\n"
        "    'body[data-ddg-origin=\"true\"]',\n",
        "challenge selector",
    )

    helpers = r'''

# STACKS_DDOS_GUARD_PATCH_V1
_DDG_TITLE = 'ddos-guard'
_DDG_SELECTORS = ('body[data-ddg-origin="true"]',)
_DDG_STABLE_SECONDS = 6.0
_NETWORK_TYPES = {'Document', 'Script', 'Image'}
_STEALTH_SCRIPT = r"""
(() => {
  const clean = (target) => {
    for (const key of Object.getOwnPropertyNames(target)) {
      if (/^\$cdc_/.test(key)) {
        try { delete target[key]; } catch (_) {}
      }
    }
  };
  try { delete Object.getPrototypeOf(navigator).webdriver; } catch (_) {}
  clean(window);
  clean(document);
  document.addEventListener('readystatechange', () => {
    clean(window);
    clean(document);
  });
})();
"""


def _prepare_browser(driver: WebDriver):
    """Install evasions before any challenge JavaScript executes."""
    if getattr(driver, '_stacks_ddg_prepared', False):
        return
    driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {'source': _STEALTH_SCRIPT})
    driver.execute_cdp_cmd('Network.enable', {})
    driver._stacks_ddg_prepared = True


def _fingerprint_issues(driver: WebDriver) -> list[str]:
    """Expose deterministic failures instead of timing out on a rejected browser."""
    return driver.execute_script(r"""
      const issues = [];
      const keys = [...Object.getOwnPropertyNames(window), ...Object.getOwnPropertyNames(document)];
      if (keys.some((key) => /^\$cdc_/.test(key))) issues.push('chromedriver-cdc-property');
      if (navigator.webdriver === true) issues.push('navigator.webdriver');
      if (/HeadlessChrome/i.test(navigator.userAgent)) issues.push('headless-user-agent');
      if (!navigator.languages || navigator.languages.length === 0) issues.push('empty-languages');
      const canvas2d = document.createElement('canvas');
      if (!canvas2d.getContext('2d')) issues.push('canvas-unavailable');
      const webglCanvas = document.createElement('canvas');
      let gl = null;
      try { gl = webglCanvas.getContext('webgl2') || webglCanvas.getContext('webgl'); } catch (_) {}
      if (!gl) issues.push('webgl-unavailable');
      if (!(window.OfflineAudioContext || window.webkitOfflineAudioContext)) issues.push('audio-unavailable');
      if (!document.fonts || typeof document.fonts.check !== 'function') issues.push('fonts-unavailable');
      return issues;
    """)


def _selector_present(driver: WebDriver, selector: str) -> bool:
    return len(driver.find_elements(By.CSS_SELECTOR, selector)) > 0


def _observed_markers_present(driver: WebDriver, titles: list[str], selectors: list[str]) -> bool:
    current_title = driver.title.casefold()
    if any(current_title == title.casefold() for title in titles):
        return True
    return any(_selector_present(driver, selector) for selector in selectors)


def _ddg_html_marker_present(driver: WebDriver) -> bool:
    source = driver.page_source[:10000].casefold()
    return (
        'data-ddg-origin' in source
        or '/.well-known/ddos-guard/js-challenge/' in source
        or 'check.ddos-guard.net/check.js' in source
    )


def _ddg_bootstrap_refresh_needed(driver: WebDriver) -> bool:
    """Advance the image-cookie bootstrap if the provider has not reloaded it."""
    cookie_names = {cookie.get('name') for cookie in driver.get_cookies()}
    return '__ddg2_' in cookie_names and '__ddg7_' not in cookie_names


def _any_challenge_marker_present(driver: WebDriver) -> bool:
    title = driver.title.casefold()
    if any(title == candidate.casefold() for candidate in CHALLENGE_TITLES):
        return True
    return (
        _ddg_html_marker_present(driver)
        or any(_selector_present(driver, selector) for selector in CHALLENGE_SELECTORS)
    )


def _url_for_log(raw_url: str) -> str:
    """Keep network diagnostics useful without query strings or userinfo."""
    try:
        parsed = urlsplit(raw_url)
        hostname = parsed.hostname or ''
        if ':' in hostname and not hostname.startswith('['):
            hostname = f'[{hostname}]'
        netloc = f"{hostname}:{parsed.port}" if parsed.port else hostname
        return urlunsplit((parsed.scheme, netloc, parsed.path, '', ''))
    except Exception:
        return '<redacted URL>'


def _proxy_url_for_log(raw_url: str) -> str:
    """Mask credentials embedded directly in a proxy URL."""
    try:
        parsed = urlsplit(raw_url)
        if parsed.username is None and parsed.password is None:
            return raw_url
        hostname = parsed.hostname or ''
        if ':' in hostname and not hostname.startswith('['):
            hostname = f'[{hostname}]'
        host_port = f"{hostname}:{parsed.port}" if parsed.port else hostname
        return urlunsplit((parsed.scheme, f'***:***@{host_port}', parsed.path, '', ''))
    except Exception:
        return '<redacted proxy URL>'


def _request_for_log(req: V1RequestBase) -> dict:
    """Keep proxy credentials and clearance cookies out of request logs."""
    request_data = utils.object_to_dict(req)
    proxy = request_data.get('proxy')
    if isinstance(proxy, dict):
        proxy = dict(proxy)
        if proxy.get('url'):
            proxy['url'] = _proxy_url_for_log(proxy['url'])
        if proxy.get('username'):
            proxy['username'] = '***'
        if proxy.get('password'):
            proxy['password'] = '***'
        request_data['proxy'] = proxy
    cookies = request_data.get('cookies')
    if isinstance(cookies, list):
        request_data['cookies'] = [
            dict(cookie, value='***') if isinstance(cookie, dict) else cookie
            for cookie in cookies
        ]
    return request_data


def _response_for_log(res: V1ResponseBase) -> dict:
    """Summarize browser results without logging cookies, HTML, or screenshots."""
    response_data = utils.object_to_dict(res)
    solution = response_data.get('solution')
    if isinstance(solution, dict):
        solution = dict(solution)
        cookies = solution.get('cookies')
        if isinstance(cookies, list):
            solution['cookies'] = [
                dict(cookie, value='***') if isinstance(cookie, dict) else cookie
                for cookie in cookies
            ]
        if solution.get('response') is not None:
            solution['response'] = f"<redacted {len(solution['response'])} chars>"
        if solution.get('screenshot') is not None:
            solution['screenshot'] = '<redacted>'
        if solution.get('turnstile_token') is not None:
            solution['turnstile_token'] = '<redacted>'
        response_data['solution'] = solution
    return response_data


def _network_idle(driver: WebDriver, quiet_seconds: float = 0.75, timeout: float = 10.0) -> tuple[bool, list[str]]:
    """Wait for critical browser traffic to settle using Chrome performance events."""
    deadline = time.monotonic() + timeout
    inflight: dict[str, tuple[str, str]] = {}
    failures: list[str] = []
    quiet_since = None
    performance_log_available = True

    while time.monotonic() < deadline:
        try:
            entries = driver.get_log('performance')
        except Exception:
            entries = []
            performance_log_available = False

        for entry in entries:
            try:
                event = json.loads(entry['message'])['message']
                method = event['method']
                params = event.get('params', {})
                request_id = params.get('requestId')
                if method == 'Network.requestWillBeSent' and params.get('type') in _NETWORK_TYPES:
                    url = params.get('request', {}).get('url', '')
                    if url.startswith(('http://', 'https://')):
                        inflight[request_id] = (params.get('type', ''), url)
                elif method == 'Network.loadingFailed' and request_id in inflight:
                    resource_type, url = inflight.pop(request_id)
                    failures.append(f"{resource_type} {_url_for_log(url)}: {params.get('errorText', 'failed')}")
                elif method == 'Network.loadingFinished':
                    inflight.pop(request_id, None)
                elif method == 'Network.responseReceived' and params.get('type') == 'Document':
                    response = params.get('response', {})
                    response_url = response.get('url', '').split('#', 1)[0]
                    response_status = response.get('status')
                    if response_url and response_status is not None:
                        statuses = getattr(driver, '_stacks_document_statuses', {})
                        statuses[response_url] = int(response_status)
                        driver._stacks_document_statuses = statuses
            except (KeyError, TypeError, ValueError):
                continue

        ready = driver.execute_script("return document.readyState") == 'complete'
        settled = not inflight or not performance_log_available
        if ready and settled:
            quiet_since = quiet_since or time.monotonic()
            if time.monotonic() - quiet_since >= quiet_seconds:
                return True, failures
        else:
            quiet_since = None
        time.sleep(0.1)

    pending = [f"{resource_type} {_url_for_log(url)}" for resource_type, url in inflight.values()]
    return False, failures + pending


def _main_document_status(driver: WebDriver) -> int:
    current_url = driver.current_url.split('#', 1)[0]
    status = getattr(driver, '_stacks_document_statuses', {}).get(current_url)
    if status is None:
        raise Exception('Final main-document HTTP status was unavailable')
    return int(status)
'''
    source = replace_once(
        source,
        "SESSIONS_STORAGE = SessionsStorage()\n\n\ndef test_browser_installation():",
        "SESSIONS_STORAGE = SessionsStorage()\n" + helpers + "\n\ndef test_browser_installation():",
        "service helper insertion",
    )
    source = replace_once(
        source,
        "    logging.info(f\"Incoming request => POST /v1 body: {utils.object_to_dict(req)}\")\n",
        "    logging.info(f\"Incoming request => POST /v1 body: {_request_for_log(req)}\")\n",
        "request log redaction",
    )
    source = replace_once(
        source,
        "    logging.debug(f\"Response => POST /v1 body: {utils.object_to_dict(res)}\")\n",
        "    logging.debug(f\"Response => POST /v1 body: {_response_for_log(res)}\")\n",
        "response log redaction",
    )
    source = replace_once(
        source,
        "    if utils.get_config_log_html():\n"
        "        logging.debug(f\"Response HTML:\\n{driver.page_source}\")\n",
        "    if utils.get_config_log_html():\n"
        "        logging.debug(\"Response HTML logging suppressed by the Stacks security overlay\")\n",
        "raw HTML log suppression",
    )
    source = replace_once(
        source,
        "def _evil_logic(req: V1RequestBase, driver: WebDriver, method: str) -> ChallengeResolutionT:\n    res = ChallengeResolutionT({})\n",
        "def _evil_logic(req: V1RequestBase, driver: WebDriver, method: str) -> ChallengeResolutionT:\n"
        "    _prepare_browser(driver)\n"
        "    res = ChallengeResolutionT({})\n",
        "browser preparation",
    )
    source = replace_once(
        source,
        "    html_element = driver.find_element(By.TAG_NAME, \"html\")\n    page_title = driver.title\n\n    # find access denied titles\n",
        "    html_element = driver.find_element(By.TAG_NAME, \"html\")\n"
        "    page_title = driver.title\n"
        "    fingerprint_issues = _fingerprint_issues(driver)\n"
        "    blocking_fingerprint_issues = [\n"
        "        issue for issue in fingerprint_issues\n"
        "        if issue in ('chromedriver-cdc-property', 'navigator.webdriver', 'headless-user-agent', 'empty-languages')\n"
        "    ]\n"
        "    if blocking_fingerprint_issues:\n"
        "        raise Exception('Browser fingerprint preflight failed: ' + ', '.join(blocking_fingerprint_issues))\n"
        "    if fingerprint_issues:\n"
        "        logging.warning('Optional browser fingerprint APIs unavailable: %s', fingerprint_issues)\n\n"
        "    # find access denied titles\n",
        "fingerprint preflight",
    )

    old_loop = '''    # find challenge by title
    challenge_found = False
    for title in CHALLENGE_TITLES:
        if title.lower() == page_title.lower():
            challenge_found = True
            logging.info("Challenge detected. Title found: " + page_title)
            break
    if not challenge_found:
        # find challenge by selectors
        for selector in CHALLENGE_SELECTORS:
            found_elements = driver.find_elements(By.CSS_SELECTOR, selector)
            if len(found_elements) > 0:
                challenge_found = True
                logging.info("Challenge detected. Selector found: " + selector)
                break

    attempt = 0
    if challenge_found:
        while True:
            try:
                attempt = attempt + 1
                # wait until the title changes
                for title in CHALLENGE_TITLES:
                    logging.debug("Waiting for title (attempt " + str(attempt) + "): " + title)
                    WebDriverWait(driver, SHORT_TIMEOUT).until_not(title_is(title))

                # then wait until all the selectors disappear
                for selector in CHALLENGE_SELECTORS:
                    logging.debug("Waiting for selector (attempt " + str(attempt) + "): " + selector)
                    WebDriverWait(driver, SHORT_TIMEOUT).until_not(
                        presence_of_element_located((By.CSS_SELECTOR, selector)))

                # all elements not found
                break

            except TimeoutException:
                logging.debug("Timeout waiting for selector")

                click_verify(driver)

                # update the html (cloudflare reloads the page every 5 s)
                html_element = driver.find_element(By.TAG_NAME, "html")

        # waits until cloudflare redirection ends
        logging.debug("Waiting for redirect")
        # noinspection PyBroadException
        try:
            WebDriverWait(driver, SHORT_TIMEOUT).until(staleness_of(html_element))
        except Exception:
            logging.debug("Timeout waiting for redirect")

        logging.info("Challenge solved!")
        res.message = "Challenge solved!"
    else:
        logging.info("Challenge not detected!")
        res.message = "Challenge not detected!"
'''
    new_loop = '''    # Find and remember only the markers actually observed on the challenge page.
    observed_titles = [title for title in CHALLENGE_TITLES if title.casefold() == page_title.casefold()]
    observed_selectors = [
        selector for selector in CHALLENGE_SELECTORS if _selector_present(driver, selector)
    ]
    challenge_found = bool(observed_titles or observed_selectors) or _ddg_html_marker_present(driver)
    is_ddg = page_title.casefold() == _DDG_TITLE or any(
        selector in _DDG_SELECTORS for selector in observed_selectors
    ) or _ddg_html_marker_present(driver)

    attempt = 0
    if challenge_found:
        logging.info("Challenge detected. Title: %s; selectors: %s", page_title, observed_selectors)
        clean_since = None
        bootstrap_refresh_done = False
        bootstrap_check_deadline = time.monotonic() + 10.0
        while True:
            attempt += 1
            if not _observed_markers_present(driver, observed_titles, observed_selectors):
                ready, resource_failures = _network_idle(driver)
                if resource_failures:
                    logging.debug("Browser resource failures: %s", resource_failures)
                if ready and not _any_challenge_marker_present(driver):
                    clean_since = clean_since or time.monotonic()
                    required_stability = _DDG_STABLE_SECONDS if is_ddg else 0.0
                    stable_for = time.monotonic() - clean_since
                    if stable_for >= required_stability:
                        break
                    logging.debug(
                        "Challenge markers clear for %.2fs; waiting for %.2fs stability",
                        stable_for,
                        required_stability,
                    )
                else:
                    clean_since = None
            else:
                clean_since = None
            logging.debug("Waiting for challenge markers (attempt %s)", attempt)
            # DDoS-Guard is automatic; Cloudflare-specific key presses can disrupt it.
            if is_ddg:
                if not bootstrap_refresh_done and time.monotonic() < bootstrap_check_deadline:
                    bootstrap_ready, bootstrap_failures = _network_idle(
                        driver, quiet_seconds=0.5, timeout=3.0
                    )
                    if bootstrap_failures:
                        logging.debug("DDoS-Guard bootstrap resource failures: %s", bootstrap_failures)
                    if bootstrap_ready and _ddg_bootstrap_refresh_needed(driver):
                        logging.info("Advancing DDoS-Guard bootstrap cookie phase")
                        bootstrap_refresh_done = True
                        driver.refresh()
                        html_element = driver.find_element(By.TAG_NAME, "html")
                        continue
                time.sleep(0.25)
            else:
                click_verify(driver)
            html_element = driver.find_element(By.TAG_NAME, "html")

        logging.info("Challenge solved!")
        res.message = "Challenge solved!"
    else:
        ready, resource_failures = _network_idle(driver, timeout=2.0)
        if not ready:
            # Long polling is normal on ordinary pages; this is a hard gate only
            # while resolving a detected challenge.
            logging.debug('Page did not reach browser network idle: %s', resource_failures[-5:])
        logging.info("Challenge not detected!")
        res.message = "Challenge not detected!"
'''
    source = replace_once(source, old_loop, new_loop, "challenge loop")

    old_response = '''    challenge_res = ChallengeResolutionResultT({})
    challenge_res.url = driver.current_url
    challenge_res.status = 200  # todo: fix, selenium not provides this info
    challenge_res.cookies = driver.get_cookies()
    challenge_res.userAgent = utils.get_user_agent(driver)
    challenge_res.turnstile_token = turnstile_token

    if not req.returnOnlyCookies:
        challenge_res.headers = {}  # todo: fix, selenium not provides this info

        if req.waitInSeconds and req.waitInSeconds > 0:
            logging.info("Waiting " + str(req.waitInSeconds) + " seconds before returning the response...")
            time.sleep(req.waitInSeconds)

        challenge_res.response = driver.page_source
'''
    new_response = '''    # DDoS-Guard can stage cookies and another reload during this caller-requested wait.
    if req.waitInSeconds and req.waitInSeconds > 0:
        logging.info("Waiting " + str(req.waitInSeconds) + " seconds before returning the response...")
        time.sleep(req.waitInSeconds)

    final_ready, final_resource_failures = _network_idle(
        driver, quiet_seconds=0.25, timeout=5.0
    )
    if not final_ready:
        raise Exception(
            'Final browser navigation did not settle: '
            + '; '.join(final_resource_failures[-5:])
        )

    if _any_challenge_marker_present(driver):
        raise Exception('Protection challenge returned during the post-solve wait')

    challenge_res = ChallengeResolutionResultT({})
    challenge_res.url = driver.current_url
    challenge_res.status = _main_document_status(driver)
    challenge_res.cookies = driver.get_cookies()
    challenge_res.userAgent = utils.get_user_agent(driver)
    challenge_res.turnstile_token = turnstile_token

    if not req.returnOnlyCookies:
        challenge_res.headers = {}  # todo: fix, selenium does not provide this info
        challenge_res.response = driver.page_source
'''
    return replace_once(source, old_response, new_response, "post-solve response capture")


def patch_utils(source: str) -> str:
    source = replace_once(
        source,
        "    scheme = parsed_url.scheme\n"
        "    host = parsed_url.hostname\n"
        "    port = parsed_url.port\n"
        "    username = proxy['username']\n"
        "    password = proxy['password']\n",
        "    scheme = json.dumps(parsed_url.scheme)\n"
        "    host = json.dumps(parsed_url.hostname)\n"
        "    port = parsed_url.port or (443 if parsed_url.scheme == 'https' else 80)\n"
        "    # Encode credentials as JavaScript string literals instead of interpolating them.\n"
        "    username = json.dumps(str(proxy['username']))\n"
        "    password = json.dumps(str(proxy['password']))\n",
        "proxy extension JavaScript values",
    )
    source = replace_once(
        source,
        "                scheme: \"%s\",\n"
        "                host: \"%s\",\n"
        "                port: %d\n",
        "                scheme: %s,\n"
        "                host: %s,\n"
        "                port: %d\n",
        "proxy extension endpoint literals",
    )
    source = replace_once(
        source,
        "                username: \"%s\",\n"
        "                password: \"%s\"\n",
        "                username: %s,\n"
        "                password: %s\n",
        "proxy extension credential literals",
    )
    source = replace_once(
        source,
        "    proxy_extension_dir = tempfile.mkdtemp()\n\n"
        "    with open(os.path.join(proxy_extension_dir, \"manifest.json\"), \"w\") as f:\n"
        "        f.write(manifest_json)\n\n"
        "    with open(os.path.join(proxy_extension_dir, \"background.js\"), \"w\") as f:\n"
        "        f.write(background_js)\n\n"
        "    return proxy_extension_dir\n",
        "    proxy_extension_dir = tempfile.mkdtemp()\n"
        "    try:\n"
        "        with open(os.path.join(proxy_extension_dir, \"manifest.json\"), \"w\") as f:\n"
        "            f.write(manifest_json)\n\n"
        "        with open(os.path.join(proxy_extension_dir, \"background.js\"), \"w\") as f:\n"
        "            f.write(background_js)\n\n"
        "        return proxy_extension_dir\n"
        "    except Exception:\n"
        "        shutil.rmtree(proxy_extension_dir, ignore_errors=True)\n"
        "        raise\n",
        "proxy extension creation cleanup",
    )
    source = replace_once(
        source,
        "    proxy_extension_dir = None\n"
        "    if proxy and all(key in proxy for key in ['url', 'username', 'password']):\n"
        "        proxy_extension_dir = create_proxy_extension(proxy)\n"
        "        options.add_argument(\"--disable-features=DisableLoadExtensionCommandLineSwitch\")\n"
        "        options.add_argument(\"--load-extension=%s\" % os.path.abspath(proxy_extension_dir))\n"
        "    elif proxy and 'url' in proxy:\n",
        "    proxy_extension_dir = None\n"
        "    authenticated_proxy = bool(\n"
        "        proxy and all(key in proxy for key in ['url', 'username', 'password'])\n"
        "    )\n"
        "    if proxy and 'url' in proxy and not authenticated_proxy:\n",
        "deferred authenticated proxy extension",
    )
    source = replace_once(
        source,
        "    options = uc.ChromeOptions()\n    options.add_argument('--no-sandbox')\n",
        "    options = uc.ChromeOptions()\n"
        "    # STACKS_DDOS_GUARD_PATCH_V1: retain CDP network events for completion checks.\n"
        "    options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})\n"
        "    options.add_argument('--use-gl=angle')\n"
        "    options.add_argument('--use-angle=swiftshader-webgl')\n"
        "    options.add_argument('--enable-unsafe-swiftshader')\n"
        "    options.add_argument('--no-sandbox')\n",
        "performance logging",
    )
    source = replace_once(
        source,
        "    language = os.environ.get('LANG', None)\n"
        "    if language is not None:\n"
        "        options.add_argument('--accept-lang=%s' % language)\n",
        "    language = os.environ.get('LANG', '').split('.', 1)[0].replace('_', '-')\n"
        "    if not language or language.upper() in ('C', 'POSIX'):\n"
        "        language = 'en-US'\n"
        "    options.add_argument('--lang=%s' % language)\n"
        "    options.add_argument('--accept-lang=%s' % language)\n",
        "browser language",
    )
    source = replace_once(
        source,
        "                           windows_headless=windows_headless, headless=get_config_headless())\n",
        "                           windows_headless=windows_headless, headless=windows_headless)\n",
        "Linux headful browser under Xvfb",
    )
    source = replace_once(
        source,
        "        logging.debug(\"Using webdriver proxy: %s\", proxy_url)\n",
        "        logging.debug(\"Using webdriver proxy\")\n",
        "webdriver proxy log redaction",
    )
    source = replace_once(
        source,
        "    # downloads and patches the chromedriver\n"
        "    # if we don't set driver_executable_path it downloads, patches, and deletes the driver each time\n"
        "    try:\n",
        "    # Defer creation until every fallible preflight is complete.\n"
        "    if authenticated_proxy:\n"
        "        proxy_extension_dir = create_proxy_extension(proxy)\n"
        "        options.add_argument(\"--disable-features=DisableLoadExtensionCommandLineSwitch\")\n"
        "        options.add_argument(\"--load-extension=%s\" % os.path.abspath(proxy_extension_dir))\n\n"
        "    # downloads and patches the chromedriver\n"
        "    # if we don't set driver_executable_path it downloads, patches, and deletes the driver each time\n"
        "    try:\n",
        "authenticated proxy extension launch",
    )
    source = replace_once(
        source,
        "    except Exception as e:\n"
        "        logging.error(\"Error starting Chrome: %s\" % e)\n"
        "        # No point in continuing if we cannot retrieve the driver\n"
        "        raise e\n",
        "    except Exception as e:\n"
        "        logging.error(\"Error starting Chrome: %s\" % e)\n"
        "        # Authenticated proxy extensions contain plaintext credentials.\n"
        "        if proxy_extension_dir is not None:\n"
        "            shutil.rmtree(proxy_extension_dir, ignore_errors=True)\n"
        "        # No point in continuing if we cannot retrieve the driver\n"
        "        raise\n\n"
        "    # Chrome has loaded the unpacked extension; erase its plaintext credentials now.\n"
        "    if proxy_extension_dir is not None:\n"
        "        shutil.rmtree(proxy_extension_dir, ignore_errors=True)\n"
        "        proxy_extension_dir = None\n",
        "proxy extension failure cleanup",
    )
    return replace_once(
        source,
        "        XVFB_DISPLAY = Xvfb()\n",
        "        XVFB_DISPLAY = Xvfb(width=1920, height=1080, colordepth=24)\n",
        "Xvfb screen dimensions",
    )


def apply(root: Path) -> None:
    service_path = root / "flaresolverr_service.py"
    utils_path = root / "utils.py"
    service = service_path.read_text()
    utils = utils_path.read_text()
    if MARKER in service or MARKER in utils:
        raise RuntimeError("patch already applied")
    service_path.write_text(patch_service(service))
    utils_path.write_text(patch_utils(utils))


def verify(root: Path) -> None:
    for filename in ("flaresolverr_service.py", "utils.py"):
        source = (root / filename).read_text()
        if MARKER not in source:
            raise RuntimeError(f"{filename} does not contain {MARKER}")
        ast.parse(source, filename=filename)
    service = (root / "flaresolverr_service.py").read_text()
    required = (
        "Page.addScriptToEvaluateOnNewDocument",
        "body[data-ddg-origin=\"true\"]",
        "driver.get_log('performance')",
        "if is_ddg:",
        "_DDG_STABLE_SECONDS = 6.0",
        "Browser fingerprint preflight failed",
        "Protection challenge returned during the post-solve wait",
        "challenge_res.status = _main_document_status(driver)",
        "Advancing DDoS-Guard bootstrap cookie phase",
        "proxy['url'] = _proxy_url_for_log(proxy['url'])",
        "proxy['password'] = '***'",
        "dict(cookie, value='***')",
        "<redacted {len(solution['response'])} chars>",
        "solution['turnstile_token'] = '<redacted>'",
        "Response HTML logging suppressed by the Stacks security overlay",
    )
    missing = [needle for needle in required if needle not in service]
    if missing:
        raise RuntimeError(f"patched service is missing checks: {missing}")
    if "'.lds-ring'" in service:
        raise RuntimeError("generic .lds-ring selector remains enabled")
    if "challenge_res.status = 200" in service:
        raise RuntimeError("main-document status is still fabricated")
    if "Response HTML:\\n{driver.page_source}" in service:
        raise RuntimeError("raw HTML debug logging remains enabled")
    if service.index("time.sleep(req.waitInSeconds)") > service.index("challenge_res.cookies = driver.get_cookies()"):
        raise RuntimeError("cookies are still captured before waitInSeconds")
    utils_source = (root / "utils.py").read_text()
    webgl_options = (
        "--use-gl=angle",
        "--use-angle=swiftshader-webgl",
        "--enable-unsafe-swiftshader",
    )
    if any(option not in utils_source for option in webgl_options):
        raise RuntimeError("software WebGL browser options are missing")
    if "headless=windows_headless" not in utils_source:
        raise RuntimeError("Linux browser is not configured headful under Xvfb")
    if "Xvfb(width=1920, height=1080, colordepth=24)" not in utils_source:
        raise RuntimeError("Xvfb and browser window dimensions are not aligned")
    if "username = json.dumps(str(proxy['username']))" not in utils_source:
        raise RuntimeError("proxy credentials are not safely encoded for JavaScript")
    if 'logging.debug("Using webdriver proxy: %s", proxy_url)' in utils_source:
        raise RuntimeError("webdriver proxy URL logging remains enabled")
    if "authenticated_proxy = bool(" not in utils_source:
        raise RuntimeError("authenticated proxy extension creation is not deferred")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("apply", "verify"))
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    if args.command == "apply":
        apply(args.root)
    else:
        verify(args.root)


if __name__ == "__main__":
    main()
