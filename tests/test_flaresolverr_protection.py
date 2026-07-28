import json
import io
import logging
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import requests


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from stacks.downloader import cookies as cookie_cache  # noqa: E402
from stacks.downloader.direct import (  # noqa: E402
    _get_download_response,
    download_direct,
)
from stacks.downloader.flaresolver import (  # noqa: E402
    _normalised_proxy_payload,
    solve_with_flaresolverr,
)
from stacks.downloader.protection import (  # noqa: E402
    response_looks_like_protection,
    streamed_response_looks_like_protection,
)
from stacks.downloader.proxy import (  # noqa: E402
    add_proxy_credentials,
    isolate_session_from_environment_proxies,
)


def _response(status=200, body="", content_type="text/html", json_body=None):
    response = requests.Response()
    response.status_code = status
    response.url = "https://example.com/protected"
    response.headers["Content-Type"] = content_type
    if json_body is not None:
        body = json.dumps(json_body)
        response.headers["Content-Type"] = "application/json"
    response._content = body.encode("utf-8")
    response.encoding = "utf-8"
    response.raw = io.BytesIO(response._content)
    return response


class ProtectionDetectionTests(unittest.TestCase):
    def test_detects_error_status_and_http_200_challenge_pages(self):
        for status in (403, 429, 503):
            with self.subTest(status=status):
                self.assertTrue(
                    response_looks_like_protection(
                        _response(status, "plain response", "text/plain")
                    )
                )

        self.assertTrue(
            response_looks_like_protection(
                _response(200, "<html>DDoS-Guard checking your browser</html>")
            )
        )
        self.assertFalse(
            response_looks_like_protection(
                _response(200, "<html><h1>Download ready</h1></html>")
            )
        )

    def test_stream_probe_replays_inspected_bytes(self):
        body = b"<html><h1>A legitimate streamed document</h1></html>" + b"x" * 6000
        response = requests.Response()
        response.status_code = 200
        response.headers["Content-Type"] = "text/html"
        response._content = False
        response.raw = io.BytesIO(body)

        self.assertFalse(streamed_response_looks_like_protection(response))
        self.assertEqual(b"".join(response.iter_content(chunk_size=257)), body)

    def test_direct_download_solves_then_retries_every_protection_shape(self):
        challenges = (
            _response(200, "<html>check.ddos-guard.net</html>"),
            _response(403, "forbidden", "text/plain"),
            _response(429, "limited", "text/plain"),
            _response(503, "unavailable", "text/plain"),
        )

        for challenge in challenges:
            with self.subTest(status=challenge.status_code):
                success = _response(200, "file bytes", "application/octet-stream")
                session = Mock()
                session.get.side_effect = [challenge, success]
                downloader = SimpleNamespace(
                    session=session,
                    flaresolverr_url="http://solver:8191",
                    solve_with_flaresolverr=Mock(return_value=(True, {}, "solved")),
                )

                result = _get_download_response(downloader, "https://example.com/file.epub")

                self.assertIs(result, success)
                downloader.solve_with_flaresolverr.assert_called_once_with(challenge.url)
                self.assertEqual(session.get.call_count, 2)

    def test_range_rejection_is_returned_for_resume_recovery(self):
        rejected_range = _response(416, "range not satisfiable", "text/plain")
        session = Mock()
        session.get.return_value = rejected_range
        downloader = SimpleNamespace(session=session, flaresolverr_url=None)

        result = _get_download_response(
            downloader,
            "https://example.com/file.epub",
            headers={"Range": "bytes=100-"},
        )

        self.assertIs(result, rejected_range)

    def test_direct_download_uses_slow_host_read_timeout(self):
        success = _response(200, "file bytes", "application/octet-stream")
        session = Mock()
        session.get.return_value = success
        downloader = SimpleNamespace(
            session=session,
            flaresolverr_url=None,
            download_read_timeout=420,
        )

        result = _get_download_response(
            downloader,
            "https://example.com/file.epub",
        )

        self.assertIs(result, success)
        session.get.assert_called_once_with(
            "https://example.com/file.epub",
            headers={},
            stream=True,
            timeout=(30, 420),
        )

    def test_resume_restarts_when_server_ignores_range(self):
        initial = _response(200, "unused", "application/octet-stream")
        ignored_range = _response(200, "complete", "application/octet-stream")
        ignored_range.close = Mock(wraps=ignored_range.close)
        for response in (initial, ignored_range):
            response.url = "https://example.com/book.pdf"

        session = Mock()
        session.get.side_effect = [initial, ignored_range]

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_dir = root / "download"
            incomplete_dir = root / "incomplete"
            output_dir.mkdir()
            incomplete_dir.mkdir()
            (incomplete_dir / "book.pdf.part").write_bytes(b"old")

            downloader = SimpleNamespace(
                session=session,
                flaresolverr_url=None,
                download_read_timeout=300,
                output_dir=output_dir,
                incomplete_dir=incomplete_dir,
                logger=Mock(),
                progress_callback=None,
                get_unique_filename=lambda path: path,
            )

            result = download_direct(
                downloader,
                "https://example.com/book.pdf",
                title="book.pdf",
                md5=None,
            )

            self.assertEqual(result, output_dir / "book.pdf")
            self.assertEqual(result.read_bytes(), b"complete")
            self.assertEqual(session.get.call_count, 2)
            self.assertEqual(
                session.get.call_args_list[1].kwargs["headers"],
                {"Range": "bytes=3-"},
            )
            ignored_range.close.assert_called()

    def test_resume_accepts_matching_content_range(self):
        initial = _response(200, "unused", "application/octet-stream")
        resumed = _response(206, "plete", "application/octet-stream")
        resumed.headers["Content-Range"] = "bytes 3-7/8"
        resumed.headers["Content-Length"] = "5"
        for response in (initial, resumed):
            response.url = "https://example.com/book.pdf"

        session = Mock()
        session.get.side_effect = [initial, resumed]

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_dir = root / "download"
            incomplete_dir = root / "incomplete"
            output_dir.mkdir()
            incomplete_dir.mkdir()
            (incomplete_dir / "book.pdf.part").write_bytes(b"com")

            downloader = SimpleNamespace(
                session=session,
                flaresolverr_url=None,
                download_read_timeout=300,
                output_dir=output_dir,
                incomplete_dir=incomplete_dir,
                logger=Mock(),
                progress_callback=None,
                get_unique_filename=lambda path: path,
            )

            result = download_direct(
                downloader,
                "https://example.com/book.pdf",
                title="book.pdf",
                md5=None,
            )

            self.assertEqual(result.read_bytes(), b"complete")
            self.assertEqual(session.get.call_count, 2)
            self.assertEqual(
                session.get.call_args_list[1].kwargs["headers"],
                {"Range": "bytes=3-"},
            )

    def test_resume_rejects_wrong_content_range(self):
        initial = _response(200, "unused", "application/octet-stream")
        wrong_range = _response(206, "junk", "application/octet-stream")
        wrong_range.headers["Content-Range"] = "bytes 0-3/8"
        wrong_range.close = Mock(wraps=wrong_range.close)
        fresh = _response(200, "complete", "application/octet-stream")
        for response in (initial, wrong_range, fresh):
            response.url = "https://example.com/book.pdf"

        session = Mock()
        session.get.side_effect = [initial, wrong_range, fresh]

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_dir = root / "download"
            incomplete_dir = root / "incomplete"
            output_dir.mkdir()
            incomplete_dir.mkdir()
            (incomplete_dir / "book.pdf.part").write_bytes(b"old")

            downloader = SimpleNamespace(
                session=session,
                flaresolverr_url=None,
                download_read_timeout=300,
                output_dir=output_dir,
                incomplete_dir=incomplete_dir,
                logger=Mock(),
                progress_callback=None,
                get_unique_filename=lambda path: path,
            )

            result = download_direct(
                downloader,
                "https://example.com/book.pdf",
                title="book.pdf",
                md5=None,
            )

            self.assertEqual(result.read_bytes(), b"complete")
            self.assertEqual(session.get.call_count, 3)
            self.assertEqual(session.get.call_args_list[2].kwargs["headers"], {})
            wrong_range.close.assert_called()

    def test_read_timeout_resumes_from_written_bytes(self):
        interrupted = _response(200, "", "application/octet-stream")
        interrupted.url = "https://example.com/book.pdf"
        interrupted.close = Mock(wraps=interrupted.close)

        def interrupted_chunks(chunk_size):
            yield b"com"
            raise requests.exceptions.ReadTimeout("slow host stalled")

        interrupted.iter_content = interrupted_chunks

        resumed = _response(206, "plete", "application/octet-stream")
        resumed.url = "https://example.com/book.pdf"
        resumed.headers["Content-Range"] = "bytes 3-7/8"
        resumed.headers["Content-Length"] = "5"
        resumed.close = Mock(wraps=resumed.close)

        session = Mock()
        session.get.side_effect = [interrupted, resumed]

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            output_dir = root / "download"
            incomplete_dir = root / "incomplete"
            output_dir.mkdir()
            incomplete_dir.mkdir()
            downloader = SimpleNamespace(
                session=session,
                flaresolverr_url=None,
                download_read_timeout=300,
                output_dir=output_dir,
                incomplete_dir=incomplete_dir,
                logger=Mock(),
                progress_callback=None,
                get_unique_filename=lambda path: path,
            )

            with patch("stacks.downloader.direct.time.sleep"):
                result = download_direct(
                    downloader,
                    "https://example.com/book.pdf",
                    title="book.pdf",
                    md5=None,
                )

            self.assertEqual(result.read_bytes(), b"complete")
            self.assertEqual(session.get.call_count, 2)
            self.assertEqual(
                session.get.call_args_list[1].kwargs["headers"],
                {"Range": "bytes=3-"},
            )
            interrupted.close.assert_called()
            resumed.close.assert_called()


class FlareSolverrTests(unittest.TestCase):
    def _downloader(self, api_response):
        target_session = requests.Session()
        target_session.proxies = {
            "http": "http://alice:p%40ssword@proxy.local:8080",
            "https": "http://alice:p%40ssword@proxy.local:8080",
        }
        control_session = Mock()
        control_session.post.return_value = api_response
        return SimpleNamespace(
            flaresolverr_url="http://solver:8191",
            flaresolverr_timeout=60000,
            session=target_session,
            flaresolverr_control_session=control_session,
            logger=Mock(),
            save_cookies_to_cache=Mock(),
        )

    def test_rejects_unresolved_target_statuses_and_challenge_html(self):
        for target_status in (403, 429, 503):
            with self.subTest(target_status=target_status):
                api_response = _response(
                    json_body={
                        "status": "ok",
                        "solution": {
                            "status": target_status,
                            "response": "blocked",
                            "cookies": [],
                        },
                    }
                )
                downloader = self._downloader(api_response)
                self.assertEqual(
                    solve_with_flaresolverr(downloader, "https://example.com/page"),
                    (False, {}, None),
                )
                downloader.save_cookies_to_cache.assert_not_called()

        api_response = _response(
            json_body={
                "status": "ok",
                "solution": {
                    "status": 200,
                    "response": "<html><title>DDoS-Guard</title></html>",
                    "cookies": [{"name": "intermediate", "value": "bad"}],
                },
            }
        )
        downloader = self._downloader(api_response)
        self.assertEqual(
            solve_with_flaresolverr(downloader, "https://example.com/page"),
            (False, {}, None),
        )
        downloader.save_cookies_to_cache.assert_not_called()

    def test_preserves_cookie_records_ua_and_target_proxy(self):
        expires = int(time.time()) + 3600
        api_response = _response(
            json_body={
                "status": "ok",
                "solution": {
                    "status": 200,
                    "response": "<html>download ready</html>",
                    "userAgent": "Solved Browser UA",
                    "cookies": [
                        {
                            "name": "__ddgmark_",
                            "value": "clearance",
                            "domain": ".example.com",
                            "path": "/",
                            "expires": expires,
                            "secure": True,
                            "httpOnly": True,
                            "sameSite": "Lax",
                        }
                    ],
                },
            }
        )
        downloader = self._downloader(api_response)
        downloader.session.cookies.set(
            "seed",
            "existing",
            domain=".example.com",
            path="/",
            expires=expires,
        )

        solved, cookie_values, _ = solve_with_flaresolverr(
            downloader,
            "https://example.com/page",
        )

        self.assertTrue(solved)
        self.assertEqual(cookie_values, {"__ddgmark_": "clearance"})
        self.assertEqual(downloader.session.headers["User-Agent"], "Solved Browser UA")
        self.assertNotIn("seed", downloader.session.cookies)
        self.assertEqual(
            downloader.session.cookies.get("__ddgmark_", domain=".example.com", path="/"),
            "clearance",
        )

        cached_cookies = downloader.save_cookies_to_cache.call_args.args[0]
        self.assertEqual(cached_cookies[0]["domain"], ".example.com")
        self.assertEqual(cached_cookies[0]["expires"], expires)
        self.assertTrue(cached_cookies[0]["secure"])
        self.assertTrue(cached_cookies[0]["httpOnly"])
        self.assertEqual(cached_cookies[0]["sameSite"], "Lax")
        self.assertTrue(downloader.save_cookies_to_cache.call_args.kwargs["replace"])

        post_call = downloader.flaresolverr_control_session.post.call_args
        payload = post_call.kwargs["json"]
        self.assertEqual(payload["cookies"][0]["expiry"], expires)
        self.assertNotIn("expires", payload["cookies"][0])
        self.assertNotIn("httpOnly", payload["cookies"][0])
        self.assertEqual(
            payload["proxy"],
            {
                "url": "http://proxy.local:8080",
                "username": "alice",
                "password": "p@ssword",
            },
        )
        self.assertNotIn("alice", payload["proxy"]["url"])
        self.assertNotIn("p@ssword", payload["proxy"]["url"])

    def test_proxy_credentials_are_encoded_once_and_decoded_for_solver(self):
        proxy_url = add_proxy_credentials(
            "http://old:credentials@proxy.local:8080",
            "user@corp",
            "p:a/ss#%",
        )
        self.assertEqual(
            proxy_url,
            "http://user%40corp:p%3Aa%2Fss%23%25@proxy.local:8080",
        )

        session = requests.Session()
        session.proxies = {"https": proxy_url}
        self.assertEqual(
            _normalised_proxy_payload(session),
            {
                "url": "http://proxy.local:8080",
                "username": "user@corp",
                "password": "p:a/ss#%",
            },
        )

    def test_isolated_session_keeps_custom_ca_bundle(self):
        session = requests.Session()
        with patch.dict("os.environ", {"REQUESTS_CA_BUNDLE": "/certs/private-ca.pem"}):
            isolate_session_from_environment_proxies(session)

        self.assertFalse(session.trust_env)
        self.assertEqual(session.verify, "/certs/private-ca.pem")

    def test_redacts_proxy_credentials_from_solver_errors(self):
        api_response = _response(
            500,
            json_body={"message": "proxy alice / p@ssword failed"},
        )
        downloader = self._downloader(api_response)

        solve_with_flaresolverr(downloader, "https://example.com/page")

        log_message = downloader.logger.error.call_args.args[0]
        self.assertNotIn("alice", log_message)
        self.assertNotIn("p@ssword", log_message)


class CookieCacheTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.cache_dir = Path(self.temp_dir.name)
        self.downloader = SimpleNamespace(
            session=requests.Session(),
            logger=logging.getLogger("cookie-cache-test"),
        )
        self.cache_patch = patch.object(cookie_cache, "COOKIE_CACHE_DIR", self.cache_dir)
        self.cache_patch.start()

    def tearDown(self):
        self.cache_patch.stop()
        self.downloader.session.close()
        self.temp_dir.cleanup()

    def test_partial_save_preserves_metadata_and_user_agent(self):
        expires = int(time.time()) + 3600
        cookie_cache._save_cookies_to_cache(
            self.downloader,
            [
                {
                    "name": "__ddgmark_",
                    "value": "first",
                    "domain": ".example.com",
                    "path": "/",
                    "expires": expires,
                    "secure": True,
                    "httpOnly": True,
                    "sameSite": "Strict",
                }
            ],
            domain="https://example.com/page",
            user_agent="Solved UA",
        )
        cookie_cache._save_cookies_to_cache(
            self.downloader,
            {"__ddgmark_": "updated", "site": "value"},
            domain="https://example.com/other",
        )

        payload = json.loads(
            (self.cache_dir / "cookie-example-com.json").read_text()
        )
        cookies_by_name = {cookie["name"]: cookie for cookie in payload["cookies"]}
        ddg_cookie = cookies_by_name["__ddgmark_"]
        self.assertEqual(ddg_cookie["value"], "updated")
        self.assertEqual(ddg_cookie["expires"], expires)
        self.assertTrue(ddg_cookie["secure"])
        self.assertTrue(ddg_cookie["httpOnly"])
        self.assertEqual(ddg_cookie["sameSite"], "Strict")
        self.assertEqual(payload["user_agent"], "Solved UA")

    def test_load_skips_expired_cookie_and_restores_metadata_and_ua(self):
        now = int(time.time())
        cache_file = self.cache_dir / "cookie-example-com.json"
        cache_file.write_text(
            json.dumps(
                {
                    "timestamp": now,
                    "user_agent": "Solved UA",
                    "cookies": [
                        {
                            "name": "expired",
                            "value": "old",
                            "domain": "example.com",
                            "path": "/",
                            "expires": now - 1,
                        },
                        {
                            "name": "active",
                            "value": "ok",
                            "domain": ".example.com",
                            "path": "/downloads",
                            "expires": now + 3600,
                            "secure": True,
                            "httpOnly": True,
                            "sameSite": "Lax",
                        },
                    ],
                }
            )
        )

        self.assertTrue(
            cookie_cache._load_cached_cookies(
                self.downloader,
                "https://example.com/page",
            )
        )
        self.assertEqual(self.downloader.session.headers["User-Agent"], "Solved UA")
        self.assertNotIn("expired", self.downloader.session.cookies)
        active = next(
            cookie
            for cookie in self.downloader.session.cookies
            if cookie.name == "active"
        )
        self.assertEqual(active.domain, ".example.com")
        self.assertEqual(active.path, "/downloads")
        self.assertTrue(active.secure)
        self.assertEqual(active.expires, now + 3600)
        self.assertTrue(active._rest["HttpOnly"])
        self.assertEqual(active._rest["SameSite"], "Lax")

    def test_authoritative_browser_save_removes_omitted_stale_cookie(self):
        cookie_cache._save_cookies_to_cache(
            self.downloader,
            {"intermediate": "stale", "keep": "old"},
            domain="example.com",
            user_agent="Old UA",
        )
        cookie_cache._save_cookies_to_cache(
            self.downloader,
            {"keep": "fresh"},
            domain="example.com",
            user_agent="Solved UA",
            replace=True,
        )

        payload = json.loads(
            (self.cache_dir / "cookie-example-com.json").read_text()
        )
        self.assertEqual(
            {cookie["name"]: cookie["value"] for cookie in payload["cookies"]},
            {"keep": "fresh"},
        )
        self.assertEqual(payload["user_agent"], "Solved UA")


if __name__ == "__main__":
    unittest.main()
