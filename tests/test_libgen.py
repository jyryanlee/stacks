import io
import logging
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import parse_qs, urlparse

import requests


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from stacks.downloader.direct import (  # noqa: E402
    _extract_url_filename,
    download_direct,
)
from stacks.downloader.html import parse_download_link_from_html  # noqa: E402
from stacks.downloader.mirrors import download_from_mirror  # noqa: E402
from stacks.downloader.orchestrator import (  # noqa: E402
    _shuffle_mirrors_for_attempt,
)
from stacks.downloader.sites.libgen import (  # noqa: E402
    is_libgen_domain,
    is_libgen_landing_url,
    parse_libgen_download_link,
)
from stacks.downloader.sources import filter_mirrors_for_policy  # noqa: E402


MD5 = "ea3e3f6df0acfcb1b2076ffb76b41a6e"
MIRROR_URL = f"https://libgen.li/ads.php?md5={MD5}"
FIXTURE_PATH = PROJECT_ROOT / "tests" / "fixtures" / "libgen_ads.html"


def _response(body, url=MIRROR_URL, content_type="text/html"):
    response = requests.Response()
    response.status_code = 200
    response.url = url
    response.headers["Content-Type"] = content_type
    response._content = body.encode("utf-8") if isinstance(body, str) else body
    response.encoding = "utf-8"
    response.raw = io.BytesIO(response._content)
    return response


class LibGenParserTests(unittest.TestCase):
    def setUp(self):
        self.downloader = SimpleNamespace(logger=Mock())
        self.fixture = FIXTURE_PATH.read_text(encoding="utf-8")

    def test_saved_layout_selects_validated_get_link(self):
        result = parse_libgen_download_link(
            self.downloader,
            self.fixture,
            MIRROR_URL,
            expected_md5=MD5,
        )

        parsed = urlparse(result)
        query = parse_qs(parsed.query)
        self.assertEqual(parsed.hostname, "libgen.li")
        self.assertEqual(parsed.path, "/get.php")
        self.assertEqual(query["md5"], [MD5])
        self.assertEqual(query["key"], ["FIXTUREKEY123"])

    def test_site_dispatch_does_not_fall_back_to_ads_navigation(self):
        result = parse_download_link_from_html(
            self.downloader,
            self.fixture,
            MD5,
            MIRROR_URL,
        )
        self.assertEqual(urlparse(result).path, "/get.php")

        invalid_html = f'<a href="{MIRROR_URL}#">self link</a>'
        self.assertIsNone(
            parse_download_link_from_html(
                self.downloader,
                invalid_html,
                MD5,
                MIRROR_URL,
            )
        )

    def test_rejects_wrong_hash_missing_key_and_foreign_host(self):
        wrong_hash = "0" * 32
        candidates = (
            f'<table id="main"><a href="/get.php?md5={wrong_hash}&key=OK">GET</a></table>',
            f'<table id="main"><a href="/get.php?md5={MD5}">GET</a></table>',
            (
                '<table id="main"><a href="/get.php?'
                f'md5={MD5}&md5={wrong_hash}&key=OK">'
                'GET</a></table>'
            ),
            (
                '<table id="main"><a href="/get.php?'
                f'md5={MD5}&key=OK&key=OTHER">'
                'GET</a></table>'
            ),
            f'<table id="main"><a href="https://libgen.li.example/get.php?md5={MD5}&key=OK">GET</a></table>',
            f'<table id="main"><a href="javascript:get.php?md5={MD5}&key=OK">GET</a></table>',
        )
        for html in candidates:
            with self.subTest(html=html):
                self.assertIsNone(
                    parse_libgen_download_link(
                        self.downloader,
                        html,
                        MIRROR_URL,
                        expected_md5=MD5,
                    )
                )

        valid_html = (
            f'<table id="main"><a href="/get.php?md5={MD5}&key=OK">'
            "GET</a></table>"
        )
        self.assertIsNone(
            parse_libgen_download_link(
                self.downloader,
                valid_html,
                MIRROR_URL,
                expected_md5=None,
            )
        )

    def test_domain_matching_is_exact(self):
        self.assertTrue(is_libgen_domain("https://libgen.li/ads.php"))
        self.assertTrue(is_libgen_domain("https://www.libgen.li/ads.php"))
        self.assertFalse(is_libgen_domain("https://libgen.li.example/ads.php"))
        self.assertFalse(is_libgen_domain("javascript://libgen.li/get.php"))
        self.assertFalse(is_libgen_domain("https://libgen.li:8443/ads.php"))
        self.assertFalse(is_libgen_domain("https://user@libgen.li/ads.php"))

    def test_landing_url_requires_ads_path_and_one_valid_hash(self):
        self.assertTrue(is_libgen_landing_url(MIRROR_URL))
        self.assertFalse(
            is_libgen_landing_url(
                f"{MIRROR_URL}&md5={'0' * 32}"
            )
        )
        self.assertFalse(
            is_libgen_landing_url(
                f"https://libgen.li/get.php?md5={MD5}"
            )
        )


class ExternalSourcePolicyTests(unittest.TestCase):
    def test_external_sources_are_opt_in_allowlisted_and_libgen_first(self):
        slow = {
            "url": "https://annas-archive.pk/slow_download/hash/0/4",
            "type": "slow_download",
        }
        libgen = {"url": MIRROR_URL, "type": "external_mirror"}
        zlib = {
            "url": "https://z-lib.fm/book/example",
            "type": "external_mirror",
        }
        unsupported = {
            "url": "https://advertising.example/download",
            "type": "external_mirror",
        }
        spoofed_by_type = {
            "url": "https://evil.example/download",
            "type": "slow_download",
        }
        spoofed_by_url_text = {
            "url": (
                "https://evil.example/fetch?"
                "next=/slow_download/hash/0/4"
            ),
            "type": "external_mirror",
        }
        wrong_type = {
            "url": "https://annas-archive.pk/slow_download/hash/0/4",
            "type": "external_mirror",
        }
        mirrors = [
            unsupported,
            zlib,
            spoofed_by_type,
            spoofed_by_url_text,
            wrong_type,
            slow,
            libgen,
        ]

        self.assertEqual(filter_mirrors_for_policy(mirrors, False), [slow])
        self.assertEqual(
            filter_mirrors_for_policy(mirrors, True),
            [slow, libgen],
        )

    def test_external_fallbacks_stay_after_slow_partners_when_shuffled(self):
        links = [
            {"url": MIRROR_URL, "type": "external_mirror"},
            {
                "url": "https://annas-archive.pk/slow_download/hash/0/4",
                "type": "slow_download",
            },
            {
                "url": "https://z-lib.fm/book/example",
                "type": "external_mirror",
            },
            {
                "url": "https://annas-archive.pk/slow_download/hash/1/4",
                "type": "slow_download",
            },
        ]

        ordered = _shuffle_mirrors_for_attempt(links)
        self.assertEqual(
            [link["type"] for link in ordered],
            [
                "slow_download",
                "slow_download",
                "external_mirror",
                "external_mirror",
            ],
        )
        self.assertEqual(
            [link["url"] for link in ordered[2:]],
            [MIRROR_URL, "https://z-lib.fm/book/example"],
        )


class LibGenDownloadFlowTests(unittest.TestCase):
    @staticmethod
    def _downloader_for_landing(landing_response):
        session = Mock()
        session.get.return_value = landing_response
        return SimpleNamespace(
            session=session,
            logger=Mock(),
            flaresolverr_url=None,
            load_cached_cookies=Mock(),
            parse_download_link_from_html=lambda html, md5, mirror_url: (
                parse_download_link_from_html(
                    SimpleNamespace(logger=Mock()),
                    html,
                    md5,
                    mirror_url,
                )
            ),
            download_direct=Mock(return_value=Path("/download/book.epub")),
        )

    def test_external_landing_page_resolves_get_at_download_time(self):
        fixture = FIXTURE_PATH.read_text(encoding="utf-8")
        landing_response = _response(fixture)
        landing_response.close = Mock(wraps=landing_response.close)
        final_path = Path("/download/book.epub")
        downloader = self._downloader_for_landing(landing_response)

        result = download_from_mirror(
            downloader,
            MIRROR_URL,
            "external_mirror",
            MD5,
            title="book.epub",
        )

        self.assertEqual(result, final_path)
        resolved_url = downloader.download_direct.call_args.args[0]
        self.assertEqual(urlparse(resolved_url).path, "/get.php")
        self.assertEqual(
            downloader.download_direct.call_args.kwargs["request_headers"],
            {"Referer": MIRROR_URL},
        )
        landing_response.close.assert_called_once_with()

    def test_redirected_landing_resolves_relative_get_on_final_origin(self):
        redirected_url = (
            f"https://www.libgen.li/ads.php?md5={MD5}"
        )
        relative_html = (
            '<table id="main"><a href="/get.php?'
            f'md5={MD5}&key=REDIRECTKEY">GET</a></table>'
        )
        downloader = self._downloader_for_landing(
            _response(relative_html, url=redirected_url)
        )

        result = download_from_mirror(
            downloader,
            MIRROR_URL,
            "external_mirror",
            MD5,
            title="book.epub",
        )

        self.assertEqual(result, Path("/download/book.epub"))
        resolved_url = downloader.download_direct.call_args.args[0]
        self.assertEqual(urlparse(resolved_url).hostname, "www.libgen.li")
        self.assertEqual(
            downloader.download_direct.call_args.kwargs["request_headers"],
            {"Referer": redirected_url},
        )

    def test_rejects_redirect_to_an_unapproved_landing_origin(self):
        relative_html = (
            '<table id="main"><a href="/get.php?'
            f'md5={MD5}&key=EVIL">GET</a></table>'
        )
        downloader = self._downloader_for_landing(
            _response(
                relative_html,
                url=f"https://evil.example/ads.php?md5={MD5}",
            )
        )

        result = download_from_mirror(
            downloader,
            MIRROR_URL,
            "external_mirror",
            MD5,
            title="book.epub",
        )

        self.assertIsNone(result)
        downloader.download_direct.assert_not_called()

    def test_get_php_uses_known_title_and_sends_referer(self):
        response = _response(
            b"book bytes",
            url=f"https://libgen.li/get.php?md5={MD5}&key=KEY",
            content_type="application/octet-stream",
        )
        session = Mock()
        session.get.return_value = response

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            downloader = SimpleNamespace(
                session=session,
                flaresolverr_url=None,
                download_read_timeout=300,
                output_dir=root / "download",
                incomplete_dir=root / "incomplete",
                logger=logging.getLogger("libgen-direct-test"),
                progress_callback=None,
                get_unique_filename=lambda path: path,
            )
            downloader.output_dir.mkdir()
            downloader.incomplete_dir.mkdir()

            result = download_direct(
                downloader,
                response.url,
                title="book.epub",
                request_headers={"Referer": MIRROR_URL},
            )

            self.assertEqual(result.name, "book.epub")
            self.assertEqual(result.read_bytes(), b"book bytes")
            self.assertEqual(
                session.get.call_args.kwargs["headers"],
                {"Referer": MIRROR_URL},
            )
            self.assertIsNone(_extract_url_filename(response.url))


if __name__ == "__main__":
    unittest.main()
