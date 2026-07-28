import sys
import unittest
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from stacks.coordinator.download_worker import (  # noqa: E402
    _build_mirrors_to_try,
    _mirror_domain,
    _uses_assigned_domain_claim,
)


class MirrorFallbackTests(unittest.TestCase):
    def test_preserves_distinct_slow_partner_urls_on_same_domain(self):
        mirrors = [
            {
                "url": "https://annas-archive.pk/slow_download/hash/0/1",
                "type": "slow_download",
                "text": "Slow Partner Server #2",
            },
            {
                "url": "https://annas-archive.pk/slow_download/hash/0/2",
                "type": "slow_download",
                "text": "Slow Partner Server #3",
            },
            {
                "url": "https://annas-archive.pk/slow_download/hash/0/3",
                "type": "slow_download",
                "text": "Slow Partner Server #4",
            },
        ]
        assigned = mirrors[1]

        ordered = _build_mirrors_to_try(assigned, mirrors)

        self.assertEqual(
            [mirror["url"] for mirror in ordered],
            [
                assigned["url"],
                mirrors[0]["url"],
                mirrors[2]["url"],
            ],
        )
        self.assertTrue(
            all(
                _mirror_domain(mirror) == "annas-archive.pk"
                for mirror in ordered
            )
        )

    def test_deduplicates_only_the_same_url(self):
        assigned = {
            "url": "https://annas-archive.pk/slow_download/hash/0/4",
            "type": "slow_download",
        }

        ordered = _build_mirrors_to_try(
            assigned,
            [
                dict(assigned),
                {
                    "url": "https://annas-archive.pk/slow_download/hash/0/5",
                    "type": "slow_download",
                },
            ],
        )

        self.assertEqual(len(ordered), 2)

    def test_external_assignment_still_checks_anna_routes_first(self):
        slow = {
            "url": "https://annas-archive.pk/slow_download/hash/0/4",
            "type": "slow_download",
        }
        external = {
            "url": (
                "https://libgen.li/ads.php?"
                "md5=ea3e3f6df0acfcb1b2076ffb76b41a6e"
            ),
            "type": "external_mirror",
        }

        ordered = _build_mirrors_to_try(
            external,
            [slow, external],
        )

        self.assertEqual(ordered, [slow, external])

    def test_reuses_assigned_lock_only_for_the_same_domain(self):
        self.assertTrue(
            _uses_assigned_domain_claim(
                "annas-archive.pk",
                "annas-archive.pk",
                True,
            )
        )
        self.assertFalse(
            _uses_assigned_domain_claim(
                "other.example",
                "annas-archive.pk",
                True,
            )
        )
        self.assertFalse(
            _uses_assigned_domain_claim(
                "annas-archive.pk",
                "annas-archive.pk",
                False,
            )
        )


if __name__ == "__main__":
    unittest.main()
