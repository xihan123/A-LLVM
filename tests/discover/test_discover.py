import importlib.util
import pathlib
import types
import unittest
from unittest import mock

SCRIPT = pathlib.Path(__file__).parents[2] / "scripts" / "discover_ndk.py"
SPEC = importlib.util.spec_from_file_location("discover_ndk", SCRIPT)
discover_ndk = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(discover_ndk)


class DiscoverReleaseTest(unittest.TestCase):
    def test_latest_release_uses_requested_channel(self):
        releases = [
            {
                "draft": False,
                "tag_name": "r30-beta2",
                "body": 'ndkVersion "30.0.15729638-beta2"',
            },
            {
                "draft": False,
                "tag_name": "r29",
                "body": 'ndkVersion "29.0.14206865"',
            },
        ]
        with mock.patch.object(discover_ndk, "gh_get", return_value=(200, releases)):
            self.assertEqual(
                discover_ndk.latest_release("stable"),
                {
                    "ndk_tag": "r29",
                    "internal": "29.0.14206865",
                    "channel": "stable",
                },
            )

    def test_hosts_are_validated_and_deduplicated(self):
        self.assertEqual(
            discover_ndk.parse_hosts("linux-x86_64,linux-x86_64,windows-x86_64"),
            ["linux-x86_64", "windows-x86_64"],
        )
        with self.assertRaises(ValueError):
            discover_ndk.parse_hosts("darwin-x86_64")

    def test_release_assets_distinguish_absent_and_existing(self):
        with mock.patch.object(discover_ndk, "gh_get", return_value=(404, None)):
            self.assertIsNone(discover_ndk.release_assets("tag", "owner/repo", "token"))
        release = {"assets": [{"name": "a.zip"}, {"name": "SHA256SUMS"}]}
        with mock.patch.object(discover_ndk, "gh_get", return_value=(200, release)):
            self.assertEqual(
                discover_ndk.release_assets("tag", "owner/repo", "token"),
                {"a.zip", "SHA256SUMS"},
            )

    def test_expected_assets_cover_every_host(self):
        self.assertEqual(
            discover_ndk.expected_release_assets("r29-p1", ["linux-x86_64"]),
            {"android-ndk-r29-p1-linux-x86_64.zip", "SHA256SUMS"},
        )

    def test_discovery_emits_host_builds_and_one_release(self):
        args = types.SimpleNamespace(
            top_n=0,
            channels="stable",
            hosts="linux-x86_64,windows-x86_64",
            force=False,
            dry_run=False,
        )
        upstream = [
            {
                "draft": False,
                "tag_name": "r29",
                "prerelease": False,
                "body": 'ndkVersion "29.0.14206865"',
            }
        ]
        with (
            mock.patch.object(
                discover_ndk,
                "load_config",
                return_value={
                    "top_n": 15,
                    "channels": {"stable": {"enabled": True}},
                },
            ),
            mock.patch.object(discover_ndk, "load_patchset", return_value="p2"),
            mock.patch.object(
                discover_ndk,
                "gh_get",
                side_effect=[
                    (200, upstream),
                    (404, None),
                ],
            ),
            mock.patch.dict(
                discover_ndk.os.environ,
                {
                    "GITHUB_TOKEN": "token",
                    "GITHUB_REPOSITORY": "owner/repo",
                },
                clear=True,
            ),
        ):
            rc, builds, releases = discover_ndk.discover(args)

        self.assertEqual(rc, 0)
        self.assertEqual(
            [entry["host"] for entry in builds],
            [
                "linux-x86_64",
                "windows-x86_64",
            ],
        )
        self.assertEqual(len(releases), 1)
        self.assertEqual(releases[0]["our_tag"], "r29-29.0.14206865-p2")


if __name__ == "__main__":
    unittest.main()
