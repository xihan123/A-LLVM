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

    def test_compose_our_tag_patchset_optional(self):
        # 默认（空 patchset）：tag 直接对应 NDK 版本，无后缀。
        self.assertEqual(
            discover_ndk.compose_our_tag("r30-beta2", "30.0.15729638", ""),
            "r30-30.0.15729638-beta2",
        )
        self.assertEqual(
            discover_ndk.compose_our_tag("r29", "29.0.14206865", ""),
            "r29-29.0.14206865",
        )
        # 机制仍在：显式设 patchset 时追加后缀。
        self.assertEqual(
            discover_ndk.compose_our_tag("r30-beta2", "30.0.15729638", "p2"),
            "r30-30.0.15729638-beta2-p2",
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
            mock.patch.object(discover_ndk, "load_patchset", return_value=""),
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
        # 默认无 patchset：our_tag 直接对应 NDK 版本，不带 -p2 后缀。
        self.assertEqual(releases[0]["our_tag"], "r29-29.0.14206865")

    def test_discovery_takes_only_latest_per_channel(self):
        args = types.SimpleNamespace(
            top_n=0,
            channels="stable,beta",
            hosts="linux-x86_64",
            force=False,
            dry_run=False,
        )
        # 倒序：每个通道首个命中即最新；同通道更旧的 r28c / r29-beta3 必须被跳过。
        upstream = [
            {
                "draft": False,
                "tag_name": "r30-beta2",
                "prerelease": True,
                "body": 'ndkVersion "30.0.15729638"',
            },
            {
                "draft": False,
                "tag_name": "r29",
                "prerelease": False,
                "body": 'ndkVersion "29.0.14206865"',
            },
            {
                "draft": False,
                "tag_name": "r29-beta3",
                "prerelease": True,
                "body": 'ndkVersion "29.0.13846066"',
            },
            {
                "draft": False,
                "tag_name": "r28c",
                "prerelease": False,
                "body": 'ndkVersion "28.2.13676358"',
            },
        ]
        with (
            mock.patch.object(
                discover_ndk,
                "load_config",
                return_value={
                    "top_n": 15,
                    "channels": {
                        "stable": {"enabled": True},
                        "beta": {"enabled": True},
                    },
                },
            ),
            mock.patch.object(discover_ndk, "load_patchset", return_value="p2"),
            mock.patch.object(
                discover_ndk,
                "gh_get",
                side_effect=[
                    (200, upstream),
                    (404, None),  # 去重查询：r30-beta2 未发布
                    (404, None),  # 去重查询：r29 未发布
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
        # 每通道仅最新一版：beta=r30-beta2、stable=r29；旧版被跳过。
        self.assertEqual([entry["ndk_tag"] for entry in builds], ["r30-beta2", "r29"])
        self.assertEqual(
            {entry["ndk_tag"] for entry in releases}, {"r30-beta2", "r29"}
        )


if __name__ == "__main__":
    unittest.main()
