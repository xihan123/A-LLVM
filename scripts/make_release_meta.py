#!/usr/bin/env python3
"""
make_release_meta.py — 写入包内可追溯元数据。

- 在 <ndk>/source.properties 追加 Ndkp.* 标识（保留官方 Pkg.Revision 不动）；
- 写 <ndk>/NDKP-build-info.json 与 <ndk>/NDKP-patch-report.json。

字段主要来自命令行/环境变量；缺失字段留空。SHA256SUMS 在打包后由工作流用
`sha256sum *.zip` 生成，不在此脚本内。
"""

import argparse
import json
import os
import shutil
import sys
from datetime import datetime, timezone


def log(*a):
    print(*a, file=sys.stderr)


def append_source_properties(ndk_dir, fields):
    path = os.path.join(ndk_dir, "source.properties")
    lines = []
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    # 移除旧的 Ndkp.* 以便幂等
    lines = [l for l in lines if not l.strip().startswith("Ndkp.")]
    for k, v in fields.items():
        lines.append(f"Ndkp.{k} = {v}")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    log(
        f"[ok] 更新 source.properties（保留 Pkg.Revision，追加 {len(fields)} 个 Ndkp.*）"
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ndk-dir", required=True)
    ap.add_argument("--our-tag", default=os.environ.get("OUR_TAG", ""))
    ap.add_argument("--ndk-tag", default=os.environ.get("NDK_TAG", ""))
    ap.add_argument("--internal", default=os.environ.get("INTERNAL", ""))
    ap.add_argument("--channel", default=os.environ.get("CHANNEL", ""))
    ap.add_argument("--host", default=os.environ.get("HOST", "linux-x86_64"))
    ap.add_argument("--patchset", default=os.environ.get("PATCHSET_VERSION", "p1"))
    ap.add_argument("--llvm-major", default=os.environ.get("LLVM_MAJOR", ""))
    ap.add_argument("--clang-rev", default=os.environ.get("CLANG_REV", ""))
    ap.add_argument("--base-commit", default=os.environ.get("BASE_COMMIT", ""))
    ap.add_argument(
        "--overlay-applied", default=os.environ.get("OVERLAY_APPLIED", "false")
    )
    ap.add_argument(
        "--overlay-source",
        default=os.environ.get("OVERLAY_SOURCE", "GPL-3.0 IR obfuscation overlay"),
    )
    ap.add_argument("--repo", default=os.environ.get("GITHUB_REPOSITORY", ""))
    ap.add_argument("--run-url", default=os.environ.get("RUN_URL", ""))
    args = ap.parse_args()

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    overlay_applied = str(args.overlay_applied).lower() in ("1", "true", "yes")

    append_source_properties(
        args.ndk_dir,
        {
            "Flavor": "custom-obfuscation",
            "Patchset": args.patchset,
            "OurTag": args.our_tag,
            "LlvmCommit": args.base_commit,
            "Upstream": f"https://github.com/{args.repo}" if args.repo else "",
            "Official": "false",
        },
    )

    build_info = {
        "generated_by": "ndk-obfuscation-workflow",
        "generated_at": now,
        "official_google_build": False,
        "our_tag": args.our_tag,
        "ndk_alias": args.ndk_tag,
        "pkg_revision": args.internal,
        "channel": args.channel,
        "host": args.host,
        "android_clang_rev": args.clang_rev,
        "llvm_major": args.llvm_major,
        "llvm_upstream_commit": args.base_commit,
        "patchset": args.patchset,
        "obfuscation_overlay_applied": overlay_applied,
        "obfuscation_source": args.overlay_source if overlay_applied else None,
        "build_run": args.run_url,
        "source_date_epoch": int(os.environ.get("SOURCE_DATE_EPOCH", "0")),
    }
    with open(
        os.path.join(args.ndk_dir, "NDKP-build-info.json"), "w", encoding="utf-8"
    ) as f:
        json.dump(build_info, f, ensure_ascii=False, indent=2)
    log("[ok] 写入 NDKP-build-info.json")

    patch_report = {
        "overlay_applied": overlay_applied,
        "llvm_major": args.llvm_major,
        "source": args.overlay_source if overlay_applied else None,
        "note": (
            "一期混淆 overlay（字符串加密 / 控制流平坦化 / 间接化 / 常量加密）"
            if overlay_applied
            else "无混淆 overlay（原样重打包）"
        ),
    }
    with open(
        os.path.join(args.ndk_dir, "NDKP-patch-report.json"), "w", encoding="utf-8"
    ) as f:
        json.dump(patch_report, f, ensure_ascii=False, indent=2)
    log("[ok] 写入 NDKP-patch-report.json")

    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    licenses_dir = os.path.join(args.ndk_dir, "LICENSES")
    os.makedirs(licenses_dir, exist_ok=True)
    license_files = {
        "NDKP-GPL-3.0.txt": os.path.join(repo_root, "LICENSE"),
        "LLVM-UIUC.txt": os.path.join(repo_root, "LICENSES", "LLVM-UIUC.txt"),
        "LIBTOMCRYPT-UNLICENSE.txt": os.path.join(
            repo_root, "LICENSES", "LIBTOMCRYPT-UNLICENSE.txt"),
    }
    for name, source in license_files.items():
        shutil.copyfile(source, os.path.join(licenses_dir, name))
    log(f"[ok] 写入 LICENSES/（{len(license_files)} 个许可文件）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
