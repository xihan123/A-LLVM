#!/usr/bin/env python3
"""
locate_llvm.py — 从已解压的官方 NDK 解析其上游 LLVM 基线坐标。

读取 <ndk>/toolchains/llvm/prebuilt/<host>/ 下：
  - AndroidVersion.txt   第 1 行为 clang 版本（如 22.0.2 -> major 22），
                         第 2 行 `based on rNNNNNN`。
  - clang_source_info.md `Base revision: <sha>` = 精确的上游 llvm/llvm-project
    base commit，不包含 Android Clang 未上游化的下游补丁集合。
并交叉读取 <ndk>/source.properties 的 Pkg.Revision（内部版本号）。

取不到 base commit 即失败退出（禁止退回近似版本）。输出 JSON 到 stdout，
并在 GITHUB_OUTPUT 存在时写出 key=value。
"""

import argparse
import json
import os
import re
import sys

BASE_REV_RE = re.compile(r"Base revision:\s*\[?([0-9a-fA-F]{7,40})")
BASED_ON_RE = re.compile(r"based on\s+(r\S+)", re.IGNORECASE)


def log(*a):
    print(*a, file=sys.stderr)


def read_text(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except FileNotFoundError:
        return None


def parse_pkg_revision(ndk_dir):
    txt = read_text(os.path.join(ndk_dir, "source.properties"))
    if not txt:
        return None
    m = re.search(r"Pkg\.Revision\s*=\s*(\S+)", txt)
    return m.group(1) if m else None


def locate(ndk_dir, host):
    prebuilt = os.path.join(ndk_dir, "toolchains", "llvm", "prebuilt", host)
    if not os.path.isdir(prebuilt):
        log(f"[error] 找不到 prebuilt 目录：{prebuilt}")
        return None

    av = read_text(os.path.join(prebuilt, "AndroidVersion.txt")) or ""
    clang_version = None
    llvm_major = None
    clang_rev = None
    lines = [l.strip() for l in av.splitlines() if l.strip()]
    if lines:
        clang_version = lines[0]
        mm = re.match(r"(\d+)\.", clang_version)
        if mm:
            llvm_major = int(mm.group(1))
    m = BASED_ON_RE.search(av)
    if m:
        clang_rev = m.group(1)

    info = read_text(os.path.join(prebuilt, "clang_source_info.md")) or ""
    base_commit = None
    m = BASE_REV_RE.search(info)
    if m:
        base_commit = m.group(1)

    result = {
        "host": host,
        "clang_version": clang_version,
        "llvm_major": llvm_major,
        "clang_rev": clang_rev,
        "base_commit": base_commit,
        "pkg_revision": parse_pkg_revision(ndk_dir),
    }
    return result


def main():
    ap = argparse.ArgumentParser(description="解析 NDK 的上游 LLVM 基线坐标")
    ap.add_argument("--ndk-dir", required=True, help="已解压 NDK 根目录")
    ap.add_argument("--host", default="linux-x86_64")
    ap.add_argument(
        "--require-commit",
        action="store_true",
        default=True,
        help="取不到 base commit 即失败（默认开启）",
    )
    ap.add_argument(
        "--allow-missing-commit", dest="require_commit", action="store_false"
    )
    args = ap.parse_args()

    res = locate(args.ndk_dir, args.host)
    if res is None:
        return 2
    print(json.dumps(res, ensure_ascii=False, indent=2))

    if args.require_commit and not res.get("base_commit"):
        log(
            "[error] 未能从 clang_source_info.md 解析 Base revision，"
            "拒绝退回近似 LLVM 版本，构建终止。"
        )
        return 1

    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as f:
            for k, v in res.items():
                f.write(f"{k}={'' if v is None else v}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
