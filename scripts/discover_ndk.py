#!/usr/bin/env python3
"""
discover_ndk.py — 发现 Android NDK 版本（含 Beta/RC 预览版），去重后输出待构建矩阵。

数据源：GitHub Releases API（api.github.com/repos/android/ndk/releases）。
  - 数组按发布时间倒序，[0] 为含预览版的最新版。
  - 每个 release 的 body 内含 `ndkVersion "30.0.15729638"`（内部版本号）与下载直链。
  - prerelease 布尔字段 + tag 名（r30-beta2 / r29-rc1 / r27d）共同决定通道。

去重（tag + 资产完整性）：键 = 内部版本 + PATCHSET_VERSION（体现在 our_tag
里）。同名 Release 必须同时包含请求的全部 host 产物和 SHA256SUMS 才算完成；
残缺 Release 不静默跳过。不做 semver 比较，因为倒序发布 ≠ 版本从高到低。

仅用标准库，便于本地干跑：
    python scripts/discover_ndk.py --dry-run
在 GitHub Actions 中（设置了 GITHUB_TOKEN / GITHUB_REPOSITORY / GITHUB_OUTPUT）：
    python scripts/discover_ndk.py
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

NDK_RELEASES_API = "https://api.github.com/repos/android/ndk/releases"
NDK_DL_TMPL = "https://dl.google.com/android/repository/android-ndk-{tag}-{host_file}"
# host -> 下载文件后缀
HOST_FILE = {
    "linux-x86_64": "linux.zip",
    "windows-x86_64": "windows.zip",
    "darwin-x86_64": "darwin.dmg",
}
NDK_VERSION_RE = re.compile(r'ndkVersion\s+"([^"]+)"')
# r30 / r27d / r29 (base)  +  可选 -beta2 / -rc1 / -canary (suffix)
TAG_RE = re.compile(r"^(r\d+[a-z]?)(?:-(.+))?$")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def log(*a):
    print(*a, file=sys.stderr)


def gh_get(url, token=None, accept="application/vnd.github+json"):
    """返回 (status_code, parsed_json_or_None)。404 不抛异常。"""
    req = urllib.request.Request(url)
    req.add_header("Accept", accept)
    req.add_header("User-Agent", "ndk-llvm-patch-discover")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return 404, None
        log(f"[warn] HTTP {e.code} for {url}: {e.reason}")
        return e.code, None
    except urllib.error.URLError as e:
        log(f"[error] 网络错误 {url}: {e.reason}")
        raise


def load_config():
    path = os.path.join(REPO_ROOT, "config", "channels.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def load_patchset():
    # 优先环境变量，其次 config/patchset.env
    v = os.environ.get("PATCHSET_VERSION")
    if v:
        return v.strip()
    path = os.path.join(REPO_ROOT, "config", "patchset.env")
    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                k, _, val = line.partition("=")
                if k.strip() == "PATCHSET_VERSION":
                    return val.strip()
    except FileNotFoundError:
        pass
    return "p2"


def classify_channel(tag):
    if "-beta" in tag:
        return "beta"
    if "-rc" in tag:
        return "rc"
    if "-canary" in tag:
        return "canary"
    return "stable"


def compose_our_tag(tag, internal, patchset):
    """r30-beta2 + 30.0.15729638 + p1 -> r30-30.0.15729638-beta2-p1"""
    m = TAG_RE.match(tag)
    if not m:
        # 兜底：直接拼
        return f"{tag}-{internal}-{patchset}"
    base, suffix = m.group(1), m.group(2)
    parts = [base, internal]
    if suffix:
        parts.append(suffix)
    parts.append(patchset)
    return "-".join(parts)


def release_assets(our_tag, repo, token):
    """返回 Release 资产名集合；不存在或本地 dry-run 返回 None。"""
    if not repo or not token:
        return None
    url = f"https://api.github.com/repos/{repo}/releases/tags/{our_tag}"
    status, release = gh_get(url, token=token)
    if status == 404:
        return None
    if status != 200 or release is None:
        raise RuntimeError(f"查询本仓库 Release 失败：{our_tag} status={status}")
    return {asset.get("name", "") for asset in release.get("assets", [])}


def parse_hosts(value):
    hosts = []
    for host in value.split(","):
        host = host.strip()
        if not host:
            continue
        if host not in ("linux-x86_64", "windows-x86_64"):
            raise ValueError(
                f"不支持的 host={host}（当前仅 linux-x86_64 / windows-x86_64）"
            )
        if host not in hosts:
            hosts.append(host)
    if not hosts:
        raise ValueError("host 列表不能为空")
    return hosts


def expected_release_assets(our_tag, hosts):
    return {f"android-ndk-{our_tag}-{host}.zip" for host in hosts} | {"SHA256SUMS"}


def discover(args):
    cfg = load_config()
    patchset = load_patchset()
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")  # owner/repo
    top_n = args.top_n or cfg.get("top_n", 15)

    # 通道启用：CLI --channels 覆盖 config
    enabled = {}
    for name, c in cfg.get("channels", {}).items():
        enabled[name] = bool(c.get("enabled"))
    if args.channels:
        want = {x.strip() for x in args.channels.split(",") if x.strip()}
        enabled = {k: (k in want) for k in enabled}

    log(
        f"[info] patchset={patchset} top_n={top_n} "
        f"enabled_channels={[k for k,v in enabled.items() if v]} "
        f"repo={repo or '(none)'} token={'yes' if token else 'no'} "
        f"dry_run={args.dry_run} force={args.force}"
    )

    status, releases = gh_get(f"{NDK_RELEASES_API}?per_page={top_n}", token=token)
    if status != 200 or releases is None:
        log(f"[error] 拉取 releases 失败 status={status}")
        return 1, [], []

    hosts = parse_hosts(args.hosts)
    entries = []
    release_entries = []
    for rel in releases:
        if rel.get("draft"):
            continue
        tag = rel.get("tag_name", "")
        channel = classify_channel(tag)
        if not enabled.get(channel, False):
            log(f"[skip] {tag}: 通道 {channel} 未启用")
            continue
        body = rel.get("body") or ""
        m = NDK_VERSION_RE.search(body)
        if not m:
            log(f"[skip] {tag}: body 未找到 ndkVersion，无法确定内部版本号")
            continue
        internal = m.group(1)
        # 预览版内部号有时带 -betaN 后缀，去掉数字段外的通道后缀以规范化（通道已在 tag 体现）
        internal_clean = re.sub(r"-(beta|rc|canary)\d*$", "", internal)
        our_tag = compose_our_tag(tag, internal_clean, patchset)
        prerelease = bool(rel.get("prerelease")) or channel != "stable"

        assets = release_assets(our_tag, repo, token)
        if assets is not None and not args.force:
            missing = expected_release_assets(our_tag, hosts) - assets
            if missing:
                raise RuntimeError(
                    f"Release {our_tag} 已存在但资产不完整，缺少 {sorted(missing)}；"
                    "为保持发布不可变，请递增 patchset 后重新发布"
                )
            log(f"[dedup] {our_tag}: Release 及全部 host 资产已存在，跳过")
            continue

        for host in hosts:
            entries.append(
                {
                    "ndk_tag": tag,
                    "channel": channel,
                    "internal": internal_clean,
                    "our_tag": our_tag,
                    "prerelease": prerelease,
                    "host": host,
                    "download_url": NDK_DL_TMPL.format(
                        tag=tag, host_file=HOST_FILE[host]
                    ),
                    "patchset": patchset,
                }
            )
        if assets is None:
            release_entries.append(
                {
                    "ndk_tag": tag,
                    "channel": channel,
                    "internal": internal_clean,
                    "our_tag": our_tag,
                    "prerelease": prerelease,
                    "hosts": ",".join(hosts),
                    "patchset": patchset,
                }
            )
        else:
            log(f"[force] {our_tag}: 仅重建验证；既有 Release 不会被覆盖")
        log(
            f"[build] {our_tag}  (ndk={tag} channel={channel} internal={internal_clean})"
        )

    return 0, entries, release_entries


def main():
    ap = argparse.ArgumentParser(description="发现待构建的 Android NDK 版本")
    ap.add_argument(
        "--top-n", type=int, default=0, help="遍历最近 N 个 release（默认取 config）"
    )
    ap.add_argument(
        "--channels", default="", help="逗号分隔，覆盖启用通道，如 stable,beta"
    )
    ap.add_argument("--hosts", default="linux-x86_64", help="逗号分隔的 host 列表")
    ap.add_argument(
        "--force", action="store_true", help="忽略去重并重建验证；既有 Release 不覆盖"
    )
    ap.add_argument("--dry-run", action="store_true", help="仅打印，不写 GITHUB_OUTPUT")
    args = ap.parse_args()

    try:
        rc, entries, release_entries = discover(args)
    except (RuntimeError, ValueError) as e:
        log(f"[error] {e}")
        return 1
    matrix = {"include": entries}
    release_matrix = {"include": release_entries}
    # 人类可读
    log(f"[result] {len(entries)} 个待构建条目")
    log(f"[result] {len(release_entries)} 个待聚合发布条目")
    # 机器可读：stdout 输出矩阵 JSON
    print(json.dumps(matrix, ensure_ascii=False))

    # GitHub Actions 输出
    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out and not args.dry_run:
        with open(gh_out, "a", encoding="utf-8") as f:
            f.write(f"matrix={json.dumps(matrix)}\n")
            f.write(f"release_matrix={json.dumps(release_matrix)}\n")
            f.write(f"count={len(entries)}\n")
            f.write(f"has_work={'true' if entries else 'false'}\n")
            f.write(f"has_release_work={'true' if release_entries else 'false'}\n")
    return rc


if __name__ == "__main__":
    sys.exit(main())
