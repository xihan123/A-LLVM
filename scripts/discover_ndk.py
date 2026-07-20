#!/usr/bin/env python3
"""
discover_ndk.py — 发现 Android NDK 版本（含 Beta/RC 预览版），去重后输出待构建矩阵。

数据源：GitHub Releases API（api.github.com/repos/android/ndk/releases）。
  - 数组按发布时间倒序，[0] 为含预览版的最新版。
  - 每个 release 的 body 内含 `ndkVersion "30.0.15729638"`（内部版本号）与下载直链。
  - prerelease 布尔字段 + tag 名（r30-beta2 / r29-rc1 / r27d）共同决定通道。

每个启用通道只取最新一个可用版本（倒序首个命中即该通道最新），不回填整个
top_n 窗口的历史版本；top_n 仅用于向后看足够远、覆盖到各通道各自的最新版
（通道按时间交错发布，最新 stable 可能排在若干 beta 之后）。

去重（tag + 资产完整性）：键 = 内部版本 + PATCHSET_VERSION（体现在 our_tag
里）。同名 Release 必须同时包含请求的全部 host 产物和 SHA256SUMS 才算完成；
残缺 Release 不静默跳过。不做 semver 比较，因为倒序发布 ≠ 版本从高到低。

定时任务用通道优先级（--channel-priority beta,stable）：按给定顺序取第一个“有待
构建条目”的通道，命中即锁定并停止降级；beta 已构建（或不存在）则降级到 stable，
两者都无待构建条目则本次不构建。rc/canary 不在优先级内，故定时任务不会构建它们。
与 --channels 互斥（后者仍保留多通道行为，供手动 workflow_dispatch 使用）。

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
    # 默认不带 patchset 后缀：our_tag 直接对应 NDK 版本（如 r30-30.0.15729638-beta2）。
    # 仅当需要就同一 NDK 版本、以变化的 overlay 重新发布时，才设 PATCHSET_VERSION=p1/p2…
    return ""


def classify_channel(tag):
    if "-beta" in tag:
        return "beta"
    if "-rc" in tag:
        return "rc"
    if "-canary" in tag:
        return "canary"
    return "stable"


def latest_release(channel, token=None):
    top_n = load_config().get("top_n", 15)
    status, releases = gh_get(f"{NDK_RELEASES_API}?per_page={top_n}", token=token)
    if status != 200 or releases is None:
        raise RuntimeError(f"拉取 NDK releases 失败 status={status}")
    for rel in releases:
        tag = rel.get("tag_name", "")
        if rel.get("draft") or classify_channel(tag) != channel:
            continue
        match = NDK_VERSION_RE.search(rel.get("body") or "")
        if match:
            return {
                "ndk_tag": tag,
                "internal": re.sub(
                    r"-(beta|rc|canary)\d*$", "", match.group(1)
                ),
                "channel": channel,
            }
    raise RuntimeError(f"最近 {top_n} 个 NDK release 中没有可用的 {channel} 版本")


def compose_our_tag(tag, internal, patchset):
    """r30-beta2 + 30.0.15729638 [+ p1] -> r30-30.0.15729638-beta2[-p1]

    patchset 为空（默认）时不追加后缀，our_tag 直接对应 NDK 版本。"""
    m = TAG_RE.match(tag)
    if not m:
        # 兜底：直接拼
        return f"{tag}-{internal}-{patchset}" if patchset else f"{tag}-{internal}"
    base, suffix = m.group(1), m.group(2)
    parts = [base, internal]
    if suffix:
        parts.append(suffix)
    if patchset:
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


def _collect_for_channels(releases, enabled, hosts, patchset, repo, token, force):
    """遍历 releases，对每个启用通道取最新一版（倒序首个命中即最新）。

    返回 (entries, release_entries)。去重/资产完整性语义见文件头。"""
    entries = []
    release_entries = []
    # 每个通道只取最新（列表按发布时间倒序，首个命中即该通道最新可用版本）。
    seen_channels = set()
    for rel in releases:
        if rel.get("draft"):
            continue
        tag = rel.get("tag_name", "")
        channel = classify_channel(tag)
        if not enabled.get(channel, False):
            log(f"[skip] {tag}: 通道 {channel} 未启用")
            continue
        if channel in seen_channels:
            log(f"[skip] {tag}: 通道 {channel} 已取到更新版本")
            continue
        body = rel.get("body") or ""
        m = NDK_VERSION_RE.search(body)
        if not m:
            log(f"[skip] {tag}: body 未找到 ndkVersion，无法确定内部版本号")
            continue
        # 命中该通道最新可用版本：标记后，同通道更旧的版本一律跳过——即便本版本
        # 稍后因去重被跳过，也不回落到旧版本（去重语义见文件头）。
        seen_channels.add(channel)
        internal = m.group(1)
        # 预览版内部号有时带 -betaN 后缀，去掉数字段外的通道后缀以规范化（通道已在 tag 体现）
        internal_clean = re.sub(r"-(beta|rc|canary)\d*$", "", internal)
        our_tag = compose_our_tag(tag, internal_clean, patchset)
        prerelease = bool(rel.get("prerelease")) or channel != "stable"

        assets = release_assets(our_tag, repo, token)
        if assets is not None and not force:
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

    return entries, release_entries


def discover(args):
    cfg = load_config()
    patchset = load_patchset()
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")  # owner/repo
    top_n = args.top_n or cfg.get("top_n", 15)
    hosts = parse_hosts(args.hosts)

    # 定时优先级：按顺序取第一个“有待构建条目”的通道（如 beta,stable）。与 --channels
    # 互斥；命中即锁定，不再考虑更低优先级。未列入优先级的通道（rc/canary）被排除。
    priority = [
        c.strip()
        for c in getattr(args, "channel_priority", "").split(",")
        if c.strip()
    ]

    # 通道启用：CLI --channels 覆盖 config
    enabled = {}
    for name, c in cfg.get("channels", {}).items():
        enabled[name] = bool(c.get("enabled"))
    if args.channels:
        want = {x.strip() for x in args.channels.split(",") if x.strip()}
        enabled = {k: (k in want) for k in enabled}

    log(
        f"[info] patchset={patchset} top_n={top_n} "
        + (
            f"priority={','.join(priority)}"
            if priority
            else f"enabled_channels={[k for k,v in enabled.items() if v]}"
        )
        + f" repo={repo or '(none)'} token={'yes' if token else 'no'} "
        f"dry_run={args.dry_run} force={args.force}"
    )

    status, releases = gh_get(f"{NDK_RELEASES_API}?per_page={top_n}", token=token)
    if status != 200 or releases is None:
        log(f"[error] 拉取 releases 失败 status={status}")
        return 1, [], []

    if priority:
        # 优先级模式（定时任务）：beta 优先，无待构建条目则降级 stable，仍无则停止。
        # 只锁定第一个产出条目的通道；config 的 enabled 在此模式下不再限制优先通道。
        for ch in priority:
            entries, release_entries = _collect_for_channels(
                releases, {ch: True}, hosts, patchset, repo, token, args.force
            )
            if entries:
                log(
                    f"[priority] 命中通道 {ch}：{len(entries)} 个待构建条目，"
                    "锁定并停止降级"
                )
                return 0, entries, release_entries
            log(f"[priority] 通道 {ch} 无待构建条目，降级到下一优先级")
        log("[priority] 所有优先通道均无待构建条目，本次不构建")
        return 0, [], []

    entries, release_entries = _collect_for_channels(
        releases, enabled, hosts, patchset, repo, token, args.force
    )
    return 0, entries, release_entries


def main():
    ap = argparse.ArgumentParser(description="发现待构建的 Android NDK 版本")
    ap.add_argument(
        "--latest-channel",
        choices=("stable", "beta", "rc", "canary"),
        help="输出指定通道的最新版本，并写入 GITHUB_ENV",
    )
    ap.add_argument(
        "--top-n", type=int, default=0, help="遍历最近 N 个 release（默认取 config）"
    )
    ap.add_argument(
        "--channels", default="", help="逗号分隔，覆盖启用通道，如 stable,beta"
    )
    ap.add_argument(
        "--channel-priority",
        default="",
        help="逗号分隔的通道优先级（定时任务用）：按顺序取第一个有待构建条目的通道，"
        "命中即锁定并停止降级，如 beta,stable。与 --channels 互斥",
    )
    ap.add_argument("--hosts", default="linux-x86_64", help="逗号分隔的 host 列表")
    ap.add_argument(
        "--force", action="store_true", help="忽略去重并重建验证；既有 Release 不覆盖"
    )
    ap.add_argument("--dry-run", action="store_true", help="仅打印，不写 GITHUB_OUTPUT")
    args = ap.parse_args()

    if args.latest_channel:
        try:
            latest = latest_release(
                args.latest_channel,
                token=os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"),
            )
        except RuntimeError as e:
            log(f"[error] {e}")
            return 1
        print(json.dumps(latest, ensure_ascii=False))
        gh_env = os.environ.get("GITHUB_ENV")
        if gh_env:
            with open(gh_env, "a", encoding="utf-8") as f:
                f.write(f"NDK_TAG={latest['ndk_tag']}\n")
                f.write(f"INTERNAL={latest['internal']}\n")
        return 0

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
