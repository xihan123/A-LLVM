#!/usr/bin/env python3
"""Sync the two LLVM overlay directories without touching unchanged mtimes."""

import argparse
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile


MANIFEST = ".ndkp-overlay-files.json"
DIRECTORIES = (
    ("Transforms/Obfuscation", "llvm/lib/Transforms/Obfuscation"),
    ("include", "llvm/include/llvm/Transforms/Obfuscation"),
)


def checked_path(path):
    """Reject symlinks, Windows junctions and non-regular files before I/O."""
    for component in reversed((path, *path.parents)):
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0)
                & stat.FILE_ATTRIBUTE_REPARSE_POINT):
            raise ValueError(f"links are not allowed: {component}")
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise ValueError(f"not a regular file or directory: {component}")
    return path


def checked_names(names):
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        raise ValueError("overlay manifest files must be a list of paths")
    for name in names:
        # Use portable relative paths, including when validating a Windows cache.
        if name.casefold() == MANIFEST.casefold() or any(
            not part or part.rstrip(" .") != part
            or any(c in '<>:"\\|?*' or ord(c) < 32 for c in part)
            or re.match(r"^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)",
                        part, re.IGNORECASE)
            for part in name.split("/")
        ):
            raise ValueError(f"unsafe overlay path: {name!r}")
    if len({os.path.normcase(n) for n in names}) != len(names):
        raise ValueError("duplicate overlay paths")
    return set(names)


def source_files(source):
    checked_path(source)
    if not source.exists():
        return set()
    files = []

    def visit(directory):
        for entry in directory.iterdir():
            checked_path(entry)
            if entry.is_dir():
                visit(entry)
            else:
                files.append(entry.relative_to(source).as_posix())

    visit(source)
    return checked_names(files)


def read_manifest(destination):
    manifest = checked_path(destination / MANIFEST)
    if not manifest.exists():
        return set()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("version") != 1:
        raise ValueError(f"unsupported overlay manifest: {manifest}")
    return checked_names(data.get("files"))


def write_changed(path, content):
    if path.exists() and path.read_bytes() == content:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    # A fresh file gets the current mtime and cannot overwrite a hardlink target.
    descriptor, name = tempfile.mkstemp(dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def write_manifest(destination, files):
    content = json.dumps({"version": 1, "files": sorted(files)}, indent=2) + "\n"
    write_changed(destination / MANIFEST, content.encode("utf-8"))


def sync_overlay(llvm_src, overlay):
    llvm_src = checked_path(Path(os.path.abspath(llvm_src)))
    overlay = checked_path(Path(os.path.abspath(overlay)))
    if not checked_path(llvm_src / "llvm").is_dir():
        raise ValueError(f"not an llvm-project source tree: {llvm_src}")
    if not checked_path(overlay / DIRECTORIES[0][0]).is_dir():
        raise ValueError(f"missing overlay sources: {overlay}")

    plans = []
    for source_name, destination_name in DIRECTORIES:
        source = overlay / source_name
        destination = checked_path(llvm_src / destination_name)
        if source.is_relative_to(destination) or destination.is_relative_to(source):
            raise ValueError("overlay source and destination must not overlap")
        current = source_files(source)
        # A case-only rename on Windows must not delete the just-synced file.
        current_names = {os.path.normcase(name): name for name in current}
        previous = {current_names.get(os.path.normcase(name), name)
                    for name in read_manifest(destination)}
        for name in current | previous:
            path = checked_path(destination / name)
            if path.exists() and not path.is_file():
                raise ValueError(f"expected an overlay file: {path}")
        plans.append((source, destination, current, previous))

    # Validate both trees before any writes or deletions.
    for source, destination, current, previous in plans:
        if not current and not previous and not destination.exists():
            continue
        # Record new paths first so an interrupted copy still tracks its files.
        write_manifest(destination, current | previous)
        for name in sorted(current):
            write_changed(destination / name, (source / name).read_bytes())
        for name in sorted(previous - current):
            (destination / name).unlink(missing_ok=True)
        write_manifest(destination, current)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llvm-src", required=True)
    parser.add_argument("--overlay", required=True)
    args = parser.parse_args()
    try:
        sync_overlay(args.llvm_src, args.overlay)
    except (OSError, ValueError) as error:
        print(f"[error] overlay sync failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
