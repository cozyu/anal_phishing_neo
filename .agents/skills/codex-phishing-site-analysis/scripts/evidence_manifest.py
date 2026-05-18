#!/usr/bin/env python3
"""Create an evidence manifest with sha256 hashes for analysis artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path


SKIP_NAMES = {"evidence_manifest.json"}


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def command_version(cmd: list[str]) -> str | None:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5, check=False)
    except Exception:
        return None
    text = (result.stdout or result.stderr).strip().splitlines()
    return text[0] if text else None


def python_pkg_version(pkg: str) -> str | None:
    try:
        from importlib.metadata import version, PackageNotFoundError  # py3.8+
    except ImportError:
        return None
    try:
        return version(pkg)
    except PackageNotFoundError:
        return None
    except Exception:
        return None


def build_manifest(root: Path, target_url: str | None, domain: str | None, notes: str | None) -> dict:
    files = []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.name in SKIP_NAMES:
            continue
        stat = path.stat()
        files.append(
            {
                "path": str(path.relative_to(root)),
                "size": stat.st_size,
                "mtime_utc": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                "sha256": sha256_file(path),
            }
        )

    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "target_url": target_url,
        "domain": domain,
        "artifact_root": str(root.resolve()),
        "analyst_notes": notes,
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "tools": {
                "chromium": command_version(["chromium", "--version"]),
                "curl": command_version(["curl", "--version"]),
                "openssl": command_version(["openssl", "version"]),
                "fc-list_ko": "yes" if command_version(["fc-list", ":lang=ko"]) else "no",
            },
            "python_packages": {
                pkg: python_pkg_version(pkg)
                for pkg in (
                    "requests",
                    "python-whois",
                    "Pillow",
                    "pypdf",
                    "playwright",
                )
            },
        },
        "files": files,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact_dir", help="report/[report_slug] directory")
    parser.add_argument("--target-url")
    parser.add_argument("--domain")
    parser.add_argument("--notes")
    parser.add_argument("--output", default="evidence_manifest.json")
    args = parser.parse_args()

    root = Path(args.artifact_dir)
    if not root.exists() or not root.is_dir():
        raise SystemExit(f"artifact_dir is not a directory: {root}")

    manifest = build_manifest(root, args.target_url, args.domain, args.notes)
    output = Path(args.output)
    if not output.is_absolute():
        output = root / output
    output.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(output)


if __name__ == "__main__":
    main()
