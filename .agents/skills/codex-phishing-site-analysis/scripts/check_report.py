#!/usr/bin/env python3
"""Pre-PDF report.html completeness check.

Validates that the report has all standard chapters, no template placeholders
remain, all <img src=> targets exist locally, and verdict/meta blocks are
filled. Exit code is non-zero on failure so it can be used in pipelines.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


REQUIRED_CHAPTERS = [
    (1, "사기 패턴 발췌"),
    (2, "핵심 요약"),
    (3, "공유 인프라"),
    (4, "공격자 활동 타임라인"),
    (5, "운영자 식별"),
    (6, "사이트"),  # 사이트/시스템 식별자
    (7, "광고"),    # 광고/추적 픽셀
    (8, "개인정보"),  # 개인정보·금융정보
    (9, "JavaScript"),
    (10, "콘텐츠 위장"),
    (11, "추정 공격 시나리오"),
    (12, "인프라 IOC"),
    (13, "위험성"),
    (14, "권고 조치"),
    (15, "분석 산출물"),
]

PLACEHOLDERS = [
    "__DOMAIN__",
    "__TITLE__",
    "__DATE__",
    "__FULL_ENTRY_URL__",
    "__VERDICT_HEADLINE__",
    "__VERDICT_BODY__",
    "__SLUG__",
]


def find_chapters(html: str) -> dict[int, str]:
    """Return {chapter_no: heading_text} for every <h2>n. ...</h2> found."""
    found: dict[int, str] = {}
    for m in re.finditer(r"<h2[^>]*>\s*(\d+)\.\s*([^<]+?)\s*</h2>", html):
        no = int(m.group(1))
        text = m.group(2).strip()
        found.setdefault(no, text)  # keep first occurrence
    return found


def find_appendix(html: str) -> bool:
    return bool(re.search(r"<h2[^>]*>\s*부록\s*A", html))


def find_images(html: str) -> list[str]:
    return re.findall(r'<img[^>]+src="([^"]+)"', html)


def check(report_html: Path, strict: bool) -> int:
    if not report_html.exists():
        print(f"  ✗ report.html not found: {report_html}", file=sys.stderr)
        return 2

    html = report_html.read_text(encoding="utf-8", errors="replace")
    root = report_html.parent
    errors: list[str] = []
    warnings: list[str] = []

    # 1) Placeholders left
    for tag in PLACEHOLDERS:
        if tag in html:
            errors.append(f"placeholder still present: {tag}")

    # 2) Required chapters
    chapters = find_chapters(html)
    for no, keyword in REQUIRED_CHAPTERS:
        if no not in chapters:
            errors.append(f"missing chapter {no} ({keyword})")
        elif keyword not in chapters[no]:
            warnings.append(
                f"chapter {no} heading does not contain expected keyword "
                f"'{keyword}': got '{chapters[no]}'"
            )

    # 3) Appendix A
    if not find_appendix(html):
        errors.append("missing 부록 A (full-page screenshots)")

    # 4) Verdict block
    if 'class="verdict"' not in html:
        errors.append("verdict block (.verdict) missing")

    # 5) Images exist
    for src in find_images(html):
        if src.startswith(("http://", "https://", "data:")):
            continue
        path = (root / src).resolve()
        if not path.is_file():
            errors.append(f"image not found: {src}")

    # 6) Chapter heading layout — warn if any chapter <2 subsections expected (loose)
    for no in (4, 5, 7, 8, 10, 13):
        if no in chapters and html.count(f"<h3>{no}.") < 2:
            warnings.append(f"chapter {no} has fewer than 2 subsections (<h3>{no}.…)")

    # Report
    print(f"  chapters found: {sorted(chapters.keys())}")
    for w in warnings:
        print(f"  ! warning: {w}")
    for e in errors:
        print(f"  ✗ error: {e}", file=sys.stderr)
    if errors:
        return 1
    if strict and warnings:
        return 1
    print("  ✓ report.html passes completeness check")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report_html", help="path to report/<slug>/report.html")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="treat warnings as errors (non-zero exit)",
    )
    args = parser.parse_args()

    sys.exit(check(Path(args.report_html), args.strict))


if __name__ == "__main__":
    main()
