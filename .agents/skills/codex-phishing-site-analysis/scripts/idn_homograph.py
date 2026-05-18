#!/usr/bin/env python3
"""IDN/homograph analyzer for a phishing target domain.

Breaks the domain into Unicode code points, flags non-ASCII characters and
script mixing (e.g. Latin + Cyrillic), and emits both Punycode and an HTML
fragment ready to paste into chapter 10.2 of the report.
"""

from __future__ import annotations

import argparse
import sys
import unicodedata


# Unicode block names that matter for homograph attacks
COMMON_HOMOGRAPH_BLOCKS = {
    "LATIN": "Latin",
    "CYRILLIC": "Cyrillic",
    "GREEK": "Greek",
    "ARMENIAN": "Armenian",
    "HEBREW": "Hebrew",
    "ARABIC": "Arabic",
    "DEVANAGARI": "Devanagari",
    "CJK": "CJK",
    "HANGUL": "Hangul",
    "HIRAGANA": "Hiragana",
    "KATAKANA": "Katakana",
    "FULLWIDTH": "Fullwidth",
}


def script_of(ch: str) -> str:
    """Return a coarse script bucket for the given character."""
    if ch.isascii():
        return "ASCII"
    try:
        name = unicodedata.name(ch, "")
    except ValueError:
        return "UNKNOWN"
    for key, label in COMMON_HOMOGRAPH_BLOCKS.items():
        if key in name:
            return label
    if "FULLWIDTH" in name:
        return "Fullwidth"
    return "Other"


def analyze(domain: str) -> dict:
    domain = domain.strip().lower().rstrip(".")
    try:
        punycode = domain.encode("idna").decode("ascii")
    except UnicodeError:
        punycode = "(IDNA encoding failed)"

    chars = []
    scripts = set()
    for ch in domain:
        if ch == ".":
            chars.append({"char": ch, "codepoint": "U+002E", "name": "FULL STOP", "script": "ASCII", "suspicious": False})
            continue
        cp = f"U+{ord(ch):04X}"
        try:
            name = unicodedata.name(ch)
        except ValueError:
            name = ""
        sc = script_of(ch)
        scripts.add(sc)
        chars.append(
            {
                "char": ch,
                "codepoint": cp,
                "name": name,
                "script": sc,
                "suspicious": sc not in ("ASCII", "Hangul", "CJK"),
            }
        )

    # Mixed-script detection: Latin + (Cyrillic|Greek|Armenian|Hebrew|Fullwidth)
    risky_mix = (
        ("Latin" in scripts or "ASCII" in scripts)
        and bool(scripts & {"Cyrillic", "Greek", "Armenian", "Hebrew", "Fullwidth"})
    )

    return {
        "input": domain,
        "punycode": punycode,
        "is_idn": punycode != domain or punycode.startswith("xn--") or "xn--" in punycode,
        "scripts": sorted(scripts),
        "risky_mix": risky_mix,
        "chars": chars,
    }


def render_text(result: dict) -> str:
    out = []
    out.append(f"input:    {result['input']}")
    out.append(f"punycode: {result['punycode']}")
    out.append(f"is_idn:   {result['is_idn']}")
    out.append(f"scripts:  {', '.join(result['scripts'])}")
    out.append(f"risky_mix: {result['risky_mix']}")
    out.append("")
    out.append(f"{'char':<6}{'codepoint':<10}{'script':<12}{'suspicious':<12}name")
    for c in result["chars"]:
        out.append(
            f"{c['char']:<6}{c['codepoint']:<10}{c['script']:<12}"
            f"{'YES' if c['suspicious'] else '':<12}{c['name']}"
        )
    return "\n".join(out)


def render_html(result: dict) -> str:
    cells = []
    for c in result["chars"]:
        klass = ""
        if c["suspicious"]:
            klass = ' class="cyrillic"'  # reuse existing red-highlight CSS
        cells.append(f'<span{klass} title="{c["codepoint"]} {c["name"]}">{c["char"]}</span>')
    pretty = "".join(cells)
    return (
        '<div class="charbox">\n'
        f'  도메인: {pretty}<br>\n'
        f'  &rarr; Punycode: <code>{result["punycode"]}</code><br>\n'
        f'  스크립트: {", ".join(result["scripts"]) or "—"}'
        + (" <strong>(혼합 — 호모그래프 의심)</strong>" if result["risky_mix"] else "")
        + "\n</div>"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("domain")
    parser.add_argument("--html", action="store_true", help="emit HTML snippet")
    args = parser.parse_args()

    result = analyze(args.domain)
    if args.html:
        print(render_html(result))
    else:
        print(render_text(result))


if __name__ == "__main__":
    main()
