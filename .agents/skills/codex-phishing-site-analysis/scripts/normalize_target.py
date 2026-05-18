#!/usr/bin/env python3
"""Normalize a phishing-analysis target into URL, domain, and safe report slug."""

from __future__ import annotations

import argparse
import json
import re
from urllib.parse import urlparse


def normalize(target: str, default_scheme: str) -> dict[str, str]:
    raw = target.strip()
    if not raw:
        raise SystemExit("target is empty")

    parse_input = raw if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw) else f"{default_scheme}://{raw}"
    parsed = urlparse(parse_input)
    host = parsed.hostname
    if not host:
        raise SystemExit(f"could not parse hostname from target: {target!r}")

    domain = host.rstrip(".").encode("idna").decode("ascii").lower()
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or "/"
    query = f"?{parsed.query}" if parsed.query else ""
    fragment = f"#{parsed.fragment}" if parsed.fragment else ""
    url = f"{parsed.scheme.lower()}://{domain}{port}{path}{query}{fragment}"

    slug_host = domain.replace("*.", "")
    slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", slug_host)
    if parsed.port:
        slug = f"{slug}_{parsed.port}"

    return {
        "input": raw,
        "url": url,
        "domain": domain,
        "host": domain,
        "report_slug": slug,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", help="URL or domain to analyze")
    parser.add_argument("--default-scheme", default="https", choices=["http", "https"])
    parser.add_argument("--shell", action="store_true", help="print shell assignments instead of JSON")
    args = parser.parse_args()

    data = normalize(args.target, args.default_scheme)
    if args.shell:
        print(f"URL={json.dumps(data['url'])}")
        print(f"DOMAIN={json.dumps(data['domain'])}")
        print(f"REPORT_SLUG={json.dumps(data['report_slug'])}")
    else:
        print(json.dumps(data, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
