"""도메인 모니터링 주기 실행 스크립트 (cron 용).

Streamlit 페이지를 띄우지 않고도 등록된 모니터링 키워드(`keywords` 테이블)를
순회하며 VirusTotal 검색 + WHOIS 조회 후 결과를 `keyword_results` 테이블에
저장한다. 페이지의 "재검색" 버튼과 동일한 로직.

사용법:
    python scripts/cron_domain_monitor.py [--mode period|incremental] [--days N] [--keyword KW]

옵션:
    --mode period       특정 기간 내 등록 도메인 (기본)
    --mode incremental  이전 검색 이후 발견된 신규 도메인만
    --days N            기간 (기본 14, period 모드에서만 사용)
    --keyword KW        특정 키워드 하나만 실행 (생략 시 활성 키워드 전체)

종료 코드:
    0  성공
    1  설정 오류 / API 키 누락
    2  부분 실패 (일부 키워드 오류)
"""

import argparse
import os
import sys
import time
from pathlib import Path

# 프로젝트 루트를 sys.path에 추가 (스크립트 단독 실행용)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
os.chdir(PROJECT_ROOT)

from domain_monitor import search_domains, get_domain_detail, sort_by_creation_date
from db import (
    get_keywords, save_keyword_results, get_seen_domains, save_history,
)

DOMAIN_SOURCE = "vt_domain"
KEYWORD_PURPOSE = "url"


def run_for_keyword(kw: dict, days: int, incremental: bool) -> dict:
    keyword = kw["keyword"]
    print(f"  [{keyword}] VirusTotal 검색 중...", flush=True)
    search_days = 365 if incremental else days
    domains = search_domains(keyword, days=search_days)
    print(f"  [{keyword}] {len(domains)}개 도메인 발견, WHOIS 조회 중...", flush=True)

    details = [get_domain_detail(d) for d in domains]
    filtered = sort_by_creation_date(details)
    save_data = [{k: v for k, v in d.items() if k != "_creation_dt"} for d in filtered]

    if incremental:
        seen = get_seen_domains(kw["id"], DOMAIN_SOURCE)
        new_data = [d for d in save_data if d.get("domain") not in seen]
    else:
        new_data = save_data

    save_keyword_results(kw["id"], keyword, DOMAIN_SOURCE, len(new_data), new_data[:200])
    return {"keyword": keyword, "total": len(new_data), "results": new_data}


def main() -> int:
    parser = argparse.ArgumentParser(description="도메인 모니터링 주기 실행")
    parser.add_argument("--mode", choices=["period", "incremental"], default="period")
    parser.add_argument("--days", type=int, default=14)
    parser.add_argument("--keyword", default=None, help="특정 키워드 하나만 실행")
    args = parser.parse_args()

    incremental = args.mode == "incremental"
    mode_label = "신규" if incremental else f"{args.days}일"

    keywords = get_keywords(active_only=True, purpose=KEYWORD_PURPOSE)
    if args.keyword:
        keywords = [k for k in keywords if k["keyword"] == args.keyword]
    if not keywords:
        print("실행할 키워드가 없습니다.", file=sys.stderr)
        return 1

    print(f"[{mode_label}] {len(keywords)}개 키워드 모니터링 시작", flush=True)

    results, errors = [], []
    for i, kw in enumerate(keywords):
        try:
            r = run_for_keyword(kw, args.days, incremental)
            print(f"  [{kw['keyword']}] 신규 {r['total']}건 저장", flush=True)
            results.append(r)
        except Exception as e:
            print(f"  [{kw['keyword']}] 오류: {e}", file=sys.stderr, flush=True)
            errors.append({"keyword": kw["keyword"], "error": str(e)})
        if i < len(keywords) - 1:
            time.sleep(1)

    if results:
        keywords_str = ", ".join(r["keyword"] for r in results)
        total_found = sum(r["total"] for r in results)
        title = f"[모니터링/{mode_label}] {keywords_str} ({total_found}건)"
        save_history("domains", title, {
            "monitor": True,
            "mode": mode_label,
            "results_by_keyword": {r["keyword"]: r["results"] for r in results},
        })

    print(f"완료: 성공 {len(results)}건, 실패 {len(errors)}건", flush=True)
    return 0 if not errors else 2


if __name__ == "__main__":
    sys.exit(main())
