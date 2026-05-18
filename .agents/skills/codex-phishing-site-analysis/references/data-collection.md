# 외부 위협 인텔리전스 일괄 조회

WHOIS·VirusTotal·urlscan.io·CT를 한 번에 돌리는 Python 블록. `$URL`, `$DOMAIN` 환경변수 + 가상환경이 활성화된 상태에서 실행.

```bash
python - <<'PY'
import os, requests, base64
vt = os.environ["VT_API_KEY"]
us = os.environ["URLSCAN_API_KEY"]
URL = os.environ.get("URL", "https://example.com")
DOMAIN = os.environ.get("DOMAIN", "example.com")

# 1. VT URL
uid = base64.urlsafe_b64encode(URL.encode()).decode().strip("=")
r = requests.get(f"https://www.virustotal.com/api/v3/urls/{uid}", headers={"x-apikey": vt}, timeout=20)
print(f"VT URL {URL}: {r.status_code}")
if r.status_code == 200:
    d = r.json()["data"]["attributes"]
    print("  stats:", d.get("last_analysis_stats"))
    print("  title:", d.get("title"))
    print("  last_final_url:", d.get("last_final_url"))
    mal = {k: v.get("result") for k, v in d.get("last_analysis_results", {}).items() if v.get("category") in ("malicious","suspicious")}
    if mal: print("  malicious_vendors:", mal)
elif r.status_code == 404:
    r2 = requests.post("https://www.virustotal.com/api/v3/urls", headers={"x-apikey": vt}, data={"url": URL}, timeout=20)
    print("  submitted:", r2.status_code)

# 2. VT Domain
r = requests.get(f"https://www.virustotal.com/api/v3/domains/{DOMAIN}", headers={"x-apikey": vt}, timeout=20)
print(f"\nVT Domain {DOMAIN}: {r.status_code}")
if r.status_code == 200:
    d = r.json()["data"]["attributes"]
    print("  stats:", d.get("last_analysis_stats"))
    print("  registrar:", d.get("registrar"))
    print("  creation_date:", d.get("creation_date"))
    print("  last_dns:", d.get("last_dns_records"))
    print("  categories:", d.get("categories"))
    mal = {k: v.get("result") for k, v in d.get("last_analysis_results", {}).items() if v.get("category") in ("malicious","suspicious")}
    if mal: print("  malicious_vendors:", mal)

# 3. urlscan.io
r = requests.get("https://urlscan.io/api/v1/search/", params={"q": f'domain:{DOMAIN}', "size": 30}, headers={"API-Key": us}, timeout=20)
j = r.json()
print(f"\nurlscan: total={j.get('total')}")
for res in j.get("results", [])[:10]:
    p = res.get("page", {}); t = res.get("task", {})
    print(f"  - {t.get('time')} | {p.get('url')} | IP={p.get('ip')} | server={p.get('server')} | title={p.get('title')!r}")
    print(f"    result: {res.get('result')}")
PY
```

## urlscan 결과 디테일 가져오기

```bash
UUID="0198f3df-435e-7387-8280-7a37964f1bcf"  # ← search 결과의 UUID
python - <<PY
import os, requests
r = requests.get(f"https://urlscan.io/api/v1/result/$UUID/", headers={"API-Key": os.environ["URLSCAN_API_KEY"]}, timeout=20)
j = r.json()
p = j['page']; t = j['task']
print("URL:", p.get('url'))
print("Title:", p.get('title'))
print("IP/ASN:", p.get('ip'), p.get('asn'), p.get('asnname'))
print("Server/Country:", p.get('server'), p.get('country'))
print("TLS:", p.get('tlsIssuer'), 'validFrom=', p.get('tlsValidFrom'))
print("Lists.domains:", j['lists'].get('domains'))
print("Lists.ips:", j['lists'].get('ips'))
# 의심 외부 호출 (광고/픽셀/정상 SaaS 제외)
from urllib.parse import urlparse
domains = set()
for rq in j['data']['requests']:
    u = rq.get('request',{}).get('request',{}).get('url','')
    if u: domains.add(urlparse(u).netloc)
print("All contacted domains:")
for d in sorted(domains): print(" -", d)
PY
```

## 운영자 활동 시간대 환산표 (Python)

분석 보고서 4.2 챕터에 들어가는 시간대 비교를 자동 생성:

```bash
python - <<'PY'
from datetime import datetime, timezone, timedelta
KST = timezone(timedelta(hours=9))
CST = timezone(timedelta(hours=8))
EVENTS = [
    ("도메인 등록",       "2025-08-25 06:06:46Z"),
    ("TLS 인증서 발급",   "2025-08-28 02:23:07Z"),
    ("urlscan 첫 캡처",   "2026-02-06 08:30:09Z"),
    ("WHOIS 갱신",        "2026-03-31 05:20:39Z"),
]
print(f"{'이벤트':22s}  {'UTC':16s}  {'KST':16s}  {'CST':16s}")
for name, ts in EVENTS:
    dt = datetime.fromisoformat(ts.replace('Z','+00:00'))
    print(f"  {name:20s}  {dt.strftime('%Y-%m-%d %H:%M'):16s}  {dt.astimezone(KST).strftime('%Y-%m-%d %H:%M'):16s}  {dt.astimezone(CST).strftime('%Y-%m-%d %H:%M'):16s}")
PY
```

## 출력 IOC 정리 헬퍼

화이트리스트는 [trusted-hosts.txt](trusted-hosts.txt)에 외부화되어 있다 — 분석을 거듭하며 신뢰 호스트를 추가해 정확도를 높인다.

```bash
python - <<'PY'
import re, collections, pathlib
SKILL = pathlib.Path('.agents/skills/codex-phishing-site-analysis/references')
NORMAL = {
    ln.strip() for ln in (SKILL / 'trusted-hosts.txt').read_text().splitlines()
    if ln.strip() and not ln.startswith('#')
}
html = open('mobile.html').read()
hosts = re.findall(r'https?://([a-z0-9.-]+)', html)
counter = collections.Counter(hosts)
print("=== 의심 호스트 ===")
for h, c in counter.most_common():
    if h in NORMAL: continue
    # 서브도메인 매칭 (예: cdn.fonts.googleapis.com → fonts.googleapis.com 화이트리스트 적용)
    if any(h == n or h.endswith('.' + n) for n in NORMAL): continue
    print(f"  {h}: {c}")
PY
```

## 보조 위협 인텔리전스 (무료 소스)

VT/urlscan/CT 외 추가 vendor diversity를 확보. 모두 무료 API.

```bash
python - <<'PY'
import os, requests
DOMAIN = os.environ["DOMAIN"]
URL = os.environ["URL"]

# 1. URLhaus (abuse.ch) - 악성 URL DB. API 키 불필요.
r = requests.post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": URL}, timeout=15)
print(f"URLhaus URL: {r.status_code} {r.json().get('query_status')}")
if r.status_code == 200 and r.json().get('query_status') == 'ok':
    j = r.json()
    print("  threat:", j.get('threat'), "tags:", j.get('tags'))
    print("  date_added:", j.get('date_added'))
r = requests.post("https://urlhaus-api.abuse.ch/v1/host/", data={"host": DOMAIN}, timeout=15)
print(f"URLhaus Host: {r.status_code} {r.json().get('query_status')}")
if r.status_code == 200 and r.json().get('query_status') == 'ok':
    j = r.json()
    print("  url_count:", j.get('url_count'))
    for u in (j.get('urls') or [])[:5]:
        print(f"   - {u.get('date_added')} {u.get('url')} ({u.get('threat')})")

# 2. PhishTank — 무료. PHISHTANK_API_KEY 있으면 application/key 사용, 없으면 anonymous.
ptk = os.environ.get("PHISHTANK_API_KEY")
headers = {"User-Agent": "phishing-site-analysis"}
data = {"url": URL, "format": "json"}
if ptk:
    data["app_key"] = ptk
r = requests.post("https://checkurl.phishtank.com/checkurl/", data=data, headers=headers, timeout=15)
print(f"\nPhishTank: {r.status_code}")
if r.status_code == 200:
    try:
        j = r.json()
        res = j.get("results", {})
        print("  in_database:", res.get("in_database"), "verified:", res.get("verified"),
              "valid:", res.get("valid"), "phish_detail:", res.get("phish_detail_page"))
    except Exception as e:
        print("  parse error:", e)

# 3. AlienVault OTX — 무료 API (OTX_API_KEY 필요)
otx = os.environ.get("OTX_API_KEY")
if otx:
    r = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{DOMAIN}/general",
                     headers={"X-OTX-API-KEY": otx}, timeout=15)
    print(f"\nOTX domain: {r.status_code}")
    if r.status_code == 200:
        j = r.json()
        pulses = j.get('pulse_info', {}).get('pulses', [])
        print(f"  pulse_count={len(pulses)}")
        for p in pulses[:5]:
            print(f"   - {p.get('created')} | {p.get('name')!r} ({len(p.get('tags', []))} tags)")
else:
    print("\nOTX: skipped (set OTX_API_KEY in .env)")

# 4. Google Safe Browsing — Lookup API (GOOGLE_SAFE_BROWSING_API_KEY 필요)
gsb = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")
if gsb:
    payload = {
        "client": {"clientId": "phishing-site-analysis", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": URL}],
        },
    }
    r = requests.post(
        f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={gsb}",
        json=payload, timeout=15,
    )
    print(f"\nSafe Browsing: {r.status_code}")
    if r.status_code == 200:
        matches = r.json().get("matches", [])
        print(f"  matches={len(matches)}")
        for m in matches:
            print(f"   - {m.get('threatType')} / {m.get('platformType')}")
else:
    print("\nSafe Browsing: skipped (set GOOGLE_SAFE_BROWSING_API_KEY in .env)")

# 5. ThreatFox (abuse.ch) — IOC 검색. API 키 불필요.
r = requests.post("https://threatfox-api.abuse.ch/api/v1/",
                  json={"query": "search_ioc", "search_term": DOMAIN}, timeout=15)
print(f"\nThreatFox: {r.status_code} {r.json().get('query_status')}")
if r.status_code == 200 and r.json().get('query_status') == 'ok':
    for d in (r.json().get('data') or [])[:5]:
        print(f"   - {d.get('first_seen')} {d.get('ioc')} {d.get('threat_type')} ({d.get('malware_printable')})")
PY
```

## Wayback Machine / archive.org 패시브 룩업

도메인이 콜드풀에서 깨어났는지, 과거 정상 운영 흔적이 있는지 확인.

```bash
# CDX API — 캡처 이력 최대 50건
curl -s "https://web.archive.org/cdx/search/cdx?url=$DOMAIN&output=json&limit=50&from=20200101" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
if not data or len(data) < 2:
    print('Wayback: no captures')
    sys.exit()
header, rows = data[0], data[1:]
idx = {k: header.index(k) for k in header}
print(f'Wayback total captures: {len(rows)}')
print(f'  first: {rows[0][idx[\"timestamp\"]]}  status={rows[0][idx[\"statuscode\"]]}  url={rows[0][idx[\"original\"]]}')
print(f'  last:  {rows[-1][idx[\"timestamp\"]]}  status={rows[-1][idx[\"statuscode\"]]}  url={rows[-1][idx[\"original\"]]}')
print('  sample:')
for r in rows[:10]:
    print(f'    {r[idx[\"timestamp\"]]} {r[idx[\"statuscode\"]]} {r[idx[\"original\"]]}')"

# 최근 스냅샷 직접 받기 (있으면)
curl -sI "https://web.archive.org/web/2y_/https://$DOMAIN" | head -5
```

체크포인트:
- 캡처 0건: 갓 만든 도메인 (cold pool 또는 신규 등록)
- 과거 캡처가 전혀 다른 콘텐츠: 도메인 재활용 / 콜드풀에서 깨어남
- 최근 캡처가 다수: 운영 활성, 시간대별 페이지 변화 비교 가능
