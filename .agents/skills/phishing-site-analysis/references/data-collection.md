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

```bash
# HTML에서 등장하는 외부 호스트를 카테고리별 분류
python - <<'PY'
import re, sys, collections
html = open('mobile.html').read()
hosts = re.findall(r'https?://([a-z0-9.-]+)', html)
counter = collections.Counter(hosts)
NORMAL = {'telegram.org','reactjs.org','www.w3.org','github.com','www.google-analytics.com',
          'www.googletagmanager.com','fonts.googleapis.com','www.facebook.com',
          'www.clarity.ms','analytics.tiktok.com','gum.criteo.com'}
print("=== 의심 호스트 ===")
for h, c in counter.most_common():
    if h in NORMAL: continue
    if any(x in h for x in ['w3.org','reactjs','github','google-analytics','googletagmanager','fonts.google','telegram.org','facebook.com','clarity.ms','tiktok.com','criteo.com']): continue
    print(f"  {h}: {c}")
PY
```
