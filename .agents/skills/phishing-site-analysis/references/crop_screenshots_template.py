"""스크린샷 발췌(crop) 템플릿.

사용법:
  1. report/[도메인]/ 안에 screenshot-*.png를 둔다 (Playwright fullPage 캡처).
  2. 이 파일을 report/[도메인]/crop_screenshots.py로 복제한다.
  3. BASE / SOURCES / CROPS를 분석 대상에 맞게 수정한다.
  4. `source .venv/bin/activate && python crop_screenshots.py`로 실행.

규칙:
  - 본문에 들어갈 crop은 350~800px 높이가 적당 (A4 1/3 ~ 1/2 면).
  - 풀 페이지는 별도로 부록 A에 풀 사이즈로 배치하므로 crop은 사기 식별 요소만.
  - 결제 페이지가 있으면 수취인 폼 / 결제수단 / 카드입력+안티봇을 3개로 나눠 잘라라.
"""

from PIL import Image
import os

BASE = '/home/cozyu/git/anal_phishing_neo/report/__DOMAIN__'  # ← 대상 폴더로 교체

# 풀 페이지 캡처 파일 목록. 보통 Playwright에서 fullPage=True로 받은 png들.
SOURCES = [
    'screenshot-main-mobile.png',
    'screenshot-detail-mobile.png',
    'screenshot-checkout-mobile.png',
]

# 자르기 작업 목록: (source, output_name, y0, y1)
# y0~y1 픽셀 구간을 잘라 output_name으로 저장. 가로는 항상 전체 폭(W).
CROPS = [
    # 메인 페이지: 상단 헤더 + 미끼 배너
    ('screenshot-main-mobile.png',     'crop-main-header.png',          0,   700),
    ('screenshot-main-mobile.png',     'crop-main-hero.png',            600, 1400),
    # 상품 디테일: 가격 + 가짜 사회적 증명
    ('screenshot-detail-mobile.png',   'crop-detail-title.png',         800, 1500),
    # 결제: 수취인 정보 / 결제수단 / 카드+안티봇
    ('screenshot-checkout-mobile.png', 'crop-checkout-recipient.png',   1300, 2300),
    ('screenshot-checkout-mobile.png', 'crop-checkout-payment.png',     2400, 3300),
    ('screenshot-checkout-mobile.png', 'crop-checkout-card-antibot.png',3000, 3700),
]

def main():
    cache = {}
    for src, out, y0, y1 in CROPS:
        spath = os.path.join(BASE, src)
        if not os.path.exists(spath):
            print(f"  SKIP {out}: source {src} not found")
            continue
        if spath not in cache:
            cache[spath] = Image.open(spath)
        im = cache[spath]
        W, H = im.size
        y1 = min(y1, H)
        if y0 >= H:
            print(f"  SKIP {out}: y0={y0} > H={H}")
            continue
        im.crop((0, y0, W, y1)).save(os.path.join(BASE, out))
        print(f"  saved {out}: {W}x{y1-y0}")

if __name__ == '__main__':
    main()
