# PhishGuard — 피싱 URL 판별 웹 서비스 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 사용자가 입력한 URL을 정규화하고, 단축 URL은 최종 주소로 풀어낸 뒤, URL 문자열 특징과 도메인 생성일을 바탕으로 규칙 기반 판별(베이스라인)과 머신러닝 판별을 수행해, 위험도(안전/주의/위험)와 그 이유를 보여주는 웹 서비스를 만든다.

**Architecture:** 단일 Python 패키지 `phishguard`. 분석 파이프라인은 `normalize → redirect 해석 → parse(PSL) → domain age 조회 → feature 추출 → rules / ML` 순서의 순수 함수와 작은 클래스로 구성한다. 특징 추출(`extract_features`)은 규칙 엔진, 학습, 서빙이 모두 공유하는 **단일 진실 공급원(single source of truth)** 이다. 웹 계층(FastAPI + Jinja2)은 `SupportsAnalyze` 프로토콜에만 의존하므로, 비즈니스 로직 없이 스텁으로 먼저 완성하고 테스트할 수 있다.

**Tech Stack:** Python 3.11, FastAPI, Jinja2, httpx, tldextract(PSL), idna, python-whois, PyYAML, scikit-learn, pandas, joblib, pytest, respx

**Spec:** `C:\Users\지민혁\Desktop\ASC\individual-project-plan-template.md` (2026년 ASC 개인 프로젝트 계획서 — 피싱 URL 판별, 작성자 지민혁). 핵심 요구사항(원문):
1. 입력된 URL의 형식을 정리하고, 단축 URL은 리다이렉트를 따라가 최종 주소를 확인함
2. URL을 구성 요소로 분해하고, 공개 접미사 목록(PSL)을 기준으로 실제 등록 도메인을 추출함
3. URL 문자열 특징(IP 주소 사용, 서브도메인 개수, 등록 도메인이 아닌 위치의 브랜드명 등)과 도메인 생성일을 판별 특징으로 사용함
4. 규칙 기반 판별을 베이스라인으로 구현하고, 동일한 특징으로 머신러닝 모델을 학습시켜 성능을 비교함
5. (기대효과) 일반 사용자가 링크를 누르기 전에 **위험 여부와 그 이유**를 확인
6. (문제점) 규칙 점수와 **3단계 경계값**을 정하는 기준이 주관적일 수 있음 → Phase 5에서 데이터 기반 보정
7. (검증) 실제 피해 URL·정상 URL로 판별 확인, 이후 **새로 수집한 피싱 URL**로 성능 확인
8. (장비) Python 라이브러리, Docker, 공개 피싱 URL 목록

---

## Global Constraints

모든 Task의 요구사항에 아래 항목이 암묵적으로 포함된다.

- Python **3.11** (개발 PC: Windows 11, Python 3.11.9). 경로는 항상 `pathlib.Path`로 다루고 OS 의존 구분자를 하드코딩하지 않는다.
- 프로젝트 루트: `C:\Users\지민혁\Desktop\File` (이 문서가 있는 폴더). 소스는 `src/phishguard/`, 테스트는 `tests/` (src layout).
- 가상환경: `py -3.11 -m venv .venv` → `.venv\Scripts\activate` (PowerShell) 또는 `source .venv/Scripts/activate` (Git Bash). 이후 모든 명령은 venv 활성화 상태를 가정한다.
- 의존성(최소 버전): `fastapi>=0.110`, `uvicorn[standard]>=0.29`, `jinja2>=3.1`, `python-multipart>=0.0.9`, `httpx>=0.27`, `tldextract>=5.1`, `idna>=3.6`, `python-whois>=0.9`, `pyyaml>=6.0`, `scikit-learn>=1.4`, `pandas>=2.2`, `numpy>=1.26`, `joblib>=1.3`. 개발용: `pytest>=8.0`, `respx>=0.21`.
- **단위 테스트는 네트워크를 사용하지 않는다.** 실제 네트워크가 필요한 테스트는 `@pytest.mark.network`를 붙이고, 기본 실행(`addopts = -m "not network"`)에서 제외한다.
- **피싱 호스트에 직접 요청하지 않는다.** 서버가 네트워크로 접촉하는 대상은 (a) 단축 URL 서비스 목록에 있는 호스트, (b) RDAP/WHOIS 서버, (c) 데이터 피드(OpenPhish 등)뿐이다.
- 레이블 규약: **`1 = phishing`, `0 = benign`**. 외부 데이터셋이 반대 규약이면 로더에서 반전한다.
- 특징 이름과 순서는 `phishguard.models.FEATURE_NAMES` 하나로만 정의한다. 변경 시 `FEATURE_SCHEMA_VERSION`을 올린다.
- 사용자에게 보이는 메시지(판정 이유, 오류)는 **한국어**. 코드 식별자·로그는 영어.
- 판정 등급은 3단계: `Verdict.SAFE`(안전) / `Verdict.SUSPICIOUS`(주의) / `Verdict.DANGEROUS`(위험).
- 난수 시드는 `42`로 고정.
- `data/raw/`, `data/processed/`, `models/*.joblib`, `cache.sqlite3`, `.venv/`는 git에 커밋하지 않는다(`.gitignore`).
- 테스트 실행: `python -m pytest` (전체), 특정 테스트는 `python -m pytest tests/<file>::<name> -v`.

---

## 아키텍처

### 데이터 흐름

```
raw_url (사용자 입력)
  │ normalize_url()                     ── 공백/defang 정리, scheme 보정, IDNA, 기본 포트 제거
  ▼
NormalizedURL ──► RedirectResolver.resolve()  ── 단축 URL 호스트일 때만 Location 헤더를 따라감
                    │                          (최종 목적지에는 요청하지 않음)
                    ▼
                 RedirectResult.final_url ─► normalize_url() ─► parse_url() ── tldextract(PSL)
                                                                   ▼
                                                                URLParts.registered_domain
                                                                   │ DomainAgeLookup.lookup() ── RDAP → WHOIS, SQLite TTL 캐시
                                                                   ▼
                                                                DomainInfo
  (NormalizedURL, URLParts, RedirectResult, DomainInfo, Resources)
  │ extract_features()
  ▼
FeatureVector ──► RuleEngine.evaluate() ─► RuleResult (점수, 등급, 이유)
              └─► PhishModel.predict()  ─► ModelResult (확률, 등급)
  ▼
AnalysisResult ─► FastAPI (HTML / JSON)
```

### 파일 구조

| 경로 | 책임 | Task |
|---|---|---|
| `pyproject.toml` | 패키지 메타데이터, 의존성, pytest 설정 | T1 |
| `.gitignore` | 데이터/모델/캐시/venv 제외 | T1 |
| `src/phishguard/__init__.py` | 버전 `__version__ = "0.1.0"` | T1 |
| `src/phishguard/models.py` | 모든 도메인 타입(dataclass/enum), `FEATURE_NAMES` | T1 |
| `src/phishguard/errors.py` | `InvalidURLError` | T1 |
| `src/phishguard/resources/*.yaml, *.txt` | 브랜드, 단축 URL, 위험 TLD, 의심 키워드, 규칙 가중치 | T2 |
| `src/phishguard/config.py` | `Resources` 로더, 경로/환경변수 설정 | T2 |
| `src/phishguard/web/app.py` | `create_app(analyzer)` FastAPI 팩토리, 라우트 | T3, T4 |
| `src/phishguard/web/stub.py` | `StubAnalyzer`, `make_sample_result` (Phase 2용, T18에서 `tests/fakes.py`로 이동) | T3, T18 |
| `src/phishguard/web/presenters.py` | `defang()`, 등급 한국어 라벨 | T4 |
| `src/phishguard/web/templates/*.html`, `static/style.css` | 입력 폼, 결과 화면 | T4 |
| `src/phishguard/web/main.py` | uvicorn 진입점 `app` (기본 Analyzer 조립) | T3, T11, T16 |
| `src/phishguard/normalize.py` | `normalize_url()` | T5 |
| `src/phishguard/parse.py` | `parse_ip_host()`, `parse_url()` | T6 |
| `src/phishguard/redirect.py` | `RedirectResolver` (SSRF 가드 포함) | T7 |
| `src/phishguard/cache.py` | `TTLCache` (SQLite) | T8 |
| `src/phishguard/domain_age.py` | `DomainAgeLookup` (RDAP + WHOIS 폴백) | T8 |
| `src/phishguard/features.py` | `match_keywords()`, `extract_features()` | T9 |
| `src/phishguard/rules.py` | `RuleEngine` | T10 |
| `src/phishguard/analyzer.py` | `Analyzer` 파이프라인 조립 | T11, T16 |
| `src/phishguard/ml.py` | `PhishModel` (아티팩트 로드/예측) | T16 |
| `src/phishguard/training/dataset.py` | 데이터셋 로더, 중복 제거, 특징 행렬 | T12 |
| `src/phishguard/training/collect_feed.py` | 신규 피싱 URL 수집 + 도메인 나이 스냅샷 | T13 |
| `src/phishguard/training/train.py` | 모델 학습, 아티팩트 저장 | T14 |
| `src/phishguard/training/evaluate.py` | 지표 계산, 비교 리포트 | T15 |
| `src/phishguard/training/calibrate.py` | 3단계 경계값 보정 | T17 |
| `Dockerfile`, `README.md` | 배포/사용 문서 | T18 |
| `tests/test_*.py` | Task별 테스트 | 각 Task |

### Phase 구성 (요청된 순서 매핑)

| Phase | 내용 | 요청 순서와의 대응 | Tasks |
|---|---|---|---|
| 1 | 프로젝트 골격 + 데이터 모델/신규 타입 + 리소스 | 데이터 모델 변경 및 신규 타입 정의 | T1–T2 |
| 2 | 웹 UI (스텁 Analyzer로 동작) | 사용자 인터페이스 | T3–T4 |
| 3 | 규칙 기반 분석 파이프라인 | 비즈니스 로직 (1) | T5–T11 |
| 4 | 데이터 구축 + ML 학습/평가/통합 | 비즈니스 로직 (2) | T12–T16 |
| 5 | 경계값 보정, 리팩토링, Docker, 문서 | 리팩토링 | T17–T18 |

---

## Review Focus

명세가 직접 말하지 않지만 실제 사용자에게 가장 먼저 문제를 일으킬 입력/상황. 각 항목의 테스트는 표시된 Task에 포함되어 있다.

1. **한국형 스미싱 단축 URL** (`han.gl`, `me2.do`, `vo.la`, `url.kr`, `bit.ly` 등) + 택배/정부기관 사칭 → 단축 URL이 풀려 최종 도메인 기준으로 판정되어야 하고, 한국 브랜드(우체국, CJ대한통운, 국민건강보험, 정부24 등)가 브랜드 목록에 있어야 한다. → T2 `test_korean_brands_and_shorteners_present`, T7 `test_resolves_korean_shortener`, T11 `test_end_to_end_smishing_shortener`
2. **한글(IDN) 도메인 / punycode 입력** (`http://네이버.com`, `xn--...`) → 예외 없이 punycode로 정규화되고 `has_punycode=1`. → T5 `test_idn_host_is_punycoded`, T9 `test_punycode_feature`
3. **사람이 복사해 붙인 지저분한 입력** (앞뒤 공백, 제로폭 문자, scheme 누락, 대문자, defang된 `hxxps://evil[.]com`) → 올바른 URL로 정리. → T5 `test_messy_inputs`
4. **외부 조회 실패** (RDAP 타임아웃, WHOIS 차단, 단축 URL 서비스 장애) → 분석은 중단되지 않고 `warnings`에 기록되며 `domain_age_unknown=1`. → T8 `test_all_sources_fail_returns_unknown`, T11 `test_analyze_survives_external_failures`
5. **내부망/루프백 주소 입력 또는 내부 IP로 해석되는 단축 URL** → 서버는 요청을 보내지 않고(SSRF 방지) `is_ip_host` 규칙으로 판정. → T7 `test_blocks_private_resolution`, T11 `test_private_ip_input_makes_no_request`

---

## 아키텍처 결정 (ADR 요약)

| # | 결정 | 이유 |
|---|---|---|
| D1 | 리다이렉트는 **단축 URL 호스트일 때만** 따라가고, `Location` 헤더만 읽는다. 다음 호스트가 단축 URL이 아니면 그 주소에 요청하지 않고 멈춘다. | 명세는 "단축 URL은 리다이렉트를 따라감"만 요구. 피싱 서버에 접속하면 서버 IP 노출, 1회용 링크 소모, SSRF 위험이 생긴다. |
| D2 | 단축 URL 호스트도 요청 전에 DNS 해석 결과가 모두 `ip.is_global`인지 확인한다. | 허용 목록 호스트라도 DNS 조작 시 내부망을 가리킬 수 있음(SSRF). |
| D3 | PSL은 `tldextract`의 **번들 스냅샷**을 기본으로 쓴다(`suffix_list_urls=()`, `cache_dir=None`). 등록 도메인은 `f"{r.domain}.{r.suffix}"`로 직접 조합한다. | 테스트/학습 재현성. `registered_domain` 속성은 tldextract 5.3에서 deprecated되어 버전 간 API 변화를 피한다. |
| D4 | 등록 도메인은 두 가지를 계산한다. `registered_domain`(ICANN 기준, WHOIS/RDAP 조회·브랜드 공식 도메인 비교용)과 `site_domain`(PSL private 섹션 포함, 예: `evil.github.io`). `is_private_suffix`는 특징으로 쓴다. | `paypal-login.github.io` 같은 무료 호스팅 피싱을 "서브도메인 위치의 브랜드명"으로 잡으려면 ICANN 기준이 필요하고, 공유 호스팅 여부는 별도 신호다. |
| D5 | 도메인 생성일은 RDAP(IANA bootstrap) 우선, 실패 시 `python-whois` 폴백. 결과는 SQLite TTL 캐시. | RDAP은 구조화된 JSON이라 파싱 오류가 적다. WHOIS는 형식이 TLD마다 달라 폴백으로만 쓴다. |
| D6 | 학습용 과거 데이터셋의 도메인 나이는 **조회하지 않고 결측(NaN)** 으로 둔다. 도메인 나이는 수집 시점에 스냅샷한 데이터(T13)에서만 사용한다. | 오래된 피싱 도메인은 이미 삭제·재등록되어 "지금" 조회한 생성일은 수집 당시와 다르다(시간 누수). |
| D7 | 규칙의 **조건은 Python 코드**, **가중치·경계값은 `rules.yaml`**. | 조건은 타입 검사/테스트가 쉬운 코드로, 보정(T17)은 yaml만 수정하도록 분리. |
| D8 | ML은 `LogisticRegression`(해석 가능, 결측 대치 필요)과 `HistGradientBoostingClassifier`(NaN 기본 지원) 두 개를 같은 특징·같은 분할로 학습해 규칙 베이스라인과 비교. | 명세 4번. 두 모델은 sklearn 기본 구성만으로 Windows에서 바로 동작. |
| D9 | 학습/테스트 분할은 `registered_domain` 기준 **그룹 분할**(`GroupShuffleSplit`). | 같은 도메인의 URL이 train/test에 나뉘면 성능이 부풀려진다. |
| D10 | 최종 판정(`final_verdict`)은 규칙 등급과 ML 등급 중 **더 위험한 쪽**. 화면에는 둘 다 표시. | 사용자 보호 우선. Open Question Q3에서 재검토. |
| D11 | 웹은 `create_app(analyzer)` 팩토리 + `SupportsAnalyze` 프로토콜로 의존성 주입. | UI를 비즈니스 로직보다 먼저 완성·테스트하기 위함(Phase 2). |

---

## 리스크

| # | 리스크 | 영향 | 대응 | 담당 Task |
|---|---|---|---|---|
| K1 | **데이터셋 편향**: 정상 URL은 대부분 홈페이지(`https://www.x.com/`), 피싱은 경로가 긴 URL → 모델이 "경로 길이"만 학습 | 실제 성능이 지표보다 크게 낮음 | 편향 감사: `url_length`+`path_length`만으로 학습한 LR의 ROC-AUC를 리포트에 기록, 0.90 초과 시 경고 문구 출력. 신규 수집 데이터로 별도 검증 | T15 |
| K2 | **도메인 나이 시간 누수** (D6) | 도메인 나이 특징 과대평가 | 과거 데이터는 NaN, 수집 시점 스냅샷만 사용. "어휘 특징 전용 모델"과 "나이 포함 모델"을 분리 평가 | T12–T15 |
| K3 | **클로킹/인터스티셜**: 일부 단축 URL은 봇에게 다른 응답을 주거나 미리보기 페이지(200 OK)를 보여줌 | 최종 주소 확인 실패 | 브라우저 User-Agent 사용, 실패 시 `complete=False` + 경고 문구 "단축 URL의 최종 주소를 확인하지 못했습니다". 단축 URL 사용 자체를 규칙 신호로 사용 | T7, T10 |
| K4 | **SSRF** | 내부망 정보 노출 | D1, D2 | T7 |
| K5 | **RDAP 속도 제한(429)/WHOIS 차단** | 대량 수집 시 실패, 응답 지연 | 캐시(D5), 429는 1시간 부정 캐시, 수집기는 요청 간 최소 간격 1초, 웹 요청당 외부 조회 타임아웃 8초 | T8, T13 |
| K6 | **해킹된 정상 사이트에 올린 피싱**: 오래된 도메인이라 나이 신호가 반대로 작동 | 미탐 | 나이는 여러 신호 중 하나로만 사용(가중치 상한), 경로 내 브랜드명 신호로 보완. 한계로 문서화 | T10, T18 |
| K7 | **브랜드 키워드 오탐**: 짧은 키워드(`kb`, `cj`, `toss`)가 무관한 단어에 매칭 | 정상 URL 오탐 | 토큰 경계 매칭 규칙(T9 `match_keywords`) + 5자 미만 키워드는 정확 토큰 일치만 허용 | T9 |
| K8 | **모델 아티팩트 호환성**: joblib 피클은 sklearn 버전이 다르면 로드 실패/오동작 | 서빙 실패 | 아티팩트에 `sklearn_version`, `feature_names`, `feature_schema_version` 저장, 로드 시 불일치면 `ModelLoadError` 후 규칙만으로 동작 | T14, T16 |
| K9 | **개념 변화(drift)**: 피싱 수법이 바뀜 | 시간이 지나면 성능 저하 | 수집기(T13)로 주기적 신규 데이터 확보, 신규 데이터 검증 지표를 리포트에 별도 기재 | T13, T15 |
| K10 | **윤리/안전**: 수집한 피싱 URL을 화면/리포트에 클릭 가능한 링크로 노출 | 2차 피해 | 화면과 리포트는 항상 `defang()` 표기(`hxxps://evil[.]com`), `<a href>` 금지 | T4, T15 |

---

## 외부 데이터 연동 및 싱크 전략

| 소스 | 용도 | 접근 방식 | 갱신/캐시 정책 | 재현성 기록 |
|---|---|---|---|---|
| Public Suffix List | 등록 도메인 추출 | tldextract 번들 스냅샷 | 기본 오프라인. 환경변수 `PHISHGUARD_PSL_REFRESH=1`이면 시작 시 최신 PSL 다운로드(tldextract 기본 URL) | tldextract 버전을 `pyproject.toml`에 고정, 학습 manifest에 기록 |
| IANA RDAP bootstrap `https://data.iana.org/rdap/dns.json` | TLD → RDAP 서버 매핑 | httpx GET | TTL 캐시 7일(키 `rdap:bootstrap`) | — |
| RDAP 서버 / WHOIS | 도메인 생성일 | `{base}/domain/{domain}` / `whois.whois()` | 성공: 30일, 실패: 1일, 429: 1시간 (키 `age:{domain}`) | 학습 데이터에는 조회 시각(`collected_at`)과 함께 스냅샷 저장 |
| 단축 URL 서비스 | 최종 주소 확인 | HEAD → (405/403/400/501이면) GET 스트림, 본문 미수신 | 캐시 1시간(키 `redir:{url}`) — 단축 URL은 대상이 바뀔 수 있어 짧게 | — |
| PhiUSIIL Phishing URL Dataset (UCI #967) | 기본 학습 데이터 | 수동 다운로드 → `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv` | 정적 | 파일 SHA-256을 `data/processed/manifest.json`에 기록 |
| OpenPhish Community feed `https://openphish.com/feed.txt` | 신규 피싱 URL(검증용 + 나이 포함 학습) | `collect_feed` 명령, 하루 1회 실행 | append-only CSV, 정규화 URL 기준 중복 제거, 수집 즉시 도메인 나이 조회 | 각 행에 `source`, `collected_at` |
| Tranco Top 1M (`https://tranco-list.eu/top-1m.csv.zip`) | 신규 정상 URL(홈페이지) | `collect_feed --benign-tranco` | 수집 시 list 날짜 기록 | manifest에 Tranco list ID/날짜 |
| 수동 한국형 샘플 `data/raw/manual_kr.csv` | 한국 스미싱/정상 URL 보강 | 사용자가 직접 작성(`url,label,source,collected_at`) | 수동 | manifest |

**싱크 원칙:** (1) 외부 조회 결과는 원본 응답 대신 정규화된 값(`creation_date` ISO 문자열 등)만 캐시한다. (2) 캐시 미스+외부 실패는 분석을 막지 않는다(결측으로 진행). (3) 학습 데이터는 append-only이며, 학습 시점에 `manifest.json`으로 입력 파일 해시·행 수·생성 시각을 고정해 재학습 결과를 재현 가능하게 한다.

---

## Open Questions

각 질문에는 **기본값**이 있어 답이 없어도 진행 가능하다. 답이 나오면 해당 Task를 수정한다.

| # | 질문 | 기본값 (답이 없을 때) | 영향 Task |
|---|---|---|---|
| Q1 | PhishTank API 키(신규 가입 제한 여부)를 확보할 수 있는가? | PhishTank 미사용. PhiUSIIL + OpenPhish + 수동 한국 샘플 | T12, T13 |
| Q2 | `.kr` 도메인 생성일이 RDAP/`python-whois`로 조회되는가? | T8의 network 테스트로 확인. 실패하면 Task를 추가해 `whois.kr` 응답의 `등록일`/`Registered Date` 줄을 파싱하는 전용 함수 작성 | T8 |
| Q3 | 규칙과 ML 판정이 다를 때 최종 판정 정책은? | 더 위험한 쪽(D10) | T16 |
| Q4 | 서비스 공개 범위: 로컬 데모만인가, 외부 공개 서버인가? | 로컬/동아리 데모. 공개 시 속도 제한·요청 로그 개인정보 처리 Task 추가 필요 | T18 |
| Q5 | 단축 URL이 아닌 일반 리다이렉트(오픈 리다이렉트 등)도 따라가야 하는가? | 따라가지 않음(D1). URL 쿼리에 다른 URL이 들어있으면 `has_embedded_url` 경고만 표시 | T7, T9 |
| Q6 | 브랜드 목록 범위 | 국내 20개 + 해외 10개(T2) | T2 |
| Q7 | 서빙 모델: 어휘 전용 vs 나이 포함 | T15 결과로 결정. 나이 포함 데이터가 클래스별 1,000건 미만이면 어휘 전용 모델 사용, 도메인 나이는 규칙에서만 사용 | T15, T16 |

---

## Phase별 완료 기준 (Definition of Done)

| Phase | 완료 기준 |
|---|---|
| 1 | `python -m pytest` 전체 통과. `from phishguard.models import AnalysisResult, FEATURE_NAMES` 및 `load_resources()`가 동작. 리소스 파일 스키마 검증 테스트 통과. |
| 2 | `uvicorn phishguard.web.main:app --reload` 실행 후 브라우저에서 `http://127.0.0.1:8000/` 입력 → 결과 화면(스텁 데이터) 표시. `POST /api/analyze` JSON 스키마 테스트 통과. XSS 이스케이프 테스트 통과. |
| 3 | 실제 `Analyzer`가 스텁을 대체. 네트워크 없이 전체 테스트 통과. `python -m pytest -m network` 수동 실행 시 `bit.ly` 해석과 `google.com` 생성일 조회 성공. 화면에 규칙 점수·이유 표시. |
| 4 | `data/processed/dataset.csv`, `models/model.joblib`, `reports/evaluation.md`, `reports/metrics.json` 생성. 리포트에 규칙/LR/HGB 비교표, 편향 감사, 신규 데이터 검증 결과 포함. 화면에 ML 확률 표시. |
| 5 | `rules.yaml`과 모델 아티팩트의 경계값이 검증 세트로 보정되어 있고, 보정 근거가 리포트에 기록됨. README로 처음 보는 사람이 설치→학습→실행 가능. Dockerfile 빌드(Docker 설치 시) 성공. |

---

# Phase 1 — 데이터 모델 및 신규 타입 정의

### Task 1: 프로젝트 골격 + 도메인 타입

**Files:**
- Create: `pyproject.toml`, `.gitignore`, `src/phishguard/__init__.py`, `src/phishguard/errors.py`, `src/phishguard/models.py`
- Create: `tests/conftest.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Consumes: 없음
- Produces (이후 모든 Task가 이 이름과 타입을 그대로 사용):

```python
# errors.py
class InvalidURLError(ValueError): ...          # str(e)는 한국어 사용자 메시지

# models.py
FEATURE_SCHEMA_VERSION: int = 1
FEATURE_NAMES: tuple[str, ...] = (
    "url_length", "host_length", "path_length", "num_subdomains",
    "num_dots_host", "num_hyphens_host", "num_digits_host", "is_ip_host",
    "has_userinfo", "has_punycode", "is_https", "has_nonstandard_port",
    "num_query_params", "num_suspicious_keywords", "brand_in_subdomain",
    "brand_in_path", "brand_in_domain_label", "is_shortener", "redirect_count",
    "is_private_suffix", "is_risky_tld", "host_entropy", "has_embedded_url",
    "domain_age_days", "domain_age_unknown",
)  # 25개

class Verdict(str, Enum):
    SAFE = "safe"; SUSPICIOUS = "suspicious"; DANGEROUS = "dangerous"
    @property
    def severity(self) -> int: ...               # SAFE=0, SUSPICIOUS=1, DANGEROUS=2
    @staticmethod
    def most_severe(*verdicts: "Verdict") -> "Verdict": ...

@dataclass(frozen=True)
class NormalizedURL:
    original: str; normalized: str; scheme: str; userinfo: str; host: str
    port: int | None; path: str; query: str; was_refanged: bool; scheme_added: bool

@dataclass(frozen=True)
class RedirectHop:
    url: str; status_code: int

@dataclass(frozen=True)
class RedirectResult:
    final_url: str; hops: tuple[RedirectHop, ...]; is_shortener: bool; complete: bool; error: str | None
    @classmethod
    def not_followed(cls, url: str) -> "RedirectResult": ...   # hops=(), is_shortener=False, complete=True, error=None

@dataclass(frozen=True)
class URLParts:
    host: str; subdomain: str; domain: str; suffix: str
    registered_domain: str      # ICANN 기준 "domain.suffix", 없으면 ""
    site_domain: str            # PSL private 섹션 포함 기준, 없으면 ""
    is_ip: bool; is_private_suffix: bool

@dataclass(frozen=True)
class DomainInfo:
    domain: str; creation_date: datetime | None; age_days: float | None
    source: Literal["rdap", "whois", "snapshot", "none"]; cached: bool; error: str | None
    @classmethod
    def unknown(cls, domain: str, error: str | None = None) -> "DomainInfo": ...

@dataclass(frozen=True)
class FeatureVector:
    values: Mapping[str, float]          # 키 집합 == set(FEATURE_NAMES), 결측은 math.nan
    evidence: Mapping[str, str]          # 예: {"brand_in_subdomain": "네이버"}
    def to_list(self) -> list[float]: ...   # FEATURE_NAMES 순서
    def __post_init__(self) -> None: ...    # 키 집합 불일치 시 ValueError

@dataclass(frozen=True)
class RuleHit:
    rule_id: str; weight: int; message: str

@dataclass(frozen=True)
class RuleResult:
    score: int; verdict: Verdict; hits: tuple[RuleHit, ...]

@dataclass(frozen=True)
class ModelResult:
    probability: float; verdict: Verdict; model_version: str

@dataclass(frozen=True)
class AnalysisResult:
    input_url: str; normalized: NormalizedURL; redirect: RedirectResult; parts: URLParts
    domain: DomainInfo; features: FeatureVector; rule: RuleResult; model: ModelResult | None
    warnings: tuple[str, ...]
    @property
    def final_verdict(self) -> Verdict: ...   # model이 None이면 rule.verdict, 아니면 most_severe (D10)
    def to_dict(self) -> dict[str, Any]: ...  # 아래 JSON 스키마, NaN → None, datetime → ISO 8601

@dataclass(frozen=True)
class LabeledURL:
    url: str; label: int; source: str; collected_at: datetime | None; domain_age_days: float | None
```

`AnalysisResult.to_dict()` JSON 스키마 (웹 API 응답과 동일, `model`은 모델이 없으면 `null`):

```json
{
  "input_url": "str", "normalized_url": "str", "final_url": "str",
  "redirect": {"is_shortener": "bool", "complete": "bool", "error": "str|null",
               "hops": [{"url": "str", "status_code": "int"}]},
  "domain": {"host": "str", "registered_domain": "str", "subdomain": "str", "suffix": "str",
             "is_ip": "bool", "creation_date": "str|null", "age_days": "float|null", "source": "str"},
  "features": {"<FEATURE_NAMES 각각>": "float|null"},
  "rule": {"score": "int", "verdict": "safe|suspicious|dangerous",
           "hits": [{"rule_id": "str", "weight": "int", "message": "str"}]},
  "model": {"probability": "float", "verdict": "str", "model_version": "str"},
  "final_verdict": "safe|suspicious|dangerous",
  "warnings": ["str"]
}
```

- [ ] **Step 1: 저장소 초기화와 `pyproject.toml` 작성**

`git init`. `pyproject.toml`: 빌드 백엔드 `setuptools>=68`, `[project] name = "phishguard"`, `requires-python = ">=3.11,<3.12"`, Global Constraints의 의존성, `[project.optional-dependencies] dev = ["pytest>=8.0", "respx>=0.21"]`, `[tool.setuptools.packages.find] where = ["src"]`, `[tool.setuptools.package-data] phishguard = ["resources/*", "web/templates/*", "web/static/*"]`, `[tool.pytest.ini_options]`에 `testpaths = ["tests"]`, `addopts = "-m 'not network'"`, `markers = ["network: requires internet access"]`.
`.gitignore`: `.venv/`, `__pycache__/`, `*.egg-info/`, `data/raw/`, `data/processed/`, `models/*.joblib`, `cache.sqlite3`, `.pytest_cache/`.

Run: `py -3.11 -m venv .venv` → 활성화 → `python -m pip install -e ".[dev]"`
Expected: `Successfully installed ... phishguard-0.1.0`

- [ ] **Step 2: 실패하는 테스트 작성 — `tests/test_models.py`**

```python
def test_feature_names_are_unique_and_25():
    assert len(FEATURE_NAMES) == 25 and len(set(FEATURE_NAMES)) == 25

def test_feature_vector_orders_by_feature_names():
    values = {n: float(i) for i, n in enumerate(FEATURE_NAMES)}
    fv = FeatureVector(values=values, evidence={})
    assert fv.to_list() == [float(i) for i in range(25)]

def test_feature_vector_rejects_missing_key():
    with pytest.raises(ValueError):
        FeatureVector(values={n: 0.0 for n in FEATURE_NAMES[:-1]}, evidence={})

def test_verdict_most_severe():
    assert Verdict.most_severe(Verdict.SAFE, Verdict.DANGEROUS, Verdict.SUSPICIOUS) is Verdict.DANGEROUS

def test_final_verdict_without_model_is_rule_verdict(sample_result):
    assert sample_result.final_verdict is sample_result.rule.verdict

def test_final_verdict_with_model_is_most_severe(sample_result):
    r = dataclasses.replace(sample_result, model=ModelResult(0.9, Verdict.DANGEROUS, "v1"))
    assert r.final_verdict is Verdict.DANGEROUS

def test_to_dict_is_json_serializable_and_nan_is_none(sample_result):
    d = sample_result.to_dict()
    json.dumps(d, allow_nan=False)                  # 예외 없어야 함
    assert d["features"]["domain_age_days"] is None
    assert d["final_verdict"] == "suspicious"
    assert set(d["features"]) == set(FEATURE_NAMES)
    assert d["model"] is None
```

`tests/conftest.py`의 `sample_result` 픽스처는 `phishguard.web.stub.make_sample_result()`를 호출한다. 이 함수는 T3에서 만들지만, T1에서는 같은 내용을 `tests/conftest.py`에 임시로 직접 구성하고 T3 Step 3에서 `make_sample_result()` 호출로 교체한다. 내용: 입력 `"http://naver.com.login-check.xyz/a"`, `rule = RuleResult(45, Verdict.SUSPICIOUS, (RuleHit("R03", 35, "'네이버' 브랜드명이 실제 등록 도메인이 아닌 서브도메인에 있습니다"),))`, `model=None`, `domain_age_days=nan`, `domain_age_unknown=1.0`, 나머지 특징 `0.0`, `warnings=()`.

- [ ] **Step 3: 실행하여 실패 확인**

Run: `python -m pytest tests/test_models.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'phishguard.models'`)

- [ ] **Step 4: `errors.py`, `models.py`, `__init__.py`(`__version__ = "0.1.0"`) 구현**

Interfaces 블록 시그니처 그대로. `to_dict`의 NaN 판정은 `math.isnan`, datetime은 `.isoformat()`.

- [ ] **Step 5: 통과 확인** — Run: `python -m pytest -v` → Expected: `7 passed`

- [ ] **Step 6: Commit**

```bash
git add pyproject.toml .gitignore src tests
git commit -m "feat: project scaffold and core domain types"
```

---

### Task 2: 리소스 파일과 설정 로더

**Files:**
- Create: `src/phishguard/resources/brands.yaml`, `shorteners.txt`, `risky_tlds.txt`, `suspicious_keywords.txt`, `rules.yaml`
- Create: `src/phishguard/config.py`
- Test: `tests/test_config.py`

**Interfaces:**
- Consumes: 없음
- Produces:

```python
@dataclass(frozen=True)
class Brand:
    name: str                          # 표시용 이름, 예: "네이버"
    keywords: tuple[str, ...]          # 소문자 ASCII, 예: ("naver",)
    official_domains: frozenset[str]   # ICANN 등록 도메인, 예: {"naver.com", "naver.me"}

@dataclass(frozen=True)
class Resources:
    brands: tuple[Brand, ...]
    shorteners: frozenset[str]
    risky_tlds: frozenset[str]          # 점 없이 소문자, 예: "xyz"
    suspicious_keywords: tuple[str, ...]
    rule_weights: Mapping[str, int]     # rule_id -> weight
    rule_thresholds: tuple[int, int]    # (suspicious_min, dangerous_min)

def resource_dir() -> Path                                    # 패키지 내 resources/
def load_resources(directory: Path | None = None) -> Resources

@dataclass(frozen=True)
class Settings:
    cache_path: Path      # env PHISHGUARD_CACHE_PATH, 기본 Path.cwd() / "cache.sqlite3"
    model_path: Path      # env PHISHGUARD_MODEL_PATH, 기본 Path.cwd() / "models" / "model.joblib"
    psl_refresh: bool     # env PHISHGUARD_PSL_REFRESH == "1"
    http_timeout: float   # 기본 5.0
    lookup_timeout: float # 기본 8.0
def load_settings() -> Settings
```

리소스 파일 형식:
- `*.txt`: 한 줄에 하나, `#` 주석과 빈 줄 무시, 소문자로 정규화.
- `brands.yaml`: `brands: [{name, keywords: [...], official_domains: [...]}]`
- `rules.yaml`: `weights: {R01: 40, ...}`, `thresholds: {suspicious: 30, dangerous: 60}`

초기 내용(이 값으로 시작, 추가는 자유):
- `shorteners.txt`: bit.ly, tinyurl.com, t.co, goo.gl, ow.ly, is.gd, buff.ly, cutt.ly, rebrand.ly, t.ly, shorturl.at, rb.gy, han.gl, me2.do, vo.la, url.kr, buly.kr, c11.kr, naver.me, abit.ly, lrl.kr
- `risky_tlds.txt`: xyz, top, icu, shop, click, link, online, site, live, buzz, cyou, rest, sbs, cfd, monster, gq, tk, ml, cf, ga
- `suspicious_keywords.txt`: login, signin, verify, verification, account, update, secure, security, confirm, banking, password, wallet, auth, webscr, unlock, suspend, billing, payment, delivery, parcel, refund, invoice, otp, certify
- `brands.yaml` 국내 20 — `이름(keywords; official_domains)`: 네이버(naver; naver.com, naver.me), 카카오(kakao, kakaotalk; kakao.com, kakaocorp.com), 쿠팡(coupang; coupang.com), 우체국(epost, koreapost; epost.go.kr, koreapost.go.kr), CJ대한통운(cjlogistics, doortodoor; cjlogistics.com), 한진택배(hanjin; hanjin.com, hanjin.co.kr), 롯데택배(lotteglogis; lotteglogis.com), 정부24(gov24; gov.kr), 홈택스(hometax; hometax.go.kr), 국민건강보험(nhis; nhis.or.kr), 국민은행(kbstar, kbcard; kbstar.com, kbcard.com), 신한(shinhan; shinhan.com, shinhancard.com), 우리은행(wooribank; wooribank.com), 하나은행(hanabank; hanabank.com), 농협(nonghyup, nhbank; nonghyup.com), 토스(toss; toss.im, tossbank.com), 카카오뱅크(kakaobank; kakaobank.com), 삼성(samsung; samsung.com), 배달의민족(baemin; baemin.com), 11번가(11st; 11st.co.kr)
- 해외 10: PayPal(paypal; paypal.com), Apple(apple, icloud; apple.com, icloud.com), Microsoft(microsoft, outlook, office365; microsoft.com, live.com, office.com, outlook.com), Google(google, gmail; google.com, gmail.com), Amazon(amazon; amazon.com), Netflix(netflix; netflix.com), Facebook(facebook; facebook.com), Instagram(instagram; instagram.com), DHL(dhl; dhl.com), Binance(binance; binance.com)
- `rules.yaml`: weights = T10 규칙 표의 초기 가중치, thresholds = `suspicious: 30`, `dangerous: 60`

- [ ] **Step 1: 실패하는 테스트 작성 — `tests/test_config.py`**

```python
def test_load_default_resources():
    r = load_resources()
    assert "bit.ly" in r.shorteners and "han.gl" in r.shorteners
    assert "xyz" in r.risky_tlds
    assert r.rule_thresholds == (30, 60)
    assert len(r.brands) == 30

def test_korean_brands_and_shorteners_present():          # Review Focus 1
    r = load_resources()
    names = {b.name for b in r.brands}
    assert {"우체국", "CJ대한통운", "국민건강보험", "정부24", "네이버"} <= names
    assert {"me2.do", "vo.la", "url.kr", "naver.me"} <= r.shorteners

def test_brand_keywords_are_lowercase_ascii():
    for b in load_resources().brands:
        assert b.keywords and b.official_domains
        for k in b.keywords:
            assert k == k.lower() and k.isascii()

def test_rule_weights_cover_all_rule_ids():
    assert set(load_resources().rule_weights) == {f"R{i:02d}" for i in range(1, 19)}

def test_txt_loader_ignores_comments_and_blank(tmp_path):
    shutil.copytree(resource_dir(), tmp_path, dirs_exist_ok=True)
    (tmp_path / "shorteners.txt").write_text("# c\n\nBIT.LY\n", encoding="utf-8")
    assert load_resources(tmp_path).shorteners == frozenset({"bit.ly"})

def test_invalid_thresholds_raise(tmp_path):
    shutil.copytree(resource_dir(), tmp_path, dirs_exist_ok=True)
    # rules.yaml의 thresholds를 suspicious: 60, dangerous: 30으로 덮어쓴 뒤
    with pytest.raises(ValueError):
        load_resources(tmp_path)
```

- [ ] **Step 2: 실행하여 실패 확인** — Run: `python -m pytest tests/test_config.py -v` → Expected: FAIL (ImportError)

- [ ] **Step 3: 리소스 파일과 `config.py` 구현**

`resource_dir()`는 `Path(str(importlib.resources.files("phishguard") / "resources"))`. YAML은 `yaml.safe_load`만 사용. 모든 파일은 `encoding="utf-8"`로 읽는다(Windows 기본 인코딩 cp949 회피).

- [ ] **Step 4: 통과 확인** — Run: `python -m pytest -v` → Expected: 전체 PASS

- [ ] **Step 5: Commit** — `git add src tests && git commit -m "feat: resource files and config loader"`

**Phase 1 검증:** `python -m pytest -v` 전체 통과 + `python -c "from phishguard.config import load_resources; print(len(load_resources().brands))"` → `30`

---

# Phase 2 — 사용자 인터페이스 (스텁 Analyzer로 동작)

이 Phase는 비즈니스 로직 없이 UI와 API 계약을 먼저 고정한다. 이후 Phase는 이 계약(`SupportsAnalyze`, JSON 스키마)을 바꾸지 않는다.

### Task 3: FastAPI 앱 팩토리, JSON API, 스텁 Analyzer

**Files:**
- Create: `src/phishguard/web/__init__.py`, `src/phishguard/web/app.py`, `src/phishguard/web/stub.py`, `src/phishguard/web/main.py`
- Modify: `tests/conftest.py` (`sample_result` → `make_sample_result()` 사용)
- Test: `tests/test_web_api.py`

**Interfaces:**
- Consumes: T1 `AnalysisResult`, `InvalidURLError`
- Produces:

```python
# web/app.py
class SupportsAnalyze(Protocol):
    def analyze(self, raw_url: str) -> AnalysisResult: ...

def create_app(analyzer: SupportsAnalyze) -> FastAPI
# 라우트
#   GET  /healthz          -> {"status": "ok"}
#   POST /api/analyze      body {"url": str}  -> 200 AnalysisResult.to_dict()
#                          InvalidURLError    -> 400 {"error": "<한국어 메시지>"}
#                          url 누락/빈 문자열 -> 400 {"error": "URL을 입력해 주세요."}
#                          len(url) > 2048    -> 400 {"error": "URL이 너무 깁니다."}
#                          그 외 예외          -> 500 {"error": "분석 중 오류가 발생했습니다."} (스택트레이스는 로그에만)

# web/stub.py
def make_sample_result(raw_url: str = "http://naver.com.login-check.xyz/a") -> AnalysisResult
class StubAnalyzer:
    def analyze(self, raw_url: str) -> AnalysisResult   # raw_url.strip()이 "invalid"이면 InvalidURLError("올바른 URL 형식이 아닙니다."), 아니면 make_sample_result(raw_url)

# web/main.py
def build_default_analyzer() -> SupportsAnalyze      # Phase 2: StubAnalyzer(), T11에서 실제 Analyzer로 교체
app: FastAPI = create_app(build_default_analyzer())
```

엔드포인트 함수는 `def`(동기)로 선언한다. FastAPI가 스레드풀에서 실행하므로 동기 httpx 호출이 이벤트 루프를 막지 않는다.

- [ ] **Step 1: 실패하는 테스트 작성 — `tests/test_web_api.py`**

```python
@pytest.fixture
def client():
    return TestClient(create_app(StubAnalyzer()))

def test_healthz(client):
    assert client.get("/healthz").json() == {"status": "ok"}

def test_api_analyze_returns_schema(client):
    r = client.post("/api/analyze", json={"url": "http://naver.com.login-check.xyz/a"})
    assert r.status_code == 200
    body = r.json()
    assert {"input_url", "normalized_url", "final_url", "redirect", "domain",
            "features", "rule", "model", "final_verdict", "warnings"} <= set(body)
    assert body["final_verdict"] in {"safe", "suspicious", "dangerous"}

def test_api_invalid_url_returns_400_korean(client):
    r = client.post("/api/analyze", json={"url": "invalid"})
    assert r.status_code == 400 and r.json()["error"] == "올바른 URL 형식이 아닙니다."

@pytest.mark.parametrize("payload", [{}, {"url": ""}, {"url": "   "}])
def test_api_empty_url_returns_400(client, payload):
    r = client.post("/api/analyze", json=payload)
    assert r.status_code == 400 and r.json()["error"] == "URL을 입력해 주세요."

def test_api_too_long_url_returns_400(client):
    r = client.post("/api/analyze", json={"url": "http://a.com/" + "a" * 2100})
    assert r.status_code == 400

def test_api_unexpected_error_returns_500():
    class Boom:
        def analyze(self, raw_url): raise RuntimeError("x")
    r = TestClient(create_app(Boom()), raise_server_exceptions=False).post("/api/analyze", json={"url": "http://a.com"})
    assert r.status_code == 500 and r.json() == {"error": "분석 중 오류가 발생했습니다."}
```

- [ ] **Step 2: 실행하여 실패 확인** — Run: `python -m pytest tests/test_web_api.py -v` → Expected: FAIL (ImportError)

- [ ] **Step 3: `app.py`, `stub.py`, `main.py` 구현, `conftest.py`의 `sample_result`를 `make_sample_result()`로 교체**

요청 바디는 Pydantic 모델 대신 `dict`로 받아 직접 검증한다(누락 키가 FastAPI 기본 422가 아니라 400 + 한국어 메시지가 되도록). 입력 길이 검사는 앱 계층에서 수행.

- [ ] **Step 4: 통과 확인** — Run: `python -m pytest -v` → Expected: 전체 PASS

- [ ] **Step 5: Commit** — `git add src tests && git commit -m "feat: FastAPI app factory with JSON API and stub analyzer"`

---

### Task 4: HTML 화면 (입력 폼 + 결과)

**Files:**
- Create: `src/phishguard/web/presenters.py`, `src/phishguard/web/templates/base.html`, `index.html`, `result.html`, `src/phishguard/web/static/style.css`
- Modify: `src/phishguard/web/app.py` (HTML 라우트 추가, `StaticFiles` 마운트 `/static`)
- Test: `tests/test_web_html.py`, `tests/test_presenters.py`

**Interfaces:**
- Consumes: T3 `create_app`, `StubAnalyzer`, `make_sample_result`
- Produces:

```python
# presenters.py
VERDICT_LABELS: Mapping[Verdict, str] = {SAFE: "안전", SUSPICIOUS: "주의", DANGEROUS: "위험"}
def defang(url: str) -> str     # "http"로 시작하면 "hxxp", 호스트의 "." → "[.]" (경로는 그대로)
# 라우트
#   GET  /           -> index.html (폼: <form method="post" action="/analyze">, <input name="url">)
#   POST /analyze    -> form field "url" -> result.html, 오류 시 index.html에 오류 메시지와 입력값 유지(상태 400)
```

결과 화면 필수 요소(위에서 아래 순서):
1. 최종 판정 배지(`VERDICT_LABELS`, 색상: 안전=초록, 주의=주황, 위험=빨강) — CSS 클래스 `verdict-safe|verdict-suspicious|verdict-dangerous`
2. 입력 URL과 최종 URL — **반드시 `defang()` 처리한 텍스트로만 표시, `<a href>` 금지** (리스크 K10)
3. 리다이렉트 경로(hops) — 단축 URL이 아니면 "리다이렉트 없음"
4. 등록 도메인, 서브도메인, 도메인 생성일/나이("확인 불가" 가능)
5. 규칙 기반 판정: 점수, 등급, `hits`의 `message` 목록("판정 이유")
6. ML 판정: 확률(%)과 등급, 모델이 없으면 "학습된 모델 없음"
7. `warnings` 목록
8. 고지문: "이 결과는 참고용이며 안전을 보장하지 않습니다. 의심되면 링크를 열지 마세요."

- [ ] **Step 1: 실패하는 테스트 작성**

```python
# tests/test_presenters.py
@pytest.mark.parametrize("url, expected", [
    ("https://evil.com/login", "hxxps://evil[.]com/login"),
    ("http://a.b.c/x.html", "hxxp://a[.]b[.]c/x.html"),
    ("http://1.2.3.4/", "hxxp://1[.]2[.]3[.]4/"),
])
def test_defang(url, expected):
    assert defang(url) == expected

# tests/test_web_html.py
def test_index_has_form(client):
    html = client.get("/").text
    assert '<form method="post" action="/analyze"' in html and 'name="url"' in html

def test_result_page_shows_verdict_reasons_and_disclaimer(client):
    html = client.post("/analyze", data={"url": "http://naver.com.login-check.xyz/a"}).text
    assert "주의" in html and "verdict-suspicious" in html
    assert "서브도메인에 있습니다" in html
    assert "참고용이며 안전을 보장하지 않습니다" in html
    assert "hxxp://naver[.]com[.]login-check[.]xyz/a" in html

def test_result_page_has_no_clickable_input_link(client):
    html = client.post("/analyze", data={"url": "http://naver.com.login-check.xyz/a"}).text
    assert 'href="http://naver.com.login-check.xyz' not in html

def test_input_is_html_escaped(client):
    html = client.post("/analyze", data={"url": 'http://a.com/"><script>alert(1)</script>'}).text
    assert "<script>alert(1)</script>" not in html

def test_invalid_url_rerenders_form_with_error(client):
    r = client.post("/analyze", data={"url": "invalid"})
    assert r.status_code == 400 and "올바른 URL 형식이 아닙니다." in r.text and 'value="invalid"' in r.text
```

(`client` 픽스처는 T3과 동일하게 `conftest.py`로 옮긴다.)

- [ ] **Step 2: 실행하여 실패 확인** — Run: `python -m pytest tests/test_web_html.py tests/test_presenters.py -v` → Expected: FAIL

- [ ] **Step 3: 구현**

`Jinja2Templates(directory=<패키지 내 templates 경로>)` — 자동 이스케이프 기본값 유지(`|safe` 사용 금지). 템플릿에 `AnalysisResult.to_dict()` 결과와 `VERDICT_LABELS`, `defang`을 전달. CSS는 외부 CDN 없이 `style.css` 하나, 모바일 폭(360px)에서 가로 스크롤이 생기지 않게 `word-break: break-all`을 URL 영역에 적용.

- [ ] **Step 4: 통과 확인** — Run: `python -m pytest -v` → Expected: 전체 PASS

- [ ] **Step 5: 수동 확인**

Run: `uvicorn phishguard.web.main:app --reload` → 브라우저 `http://127.0.0.1:8000/`에서 아무 URL 입력
Expected: 스텁 결과 화면(주의 배지, 판정 이유 1개, 고지문) 표시. 확인 후 서버 종료.

- [ ] **Step 6: Commit** — `git add src tests && git commit -m "feat: HTML form and result pages with defanged display"`

**Phase 2 검증:** Phase별 완료 기준 표의 Phase 2 항목.

---

# Phase 3 — 비즈니스 로직 (1): 규칙 기반 분석 파이프라인

### Task 5: URL 정규화

**Files:**
- Create: `src/phishguard/normalize.py`
- Test: `tests/test_normalize.py`

**Interfaces:**
- Consumes: T1 `NormalizedURL`, `InvalidURLError`
- Produces: `normalize_url(raw: str, *, refang: bool = True) -> NormalizedURL`, `MAX_URL_LENGTH: int = 2048`

알고리즘(순서 고정):
1. 앞뒤 공백 제거, 제로폭/BOM 문자(`​ ‌ ‍ ⁠ ﻿`) 전부 제거, 양끝을 감싼 `<>`, `"`, `'` 한 쌍 제거.
2. `refang=True`면: 맨 앞 `hxxp`/`hXXp`(대소문자 무시) → `http`, `[.]`·`(.)`·`{.}` → `.`, `[:]` → `:`. 하나라도 바뀌면 `was_refanged=True`.
3. 빈 문자열 → `InvalidURLError("URL을 입력해 주세요.")`. 길이 > `MAX_URL_LENGTH` → `InvalidURLError("URL이 너무 깁니다.")`.
4. `^(javascript|data|file|vbscript|mailto):`(대소문자 무시)면 `InvalidURLError("웹 주소(http/https)만 검사할 수 있습니다.")`.
5. `^[a-zA-Z][a-zA-Z0-9+.-]*://`가 없으면 앞에 `http://`를 붙이고 `scheme_added=True`. (`example.com:8080/x`를 `urlsplit`이 scheme으로 오인하는 문제 방지.)
6. `urllib.parse.urlsplit`. scheme 소문자화, `http`/`https`가 아니면 4번과 같은 오류.
7. host = `.hostname`(소문자, IPv6 괄호 제거됨) 끝의 `.` 제거. 비어 있으면 `InvalidURLError("올바른 URL 형식이 아닙니다.")`. ASCII가 아니면 `idna.encode(host, uts46=True).decode("ascii")`, 실패 시 `host.encode("idna").decode("ascii")`, 그것도 실패하면 같은 오류.
8. `.port` 접근 시 `ValueError` → 같은 오류. 기본 포트(http:80, https:443)는 `None`.
9. userinfo = netloc의 `@` 앞부분(없으면 `""`). path가 비면 `"/"`. fragment 제거. query 유지. path·query의 대소문자 유지.
10. `normalized = f"{scheme}://{userinfo + '@' if userinfo else ''}{host_for_url}{':' + str(port) if port else ''}{path}{'?' + query if query else ''}"` — `host_for_url`은 IPv6면 `[host]`.

- [ ] **Step 1: 실패하는 테스트 작성 — `tests/test_normalize.py`**

```python
@pytest.mark.parametrize("raw, expected", [
    ("  HTTPS://WWW.Example.COM:443/Path?q=1#frag ", "https://www.example.com/Path?q=1"),
    ("example.com", "http://example.com/"),
    ("example.com:8080/x", "http://example.com:8080/x"),
    ("http://example.com./", "http://example.com/"),
    ("​http://a.com/﻿", "http://a.com/"),
    ("<http://a.com/b>", "http://a.com/b"),
    ("http://[::1]:8080/", "http://[::1]:8080/"),
])
def test_messy_inputs(raw, expected):                    # Review Focus 3
    assert normalize_url(raw).normalized == expected

def test_scheme_added_flag():
    assert normalize_url("example.com").scheme_added is True
    assert normalize_url("http://example.com").scheme_added is False

def test_refang():
    n = normalize_url("hxxps://evil[.]com/login")
    assert n.normalized == "https://evil.com/login" and n.was_refanged

def test_idn_host_is_punycoded():                        # Review Focus 2
    n = normalize_url("http://네이버.com/")
    assert n.host.startswith("xn--") and n.host.endswith(".com")
    assert normalize_url("http://xn--950bt9s8xi.com/").host == "xn--950bt9s8xi.com"  # 이미 punycode면 그대로

def test_userinfo_is_kept():
    n = normalize_url("http://paypal.com@evil.com/x")
    assert n.userinfo == "paypal.com" and n.host == "evil.com"

@pytest.mark.parametrize("raw", ["", "   ", "javascript:alert(1)", "ftp://a.com/", "http://", "http://a.com:99999/", "data:text/html,x"])
def test_invalid_inputs_raise(raw):
    with pytest.raises(InvalidURLError):
        normalize_url(raw)

def test_too_long():
    with pytest.raises(InvalidURLError, match="너무 깁니다"):
        normalize_url("http://a.com/" + "a" * 2100)
```

- [ ] **Step 2: 실행하여 실패 확인** — Run: `python -m pytest tests/test_normalize.py -v` → Expected: FAIL (ImportError)

- [ ] **Step 3: `normalize_url` 구현** (위 알고리즘)

- [ ] **Step 4: 통과 확인** — Run: `python -m pytest tests/test_normalize.py -v` → Expected: PASS. (`xn--950bt9s8xi`가 실제 "네이버"의 punycode와 다르면 테스트 값을 `idna.encode("네이버.com", uts46=True)` 결과로 교정한다.)

- [ ] **Step 5: Commit** — `git commit -am "feat: URL normalization"` (새 파일은 먼저 `git add`)

---

### Task 6: URL 분해와 PSL 기반 등록 도메인 추출

**Files:**
- Create: `src/phishguard/parse.py`
- Test: `tests/test_parse.py`

**Interfaces:**
- Consumes: T1 `NormalizedURL`, `URLParts`; T5 `normalize_url` (테스트에서)
- Produces:

```python
def parse_ip_host(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None
def parse_url(url: NormalizedURL, *, psl_refresh: bool = False) -> URLParts
```

- `tldextract.TLDExtract` 인스턴스 2개를 모듈 수준에서 지연 생성·재사용: ICANN 전용(`include_psl_private_domains=False`)과 private 포함(`True`). `psl_refresh=False`면 `suffix_list_urls=()`, `cache_dir=None`(번들 스냅샷, D3). `True`면 tldextract 기본값.
- `registered_domain = f"{r.domain}.{r.suffix}" if r.domain and r.suffix else ""`. `site_domain`은 private 결과로 같은 방식. `is_private_suffix = private.suffix != icann.suffix`.
- IP 호스트면 `subdomain=domain=suffix=registered_domain=site_domain=""`, `is_ip=True`.

`parse_ip_host` 알고리즘 (WHATWG URL 표준의 IPv4 파서 — 브라우저가 실제로 접속하는 해석과 동일):
1. `[...]`면 괄호 제거. `:`가 있으면 `ipaddress.IPv6Address` 시도, 실패 시 `None`.
2. `.`로 분리, 마지막이 빈 문자열이면 제거. 조각이 0개거나 4개 초과면 `None`.
3. 각 조각: `0x`/`0X` 접두 → 16진수(접두만 있으면 0), 길이 >1이고 `0`으로 시작 → 8진수, 그 외 10진수. 하나라도 숫자가 아니면 `None`.
4. 마지막을 제외한 조각이 255 초과면 `None`. 마지막 조각은 `256 ** (5 - n)` 미만이어야 함.
5. `value = last + Σ part[i] * 256 ** (3 - i)` → `IPv4Address(value)`.

- [ ] **Step 1: 실패하는 테스트 작성 — `tests/test_parse.py`**

```python
@pytest.mark.parametrize("host, expected", [
    ("192.168.1.1", "192.168.1.1"), ("3232235777", "192.168.1.1"),
    ("0xc0a80101", "192.168.1.1"), ("0300.0250.1.1", "192.168.1.1"),
    ("127.1", "127.0.0.1"), ("::1", "::1"), ("[::1]", "::1"),
    ("example.com", None), ("1.2.3.4.5", None), ("999.1.1.1", None), ("123.example", None),
])
def test_parse_ip_host(host, expected):
    ip = parse_ip_host(host)
    assert (str(ip) if ip else None) == expected

def p(raw): return parse_url(normalize_url(raw))

def test_multi_label_suffix():
    r = p("http://www.example.co.kr/")
    assert (r.subdomain, r.domain, r.suffix, r.registered_domain) == ("www", "example", "co.kr", "example.co.kr")

def test_brand_as_subdomain():
    r = p("http://naver.com.login-check.xyz/a")
    assert r.subdomain == "naver.com" and r.registered_domain == "login-check.xyz"

def test_private_suffix_shared_hosting():
    r = p("https://paypal-login.github.io/")
    assert r.registered_domain == "github.io" and r.subdomain == "paypal-login"
    assert r.site_domain == "paypal-login.github.io" and r.is_private_suffix

def test_ip_host():
    r = p("http://3232235777/login")
    assert r.is_ip and r.registered_domain == ""

def test_no_public_suffix():
    assert p("http://localhost/").registered_domain == ""

def test_psl_snapshot_makes_no_network_call(monkeypatch):
    # socket.socket 생성 시 예외를 던지도록 패치한 뒤 parse_url 호출이 성공해야 함
    ...
```

- [ ] **Step 2: 실패 확인** — Run: `python -m pytest tests/test_parse.py -v` → Expected: FAIL

- [ ] **Step 3: 구현**

- [ ] **Step 4: 통과 확인** — Run: `python -m pytest tests/test_parse.py -v` → Expected: PASS

- [ ] **Step 5: Commit** — `git add src tests && git commit -m "feat: URL decomposition with PSL and IPv4 host parsing"`

---

### Task 7: 단축 URL 리다이렉트 해석 (SSRF 가드 포함)

**Files:**
- Create: `src/phishguard/redirect.py`
- Test: `tests/test_redirect.py`

**Interfaces:**
- Consumes: T1 `NormalizedURL`, `RedirectHop`, `RedirectResult`; T5 `normalize_url`
- Produces:

```python
BROWSER_UA: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
ResolveFn = Callable[[str], list[str]]
def default_resolve(host: str) -> list[str]          # socket.getaddrinfo 결과의 IP 문자열 목록
def is_shortener_host(host: str, shorteners: frozenset[str]) -> bool   # host == s 또는 host.endswith("." + s)
class RedirectResolver:
    def __init__(self, shorteners: frozenset[str], client: httpx.Client, *,
                 max_hops: int = 5, resolve: ResolveFn = default_resolve) -> None
    def resolve(self, url: NormalizedURL) -> RedirectResult
```

`RedirectResult.error` 코드(정확히 이 문자열): `"blocked_private_address"`, `"dns_error"`, `"network_error"`, `"too_many_redirects"`, `"redirect_loop"`, `"no_redirect_from_shortener"`, `"invalid_location"`.

알고리즘(D1, D2):
1. `is_shortener = is_shortener_host(url.host, shorteners)`. 아니면 즉시 `RedirectResult.not_followed(url.normalized)` (요청 0회).
2. `current = url`, `seen = {current.normalized}`, `hops = []`. 반복:
   - `current.host`가 단축 URL이 아니면 종료(`complete=True`, `final_url=current.normalized`).
   - `len(hops) >= max_hops` → `too_many_redirects`.
   - `resolve(host)`: `OSError` → `dns_error`; 결과 중 하나라도 `not ipaddress.ip_address(ip).is_global` → `blocked_private_address` (요청하지 않음).
   - `client.head(current.normalized, follow_redirects=False, headers={"User-Agent": BROWSER_UA})`. 상태가 400/403/405/501이면 `with client.stream("GET", ..., follow_redirects=False, headers=...) as resp:`로 재시도(본문은 읽지 않음).
   - `httpx.HTTPError` → `network_error`.
   - 상태가 301/302/303/307/308이고 `Location`이 있으면: `next = normalize_url(urljoin(current.normalized, location), refang=False)` (`InvalidURLError` → `invalid_location`), `hops.append(RedirectHop(current.normalized, status))`, `next.normalized in seen` → `redirect_loop`, 아니면 `current = next`.
   - 그 외 상태 → `no_redirect_from_shortener`.
3. 오류로 끝나면 `complete=False`, `final_url`은 마지막으로 알게 된 URL, `hops`는 그때까지의 목록.

- [ ] **Step 1: 실패하는 테스트 작성 — `tests/test_redirect.py`**

모든 테스트는 `respx.mock(assert_all_mocked=True)`로 감싸 **등록하지 않은 호스트(=최종 피싱 호스트)로 요청이 나가면 실패**하게 한다. `resolve`는 기본적으로 `lambda h: ["93.184.216.34"]`를 주입.

```python
def test_non_shortener_makes_no_request(resolver): ...
    # respx 라우트 0개 상태에서 resolve(normalize_url("https://evil.example/a")) → hops == (), is_shortener False, complete True

def test_resolves_bitly_single_hop(resolver):
    respx.head("https://bit.ly/abc").respond(301, headers={"Location": "https://evil.example/login"})
    r = resolver.resolve(normalize_url("https://bit.ly/abc"))
    assert r.final_url == "https://evil.example/login" and r.complete and r.is_shortener
    assert r.hops == (RedirectHop("https://bit.ly/abc", 301),)

def test_resolves_korean_shortener(resolver):            # Review Focus 1
    # han.gl 302 → https://me2.do/x, me2.do 301 → https://phish.example/a → hops 2개, final == "https://phish.example/a"

def test_head_not_allowed_falls_back_to_get(resolver):
    # HEAD 405, GET 302 Location → final 확인

def test_relative_location(resolver):
    # https://bit.ly/a → Location "/b" → https://bit.ly/b → Location "https://x.example/" → final "https://x.example/"

def test_redirect_loop(resolver):                          # a → b → a  ⇒ error "redirect_loop", complete False
def test_too_many_redirects():                             # max_hops=2, 단축 URL 3단 체인 ⇒ "too_many_redirects"
def test_shortener_200_is_incomplete(resolver):            # 200 응답 ⇒ "no_redirect_from_shortener", final_url == 입력
def test_timeout_is_network_error(resolver):               # side_effect=httpx.ConnectTimeout ⇒ "network_error"
def test_blocks_private_resolution():                      # Review Focus 5
    # resolve=lambda h: ["10.0.0.1"], 라우트는 등록하되 route.called is False 확인, error "blocked_private_address"
def test_dns_failure():                                    # resolve가 OSError ⇒ "dns_error"
def test_javascript_location_is_invalid(resolver):        # Location "javascript:alert(1)" ⇒ "invalid_location"

@pytest.mark.network
def test_live_shortener():
    # 구현자가 직접 만든 단축 URL(→ https://example.com/)로 실제 해석 확인. 링크를 만들 수 없으면 skip.
```

(`resolver` 픽스처: `RedirectResolver(load_resources().shorteners, httpx.Client(timeout=5.0), resolve=lambda h: ["93.184.216.34"])`. 나머지 본문은 주석에 적힌 입력/기대값 그대로 작성.)

- [ ] **Step 2: 실패 확인** — Run: `python -m pytest tests/test_redirect.py -v` → Expected: FAIL

- [ ] **Step 3: 구현** (위 알고리즘)

- [ ] **Step 4: 통과 확인** — Run: `python -m pytest tests/test_redirect.py -v` → Expected: PASS (network 테스트는 deselected)

- [ ] **Step 5: Commit** — `git add src tests && git commit -m "feat: shortener redirect resolver with SSRF guard"`

---

### Task 8: SQLite TTL 캐시 + 도메인 생성일 조회 (RDAP → WHOIS)

**Files:**
- Create: `src/phishguard/cache.py`, `src/phishguard/domain_age.py`
- Test: `tests/test_cache.py`, `tests/test_domain_age.py`

**Interfaces:**
- Consumes: T1 `DomainInfo`
- Produces:

```python
# cache.py — 값은 JSON 직렬화 가능한 것만
class TTLCache:
    def __init__(self, path: Path | str, *, now: Callable[[], float] = time.time) -> None   # ":memory:" 허용
    def get(self, key: str) -> Any | None          # 만료되었거나 없으면 None
    def set(self, key: str, value: Any, ttl_seconds: float) -> None
    def close(self) -> None
# 테이블: kv(key TEXT PRIMARY KEY, value TEXT NOT NULL, expires_at REAL NOT NULL)
# sqlite3.connect(..., check_same_thread=False) + threading.Lock (FastAPI 스레드풀 동시 접근)

# domain_age.py
IANA_RDAP_BOOTSTRAP: str = "https://data.iana.org/rdap/dns.json"
POSITIVE_TTL: int = 30 * 86400; NEGATIVE_TTL: int = 86400; RATE_LIMIT_TTL: int = 3600; BOOTSTRAP_TTL: int = 7 * 86400
WhoisFn = Callable[[str], datetime | None]
def whois_creation_date(domain: str) -> datetime | None
def parse_rdap_registration(payload: Mapping[str, Any]) -> datetime | None
class DomainAgeLookup:
    def __init__(self, cache: TTLCache, client: httpx.Client, *, whois_fn: WhoisFn = whois_creation_date,
                 now: Callable[[], datetime] = lambda: datetime.now(timezone.utc), timeout: float = 8.0) -> None
    def lookup(self, registered_domain: str) -> DomainInfo
```

`DomainInfo.error` 코드: `"not_a_domain"`, `"lookup_failed"`, `"rate_limited"`.

`lookup` 알고리즘:
1. 빈 문자열이거나 `.`이 없으면 `DomainInfo.unknown(domain, "not_a_domain")` (네트워크·캐시 미사용).
2. 캐시 키 `age:{domain}` 적중 → 저장된 `{"creation_date": iso|None, "source": str, "error": str|None}`로 `DomainInfo(..., cached=True)`. `age_days`는 **현재 `now()` 기준으로 재계산**.
3. RDAP: bootstrap(캐시 키 `rdap:bootstrap`, 값은 `{tld: base_url}`; `services`의 각 `[tlds, urls]`에서 `urls[0]` 사용)에서 `domain.rsplit(".", 1)[1]`의 base를 찾아 `GET {base.rstrip("/")}/domain/{domain}` (`Accept: application/rdap+json`, `timeout=self.timeout`). 200이면 `parse_rdap_registration`. 429는 `rate_limited` 표시. `httpx.HTTPError`/JSON 오류는 실패로 처리.
4. RDAP 실패 시 `whois_fn`을 **모듈 수준 공유 `ThreadPoolExecutor(max_workers=4)`** 에 제출하고 `future.result(timeout=self.timeout)`. (`with ThreadPoolExecutor()`를 쓰면 종료 시 멈춘 스레드를 기다려 타임아웃이 무력화되므로 금지.)
5. 성공: source `"rdap"`/`"whois"`, `POSITIVE_TTL`로 캐시. 실패: source `"none"`, error `"rate_limited"`(429였을 때, TTL `RATE_LIMIT_TTL`) 또는 `"lookup_failed"`(TTL `NEGATIVE_TTL`).
6. `age_days = max(0.0, (now() - creation_date).total_seconds() / 86400)`. tz 정보 없는 datetime은 UTC로 간주.

`whois_creation_date`: `whois.whois(domain).creation_date`가 리스트면 datetime 원소 중 최솟값, 모든 예외는 `None`.
`parse_rdap_registration`: `events` 중 `eventAction == "registration"`의 `eventDate`를 `datetime.fromisoformat(s.replace("Z", "+00:00"))`로 파싱, 없거나 형식 오류면 `None`.

- [ ] **Step 1: 실패하는 테스트 작성**

```python
# tests/test_cache.py
def test_set_get_and_expiry():
    t = [1000.0]; c = TTLCache(":memory:", now=lambda: t[0])
    c.set("k", {"a": 1}, ttl_seconds=10)
    assert c.get("k") == {"a": 1}
    t[0] = 1011.0
    assert c.get("k") is None

def test_persists_across_instances(tmp_path):
    TTLCache(tmp_path / "c.sqlite3").set("k", [1, 2], 60)
    assert TTLCache(tmp_path / "c.sqlite3").get("k") == [1, 2]

# tests/test_domain_age.py
BOOT = {"services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]}
NOW = datetime(2024, 1, 12, 3, 4, 5, tzinfo=timezone.utc)

def test_parse_rdap_registration():
    p = {"events": [{"eventAction": "expiration", "eventDate": "2030-01-01T00:00:00Z"},
                    {"eventAction": "registration", "eventDate": "2024-01-02T03:04:05Z"}]}
    assert parse_rdap_registration(p) == datetime(2024, 1, 2, 3, 4, 5, tzinfo=timezone.utc)

@respx.mock(assert_all_mocked=True)
def test_rdap_success_and_cache_hit():
    respx.get(IANA_RDAP_BOOTSTRAP).respond(json=BOOT)
    route = respx.get("https://rdap.verisign.com/com/v1/domain/example.com").respond(
        json={"events": [{"eventAction": "registration", "eventDate": "2024-01-02T03:04:05Z"}]})
    lk = DomainAgeLookup(TTLCache(":memory:"), httpx.Client(), whois_fn=lambda d: None, now=lambda: NOW)
    first = lk.lookup("example.com")
    assert first.source == "rdap" and first.age_days == pytest.approx(10.0) and not first.cached
    second = lk.lookup("example.com")
    assert second.cached and route.call_count == 1

def test_rdap_404_falls_back_to_whois(): ...
    # RDAP 404, whois_fn → datetime(2020,1,1,tzinfo=UTC) ⇒ source "whois"

def test_all_sources_fail_returns_unknown(): ...          # Review Focus 4
    # RDAP ConnectTimeout, whois_fn → None ⇒ age_days None, source "none", error "lookup_failed"
    # 두 번째 호출은 네트워크 없이 같은 결과(cached True)

def test_rate_limited_uses_short_ttl(): ...
    # RDAP 429, whois None ⇒ error "rate_limited"; 시계를 3601초 진행하면 캐시 만료되어 재조회

def test_whois_timeout_returns_quickly(): ...
    # RDAP 실패, whois_fn이 time.sleep(3), timeout=0.5 ⇒ 1.5초 안에 반환, error "lookup_failed"

def test_tld_not_in_bootstrap_uses_whois(): ...           # .kr이 bootstrap에 없을 때 whois 경로로 감

def test_not_a_domain_makes_no_request(): ...             # lookup("") 와 lookup("localhost") ⇒ error "not_a_domain", 요청 0회

@pytest.mark.network
def test_live_google_com():
    assert DomainAgeLookup(TTLCache(":memory:"), httpx.Client()).lookup("google.com").age_days > 9000

@pytest.mark.network
def test_live_kr_domain():                                 # Open Question Q2 확인용
    info = DomainAgeLookup(TTLCache(":memory:"), httpx.Client()).lookup("kisa.or.kr")
    assert info.age_days is not None, f"kr lookup failed: {info}"
```

- [ ] **Step 2: 실패 확인** — Run: `python -m pytest tests/test_cache.py tests/test_domain_age.py -v` → Expected: FAIL

- [ ] **Step 3: `cache.py`, `domain_age.py` 구현**

- [ ] **Step 4: 통과 확인** — Run: `python -m pytest tests/test_cache.py tests/test_domain_age.py -v` → Expected: PASS

- [ ] **Step 5: 네트워크 확인(수동)** — Run: `python -m pytest -m network tests/test_domain_age.py -v`
Expected: `test_live_google_com` PASS. `test_live_kr_domain`이 FAIL이면 Open Question Q2의 기본 대응(whois.kr 전용 파서 Task 추가)을 사용자에게 보고하고 계속 진행.

- [ ] **Step 6: Commit** — `git add src tests && git commit -m "feat: SQLite TTL cache and RDAP/WHOIS domain age lookup"`

---

### Task 9: 특징 추출

**Files:**
- Create: `src/phishguard/features.py`
- Test: `tests/test_features.py`

**Interfaces:**
- Consumes: T1 타입 전부, T2 `Resources`/`Brand`, (테스트에서) T5 `normalize_url`, T6 `parse_url`
- Produces:

```python
def match_keywords(text: str, keywords: Iterable[str]) -> set[str]
def shannon_entropy(s: str) -> float                       # 밑 2, 빈 문자열은 0.0
def extract_features(url: NormalizedURL, parts: URLParts, redirect: RedirectResult,
                     domain: DomainInfo, resources: Resources) -> FeatureVector
```

`match_keywords` (리스크 K7): `tokens = [t for t in re.split(r"[^a-z0-9]+", text.lower()) if t]`. 키워드 `k`는 `k in tokens`이거나 `len(k) >= 5`이고 어떤 토큰의 부분 문자열이면 매칭.

특징 정의 (`url`은 **최종 URL**의 `NormalizedURL`, 분석기에서 리다이렉트 해석 후 전달):

| 특징 | 정의 |
|---|---|
| `url_length` / `host_length` / `path_length` | `len(url.normalized)` / `len(url.host)` / `len(url.path)` |
| `num_subdomains` | `parts.subdomain`을 `.`로 나눈 라벨 수. 첫 라벨이 `www`면 하나 제외. 빈 문자열·IP는 0 |
| `num_dots_host` / `num_hyphens_host` / `num_digits_host` | `url.host`의 `.` / `-` / 숫자 개수 |
| `is_ip_host` | `parts.is_ip` |
| `has_userinfo` | `url.userinfo != ""` (`paypal.com@evil.com` 수법) |
| `has_punycode` | 호스트 라벨 중 `xn--`로 시작하는 것이 있음 |
| `is_https` | `url.scheme == "https"` |
| `has_nonstandard_port` | `url.port is not None` |
| `num_query_params` | `len(parse_qsl(url.query, keep_blank_values=True))` |
| `num_suspicious_keywords` | `len(match_keywords(f"{url.host} {url.path} {url.query}", resources.suspicious_keywords))` |
| `brand_in_subdomain` | 어떤 브랜드 키워드가 `parts.subdomain`에 매칭되고 `parts.registered_domain not in brand.official_domains` |
| `brand_in_path` | 같은 조건, 대상 텍스트는 `url.path + " " + url.query` |
| `brand_in_domain_label` | 같은 조건, 대상 텍스트는 `parts.domain` (콤보스쿼팅: `paypal-secure.com`) |
| `is_shortener` / `redirect_count` | `redirect.is_shortener` / `len(redirect.hops)` |
| `is_private_suffix` | `parts.is_private_suffix` |
| `is_risky_tld` | `parts.suffix.rsplit(".", 1)[-1] in resources.risky_tlds` |
| `host_entropy` | `shannon_entropy(parts.domain or url.host)` |
| `has_embedded_url` | `re.search(r"https?(://\|%3A%2F%2F)", url.path + "?" + url.query, re.I)` |
| `domain_age_days` | `domain.age_days`, 없으면 `math.nan` |
| `domain_age_unknown` | `1.0 if domain.age_days is None else 0.0` |

(표 안의 `\|`는 마크다운 표 이스케이프이며 실제 정규식은 `https?(://|%3A%2F%2F)`이다.)

불리언은 `1.0`/`0.0`. `evidence`에는 항상 `registered_domain`, `site_domain`, `tld`(마지막 라벨), `port`(문자열, 없으면 `""`)를 넣고, 브랜드 특징이 1이면 해당 키(`brand_in_subdomain` 등)에 `Brand.name`을 넣는다.

- [ ] **Step 1: 실패하는 테스트 작성 — `tests/test_features.py`**

헬퍼: `def fv(raw, *, age=None): n = normalize_url(raw); return extract_features(n, parse_url(n), RedirectResult.not_followed(n.normalized), DomainInfo(...age...) if age is not None else DomainInfo.unknown("x"), load_resources())`

```python
def test_match_keywords_token_boundary():
    assert match_keywords("tossup.com", ["toss"]) == set()
    assert match_keywords("toss-login.com", ["toss"]) == {"toss"}
    assert match_keywords("mypaypalaccount.com", ["paypal"]) == {"paypal"}

def test_brand_in_subdomain():
    f = fv("http://naver.com.login-check.xyz/a")
    assert f.values["brand_in_subdomain"] == 1.0 and f.evidence["brand_in_subdomain"] == "네이버"
    assert f.values["is_risky_tld"] == 1.0 and f.evidence["registered_domain"] == "login-check.xyz"

def test_official_domain_not_flagged():
    f = fv("https://www.naver.com/")
    assert f.values["brand_in_subdomain"] == f.values["brand_in_path"] == f.values["brand_in_domain_label"] == 0.0

def test_brand_in_path():           assert fv("http://evil.example/paypal/login").values["brand_in_path"] == 1.0
def test_combosquat():              assert fv("https://paypal-secure.com/").values["brand_in_domain_label"] == 1.0
def test_shared_hosting():
    f = fv("https://paypal-login.github.io/")
    assert f.values["brand_in_subdomain"] == 1.0 and f.values["is_private_suffix"] == 1.0
def test_ip_and_userinfo():
    f = fv("http://paypal.com@3232235777/")
    assert f.values["is_ip_host"] == 1.0 and f.values["has_userinfo"] == 1.0
def test_punycode_feature():        assert fv("http://네이버.com/").values["has_punycode"] == 1.0   # Review Focus 2
def test_num_subdomains_excludes_www(): assert fv("http://www.a.example.com/").values["num_subdomains"] == 1.0
def test_embedded_url():            assert fv("http://a.com/r?u=https%3A%2F%2Fevil.com").values["has_embedded_url"] == 1.0
def test_domain_age_missing_is_nan_and_flag():
    f = fv("http://a.com/")
    assert math.isnan(f.values["domain_age_days"]) and f.values["domain_age_unknown"] == 1.0
def test_feature_vector_complete(): assert set(fv("http://a.com/").values) == set(FEATURE_NAMES)
def test_entropy():                 assert shannon_entropy("aaaa") == 0.0 and shannon_entropy("ab") == 1.0
```

- [ ] **Step 2: 실패 확인** — Run: `python -m pytest tests/test_features.py -v` → Expected: FAIL

- [ ] **Step 3: 구현**

- [ ] **Step 4: 통과 확인** — Run: `python -m pytest tests/test_features.py -v` → Expected: PASS

- [ ] **Step 5: Commit** — `git add src tests && git commit -m "feat: feature extraction"`

---

### Task 10: 규칙 기반 판별 엔진 (베이스라인)

**Files:**
- Create: `src/phishguard/rules.py`
- Modify: `src/phishguard/resources/rules.yaml` (아래 초기 가중치, T2에서 이미 작성했다면 값만 확인)
- Test: `tests/test_rules.py`

**Interfaces:**
- Consumes: T1 `FeatureVector`, `RuleHit`, `RuleResult`, `Verdict`; T2 `Resources`
- Produces:

```python
@dataclass(frozen=True)
class Rule:
    rule_id: str
    condition: Callable[[Mapping[str, float]], bool]   # FeatureVector.values를 받음
    message: str                                       # str.format_map 템플릿 (한국어)
RULES: tuple[Rule, ...]                                # 아래 18개, 이 순서
class RuleEngine:
    def __init__(self, resources: Resources) -> None
    def evaluate(self, features: FeatureVector, *, disabled: frozenset[str] = frozenset()) -> RuleResult
    def verdict_for(self, score: int) -> Verdict       # score >= dangerous → DANGEROUS, >= suspicious → SUSPICIOUS, else SAFE
```

규칙 표 (`v` = `features.values`, 메시지 템플릿 변수는 `evidence` 키와 특징 이름. 특징 값은 정수로 포맷):

| ID | 조건 | 초기 가중치 | 메시지 |
|---|---|---|---|
| R01 | `v["is_ip_host"] == 1` | 40 | 도메인 이름 대신 IP 주소를 사용합니다. |
| R02 | `v["has_userinfo"] == 1` | 30 | 주소에 '@'가 있어 실제 접속하는 사이트를 숨기고 있을 수 있습니다. |
| R03 | `v["brand_in_subdomain"] == 1` | 35 | '{brand_in_subdomain}' 브랜드명이 실제 등록 도메인이 아닌 서브도메인에 있습니다. 실제 도메인은 {registered_domain} 입니다. |
| R04 | `v["brand_in_path"] == 1` | 20 | '{brand_in_path}' 브랜드명이 도메인이 아닌 경로/파라미터에 있습니다. |
| R05 | `v["brand_in_domain_label"] == 1` | 30 | '{brand_in_domain_label}' 브랜드명을 포함하지만 공식 도메인이 아닙니다({registered_domain}). |
| R06 | `v["domain_age_days"] < 30` (NaN이면 거짓) | 35 | 도메인이 생성된 지 {domain_age_days}일밖에 되지 않았습니다. |
| R07 | `30 <= v["domain_age_days"] < 180` | 15 | 도메인이 생성된 지 6개월이 되지 않았습니다({domain_age_days}일). |
| R08 | `v["domain_age_unknown"] == 1 and v["is_ip_host"] == 0` | 10 | 도메인 생성일을 확인할 수 없습니다. |
| R09 | `v["num_subdomains"] >= 3` | 15 | 서브도메인이 {num_subdomains}단계로 지나치게 깁니다. |
| R10 | `v["has_punycode"] == 1` | 25 | 국제화 도메인(punycode)을 사용해 다른 사이트처럼 보이게 할 수 있습니다. |
| R11 | `v["is_risky_tld"] == 1` | 15 | 피싱에 자주 악용되는 최상위 도메인(.{tld})입니다. |
| R12 | `v["num_suspicious_keywords"] >= 2` | 15 | 로그인·인증 등을 유도하는 단어가 {num_suspicious_keywords}개 포함되어 있습니다. |
| R13 | `v["is_https"] == 0` | 10 | 암호화되지 않은 HTTP 연결을 사용합니다. |
| R14 | `v["has_nonstandard_port"] == 1` | 15 | 일반적이지 않은 포트({port})를 사용합니다. |
| R15 | `v["url_length"] > 100` | 5 | 주소가 지나치게 깁니다({url_length}자). |
| R16 | `v["is_shortener"] == 1` | 10 | 단축 URL로 실제 주소를 숨겼습니다. |
| R17 | `v["is_private_suffix"] == 1` | 10 | 누구나 만들 수 있는 공유 호스팅 주소({site_domain})입니다. |
| R18 | `v["has_embedded_url"] == 1` | 10 | 주소 안에 다른 주소가 들어 있어 다른 사이트로 이동시킬 수 있습니다. |

`evaluate`: `disabled`에 없는 규칙 중 조건이 참인 것의 `RuleHit(rule_id, weight, message.format_map(ctx))`를 가중치 내림차순으로 정렬, `score = sum(weights)`. `ctx = _SafeDict({**{k: _fmt(v) for k, v in values.items()}, **evidence})` (`_fmt`: 정수면 `"3"`, NaN이면 `"?"`; `_SafeDict`는 `__missing__`이 `"?"`를 반환하는 `dict` 하위 클래스 — 학습 데이터처럼 evidence가 비어 있어도 `KeyError`가 나지 않게 함, T15에서 사용).

- [ ] **Step 1: 실패하는 테스트 작성 — `tests/test_rules.py`**

헬퍼 `make_fv(**overrides)`: 모든 특징 0.0, `domain_age_days=9000.0`, `is_https=1.0`, evidence는 `registered_domain="example.com"`, `site_domain=""`, `tld="com"`, `port=""`에 overrides 반영(evidence 키도 같은 kwargs로 받음).

```python
engine = RuleEngine(load_resources())

def test_clean_features_are_safe():
    r = engine.evaluate(make_fv())
    assert r.score == 0 and r.verdict is Verdict.SAFE and r.hits == ()

def test_ip_rule():
    r = engine.evaluate(make_fv(is_ip_host=1.0))
    assert [h.rule_id for h in r.hits] == ["R01"] and r.verdict is Verdict.SUSPICIOUS

def test_brand_subdomain_young_domain_is_dangerous():
    r = engine.evaluate(make_fv(brand_in_subdomain=1.0, domain_age_days=3.0, is_risky_tld=1.0, is_https=0.0,
                                evidence={"brand_in_subdomain": "네이버", "registered_domain": "login-check.xyz", "tld": "xyz"}))
    assert {h.rule_id for h in r.hits} == {"R03", "R06", "R11", "R13"}
    assert r.score == 95 and r.verdict is Verdict.DANGEROUS
    assert any("네이버" in h.message and "login-check.xyz" in h.message for h in r.hits)
    assert any("3일" in h.message for h in r.hits)

@pytest.mark.parametrize("age, expected", [(10.0, {"R06"}), (100.0, {"R07"}), (200.0, set())])
def test_age_rules_are_exclusive(age, expected):
    assert {h.rule_id for h in engine.evaluate(make_fv(domain_age_days=age)).hits} == expected

def test_age_unknown_not_applied_to_ip():
    r = engine.evaluate(make_fv(is_ip_host=1.0, domain_age_days=math.nan, domain_age_unknown=1.0))
    assert "R08" not in {h.rule_id for h in r.hits}

def test_disabled_rules():
    r = engine.evaluate(make_fv(domain_age_days=3.0), disabled=frozenset({"R06", "R07", "R08"}))
    assert r.hits == ()

def test_thresholds_come_from_resources():
    res = dataclasses.replace(load_resources(), rule_thresholds=(10, 20))
    assert RuleEngine(res).verdict_for(15) is Verdict.SUSPICIOUS and RuleEngine(res).verdict_for(20) is Verdict.DANGEROUS

def test_every_rule_has_weight():
    assert {r.rule_id for r in RULES} == set(load_resources().rule_weights)

def test_all_messages_format():
    everything = make_fv(**{n: 1.0 for n in FEATURE_NAMES}, evidence={"brand_in_subdomain": "A", "brand_in_path": "B",
                         "brand_in_domain_label": "C", "registered_domain": "x.com", "site_domain": "y.github.io", "tld": "xyz", "port": "8080"})
    for h in engine.evaluate(everything).hits:
        assert "{" not in h.message and "}" not in h.message
```

- [ ] **Step 2: 실패 확인** — Run: `python -m pytest tests/test_rules.py -v` → Expected: FAIL

- [ ] **Step 3: 구현**

- [ ] **Step 4: 통과 확인** — Run: `python -m pytest tests/test_rules.py -v` → Expected: PASS

- [ ] **Step 5: Commit** — `git add src tests && git commit -m "feat: rule-based scoring engine"`

---

### Task 11: 분석 파이프라인 조립 + 웹 연결

**Files:**
- Create: `src/phishguard/analyzer.py`, `tests/fakes.py`
- Modify: `src/phishguard/web/main.py` (`build_default_analyzer()`가 `build_analyzer(load_settings())` 반환)
- Test: `tests/test_analyzer.py`

**Interfaces:**
- Consumes: T2 `Resources`, `Settings`, `load_settings`; T5 `normalize_url`; T6 `parse_url`; T7 `RedirectResolver`; T8 `TTLCache`, `DomainAgeLookup`; T9 `extract_features`; T10 `RuleEngine`
- Produces:

```python
WARNING_MESSAGES: Mapping[str, str] = {
    "blocked_private_address": "단축 URL이 내부망 주소를 가리켜 확인을 중단했습니다.",
    "dns_error": "단축 URL 서비스의 주소를 찾을 수 없습니다.",
    "network_error": "단축 URL 서비스에 연결하지 못해 최종 주소를 확인하지 못했습니다.",
    "too_many_redirects": "리다이렉트가 너무 많아 확인을 중단했습니다.",
    "redirect_loop": "리다이렉트가 순환하여 확인을 중단했습니다.",
    "no_redirect_from_shortener": "단축 URL의 최종 주소를 확인하지 못했습니다(미리보기 페이지 또는 차단).",
    "invalid_location": "단축 URL이 웹 주소가 아닌 곳으로 이동합니다.",
    "lookup_failed": "도메인 생성일을 조회하지 못했습니다.",
    "rate_limited": "도메인 조회 서버의 요청 제한으로 생성일을 확인하지 못했습니다.",
}
class Analyzer:   # SupportsAnalyze 구현
    def __init__(self, *, resources: Resources, resolver: RedirectResolver, age_lookup: DomainAgeLookup,
                 rule_engine: RuleEngine, model: "PhishModel | None" = None, psl_refresh: bool = False) -> None
    def analyze(self, raw_url: str) -> AnalysisResult
def build_analyzer(settings: Settings | None = None) -> Analyzer
    # httpx.Client(timeout=settings.http_timeout, headers={"User-Agent": BROWSER_UA}) 하나를 resolver와 age_lookup이 공유
    # TTLCache(settings.cache_path), model은 T16 전까지 None
```

`analyze` 순서:
1. `n = normalize_url(raw_url)` — `InvalidURLError`는 그대로 전파(웹 계층이 400 처리).
2. `redirect = resolver.resolve(n)`; `redirect.error`가 있으면 `WARNING_MESSAGES[error]`를 warnings에 추가.
3. `final = n if not redirect.hops else normalize_url(redirect.final_url, refang=False)`
4. `parts = parse_url(final, psl_refresh=...)`
5. `domain = age_lookup.lookup(parts.registered_domain)` — 단, `parts.is_ip`면 조회하지 않고 `DomainInfo.unknown("", "not_a_domain")`. `domain.error`가 `WARNING_MESSAGES`에 있으면 warnings에 추가.
6. `features = extract_features(final, parts, redirect, domain, resources)` → `rule = rule_engine.evaluate(features)` → `model = None` (T16에서 연결)
7. `AnalysisResult(input_url=raw_url, normalized=n, redirect=redirect, parts=parts, domain=domain, features=features, rule=rule, model=model, warnings=tuple(warnings))`

- [ ] **Step 1: 실패하는 테스트 작성 — `tests/test_analyzer.py`**

`FakeResolver(mapping: dict[str, RedirectResult])`(없으면 `not_followed`), `FakeAgeLookup(age_days: float | None)`(호출된 도메인을 `calls`에 기록)을 `tests/fakes.py`에 정의한다(T13 테스트에서도 재사용, `RedirectResolver`/`DomainAgeLookup`과 같은 메서드 시그니처, 덕 타이핑).

```python
def test_end_to_end_smishing_shortener():                 # Review Focus 1
    final = "http://epost.go.kr.parcel-check.xyz/track"
    resolver = FakeResolver({"https://han.gl/abc": RedirectResult(final, (RedirectHop("https://han.gl/abc", 302),), True, True, None)})
    lookup = FakeAgeLookup(2.0)
    r = make_analyzer(resolver, lookup).analyze("https://han.gl/abc")
    assert r.parts.registered_domain == "parcel-check.xyz" and lookup.calls == ["parcel-check.xyz"]
    ids = {h.rule_id for h in r.rule.hits}
    assert {"R03", "R06", "R16"} <= ids and r.final_verdict is Verdict.DANGEROUS
    assert any("우체국" in h.message for h in r.rule.hits)

def test_official_site_is_safe():
    r = make_analyzer(FakeResolver({}), FakeAgeLookup(9000.0)).analyze("https://www.naver.com/")
    assert r.final_verdict is Verdict.SAFE and r.warnings == ()

@respx.mock(assert_all_mocked=True)
def test_analyze_survives_external_failures():            # Review Focus 4 — 실제 Resolver/Lookup 사용
    respx.head("https://bit.ly/x").mock(side_effect=httpx.ConnectTimeout("t"))
    respx.get(IANA_RDAP_BOOTSTRAP).mock(side_effect=httpx.ConnectTimeout("t"))
    a = build_analyzer_for_test(whois_fn=lambda d: None, resolve=lambda h: ["93.184.216.34"])
    r = a.analyze("https://bit.ly/x")
    assert WARNING_MESSAGES["network_error"] in r.warnings
    assert WARNING_MESSAGES["lookup_failed"] in r.warnings
    assert r.features.values["domain_age_unknown"] == 1.0

@respx.mock(assert_all_mocked=True)
def test_private_ip_input_makes_no_request():             # Review Focus 5
    lookup = FakeAgeLookup(None)
    r = make_analyzer(real_resolver_no_routes(), lookup).analyze("http://127.0.0.1/admin")
    assert "R01" in {h.rule_id for h in r.rule.hits} and lookup.calls == []

def test_invalid_url_propagates():
    with pytest.raises(InvalidURLError):
        make_analyzer(FakeResolver({}), FakeAgeLookup(None)).analyze("javascript:alert(1)")

def test_web_app_with_real_pipeline():
    client = TestClient(create_app(make_analyzer(FakeResolver({}), FakeAgeLookup(5.0))))
    body = client.post("/api/analyze", json={"url": "http://paypal-secure.com/login"}).json()
    assert {"R05", "R06"} <= {h["rule_id"] for h in body["rule"]["hits"]}
```

(`make_analyzer`, `build_analyzer_for_test`, `real_resolver_no_routes`는 테스트 파일 내 헬퍼: `TTLCache(":memory:")`, `load_resources()`, `RuleEngine` 사용.)

- [ ] **Step 2: 실패 확인** — Run: `python -m pytest tests/test_analyzer.py -v` → Expected: FAIL

- [ ] **Step 3: `analyzer.py` 구현, `web/main.py` 교체**

- [ ] **Step 4: 전체 테스트 통과 확인** — Run: `python -m pytest -v` → Expected: 전체 PASS (T3/T4 웹 테스트는 계속 `StubAnalyzer` 사용)

- [ ] **Step 5: 수동 확인(실제 네트워크)**

Run: `uvicorn phishguard.web.main:app` 후 브라우저에서 `https://www.google.com` 입력
Expected: 안전, 도메인 생성일 표시(1997년경). `http://paypal.com@1.2.3.4/login` 입력 → 위험 또는 주의, R01·R02 이유 표시. 실제 피싱 URL은 입력해도 서버는 접속하지 않음을 서버 로그(요청 없음)로 확인.

- [ ] **Step 6: Commit** — `git add src tests && git commit -m "feat: analysis pipeline wired into web app"`

**Phase 3 검증:** Phase별 완료 기준 표의 Phase 3 항목 + `python -m pytest -m network -v` 결과를 사용자에게 보고(특히 `.kr` 조회 결과, Q2).

---

# Phase 4 — 비즈니스 로직 (2): 데이터 구축과 머신러닝

**데이터 준비(사람이 할 일, T12 시작 전):** UCI "PhiUSIIL Phishing URL Dataset"(https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)을 내려받아 `data/raw/PhiUSIIL_Phishing_URL_Dataset.csv`에 둔다. 이 데이터셋은 `label 1 = 정상, 0 = 피싱`이므로 로더에서 반전한다(Global Constraints). 파일이 없으면 T12의 단위 테스트는 합성 데이터로 진행하고, CLI 실행 단계에서 사용자에게 다운로드를 요청한다.

### Task 12: 데이터셋 로딩, 정제, 특징 행렬, 그룹 분할

**Files:**
- Create: `src/phishguard/training/__init__.py`, `src/phishguard/training/dataset.py`
- Test: `tests/test_dataset.py`

**Interfaces:**
- Consumes: T1 `LabeledURL`, `FEATURE_NAMES`, `DomainInfo`, `RedirectResult`; T2 `Resources`; T5 `normalize_url`; T6 `parse_url`; T7 `is_shortener_host`; T9 `extract_features`
- Produces:

```python
LABELED_CSV_COLUMNS: tuple[str, ...] = ("url", "label", "source", "collected_at", "domain_age_days")
def load_phiusiil(path: Path) -> list[LabeledURL]     # 열 URL,label 사용, label = 1 - label, source="phiusiil"
def load_labeled_csv(path: Path) -> list[LabeledURL]  # LABELED_CSV_COLUMNS 형식 (T13 출력, manual_kr.csv)
def assert_label_sanity(records: Sequence[LabeledURL]) -> None
    # 등록 도메인이 {google.com, youtube.com, wikipedia.org, microsoft.com, apple.com, amazon.com,
    #  naver.com, github.com, linkedin.com, yahoo.com}인 레코드가 5개 이상이면 그중 label==0 비율이 0.9 미만일 때 ValueError
def dedupe(records: Iterable[LabeledURL]) -> list[LabeledURL]
    # normalize_url(r.url).normalized 기준. InvalidURLError 행은 제거. 같은 URL에 레이블이 다르면 모두 제거.
    # 같은 URL·같은 레이블이면 domain_age_days가 있는 쪽, 그다음 먼저 나온 쪽을 남김
def save_labeled_csv(path: Path, records: Sequence[LabeledURL]) -> None

@dataclass(frozen=True)
class FeatureMatrix:
    X: pd.DataFrame          # columns == list(FEATURE_NAMES)
    y: np.ndarray            # int, 1=phishing
    groups: np.ndarray       # registered_domain, 비어 있으면 host
    urls: np.ndarray         # 정규화 URL (리포트 예시용)
    sources: np.ndarray
    skipped: int             # 특징 추출 실패 행 수
def featurize(records: Sequence[LabeledURL], resources: Resources) -> FeatureMatrix
    # 네트워크 금지. redirect = RedirectResult(n.normalized, (), is_shortener_host(n.host, resources.shorteners), False, "offline")
    # domain = r.domain_age_days가 있으면 DomainInfo(source="snapshot", age_days=...), 없으면 DomainInfo.unknown(...)  (D6)

@dataclass(frozen=True)
class Split:
    train: np.ndarray; val: np.ndarray; test: np.ndarray   # 행 인덱스
def three_way_split(fm: FeatureMatrix, *, seed: int = 42) -> Split
    # GroupShuffleSplit(test_size=0.2, random_state=seed)로 test 분리 → 나머지에서 GroupShuffleSplit(test_size=0.2, random_state=seed)로 val 분리
def write_manifest(path: Path, inputs: Sequence[Path], counts: Mapping[str, int]) -> None
    # {"created_at", "inputs": [{"path", "sha256", "rows"}], "counts", "tldextract_version", "sklearn_version", "feature_schema_version"}
# CLI
# python -m phishguard.training.dataset --phiusiil data/raw/PhiUSIIL_Phishing_URL_Dataset.csv
#        [--extra data/raw/feed.csv --extra data/raw/manual_kr.csv] --out data/processed/dataset.csv
#   → 로드 → assert_label_sanity(PhiUSIIL) → dedupe → save_labeled_csv → manifest.json(같은 폴더) → 클래스별 개수 출력
```

`dataset.csv`는 특징이 아니라 **레이블된 URL**을 저장한다. 특징은 학습/평가 시점에 `featurize`로 계산하므로, 특징을 바꿔도 데이터셋을 다시 만들 필요가 없다.

- [ ] **Step 1: 실패하는 테스트 작성 — `tests/test_dataset.py`** (모두 `tmp_path`의 합성 CSV 사용)

```python
def test_load_phiusiil_inverts_label(tmp_path):
    p = tmp_path / "phi.csv"; p.write_text("URL,label\nhttps://www.google.com,1\nhttp://evil.xyz/login,0\n", encoding="utf-8")
    assert [r.label for r in load_phiusiil(p)] == [0, 1]

def test_label_sanity_raises_on_inverted():
    recs = [LabeledURL(f"https://{d}/", 1, "t", None, None) for d in ["google.com", "naver.com", "github.com", "apple.com", "amazon.com"]]
    with pytest.raises(ValueError):
        assert_label_sanity(recs)

def test_dedupe_normalizes_and_drops_conflicts():
    recs = [LabeledURL("HTTP://A.com", 0, "x", None, None), LabeledURL("http://a.com/", 0, "y", None, 100.0),
            LabeledURL("http://b.com", 0, "x", None, None), LabeledURL("http://b.com/", 1, "y", None, None),
            LabeledURL("javascript:x", 1, "x", None, None)]
    out = dedupe(recs)
    assert len(out) == 1 and out[0].domain_age_days == 100.0

def test_featurize_columns_and_offline(monkeypatch):
    monkeypatch.setattr(socket, "socket", _raise)          # 네트워크 시도 시 실패
    fm = featurize([LabeledURL("http://1.2.3.4/x", 1, "t", None, None), LabeledURL("https://naver.com/", 0, "t", None, 9000.0)], load_resources())
    assert list(fm.X.columns) == list(FEATURE_NAMES) and fm.y.tolist() == [1, 0]
    assert math.isnan(fm.X.iloc[0]["domain_age_days"]) and fm.X.iloc[1]["domain_age_days"] == 9000.0

def test_three_way_split_groups_disjoint():
    fm = featurize([LabeledURL(f"http://d{i % 50}.com/p{i}", i % 2, "t", None, None) for i in range(500)], load_resources())
    s = three_way_split(fm)
    g = lambda idx: set(fm.groups[idx])
    assert not (g(s.train) & g(s.test)) and not (g(s.train) & g(s.val)) and not (g(s.val) & g(s.test))
    assert len(s.train) + len(s.val) + len(s.test) == 500

def test_manifest_records_sha256(tmp_path): ...   # 입력 파일 sha256이 hashlib 결과와 일치
```

- [ ] **Step 2: 실패 확인** — Run: `python -m pytest tests/test_dataset.py -v` → Expected: FAIL

- [ ] **Step 3: 구현**

- [ ] **Step 4: 통과 확인** — Run: `python -m pytest tests/test_dataset.py -v` → Expected: PASS

- [ ] **Step 5: 실제 데이터로 실행(파일이 있을 때)**

Run: `python -m phishguard.training.dataset --phiusiil data/raw/PhiUSIIL_Phishing_URL_Dataset.csv --out data/processed/dataset.csv`
Expected: `phishing=<약 10만>, benign=<약 13만>` 형태 출력(PhiUSIIL 원본 약 23.5만 행, 중복 제거 후 감소), `data/processed/manifest.json` 생성. `assert_label_sanity` 통과.

- [ ] **Step 6: Commit** — `git add src tests && git commit -m "feat: dataset loading, dedupe, featurize and grouped split"`

---

### Task 13: 신규 피싱/정상 URL 수집기 (도메인 나이 스냅샷)

**Files:**
- Create: `src/phishguard/training/collect_feed.py`
- Test: `tests/test_collect_feed.py`

**Interfaces:**
- Consumes: T1 `LabeledURL`; T5 `normalize_url`; T6 `parse_url`; T8 `DomainAgeLookup`, `TTLCache`; T12 `load_labeled_csv`, `LABELED_CSV_COLUMNS`
- Produces:

```python
OPENPHISH_FEED: str = "https://openphish.com/feed.txt"
TRANCO_TOP1M: str = "https://tranco-list.eu/top-1m.csv.zip"
def fetch_openphish(client: httpx.Client) -> list[str]                       # 빈 줄 제거
def fetch_tranco_domains(client: httpx.Client, *, start_rank: int, count: int) -> list[str]   # zip 안 CSV "rank,domain"
def collect(urls: Iterable[str], *, label: int, source: str, age_lookup: DomainAgeLookup,
            now: datetime, existing: set[str], min_interval: float = 1.0,
            sleep: Callable[[float], None] = time.sleep) -> list[LabeledURL]
    # 정규화 실패/이미 existing에 있는 URL은 건너뜀. 등록 도메인이 같은 URL은 나이 조회를 1회만 함(로컬 dict).
    # 실제 네트워크 조회 사이에 sleep(min_interval) (캐시 적중 시 생략). collected_at=now, domain_age_days=조회 결과
def append_records(path: Path, records: Sequence[LabeledURL]) -> int        # 파일이 없으면 헤더 작성, append-only, 쓴 행 수 반환
# CLI
# python -m phishguard.training.collect_feed --source openphish --out data/raw/feed.csv
# python -m phishguard.training.collect_feed --source tranco --start-rank 1 --count 10000 --out data/raw/feed.csv
# python -m phishguard.training.collect_feed --source openphish --out data/raw/fresh.csv        (학습 이후 수집 = 신규 검증 세트)
# python -m phishguard.training.collect_feed --source tranco --start-rank 10001 --count 2000 --out data/raw/fresh.csv
```

규칙: 수집기는 **피드 URL과 RDAP/WHOIS만 요청**하고 수집한 피싱 URL 자체에는 절대 요청하지 않는다. Tranco 도메인은 `https://{domain}/` 형태로 저장(리스크 K1 — 리포트에서 편향으로 다룸). 학습용 Tranco 순위(1–10000)와 신규 검증용 순위(10001–12000)는 겹치지 않게 한다.

- [ ] **Step 1: 실패하는 테스트 작성 — `tests/test_collect_feed.py`**

```python
@respx.mock(assert_all_mocked=True)
def test_fetch_openphish():
    respx.get(OPENPHISH_FEED).respond(text="http://a.xyz/login\n\nhttps://b.top/x\n")
    assert fetch_openphish(httpx.Client()) == ["http://a.xyz/login", "https://b.top/x"]

def test_collect_snapshots_age_and_never_contacts_phishing_host():
    lookup = FakeAgeLookup(3.0)                       # T11 테스트의 Fake와 같은 형태
    now = datetime(2026, 10, 15, tzinfo=timezone.utc)
    with respx.mock(assert_all_mocked=True):          # 라우트 0개: 어떤 HTTP 요청도 실패
        out = collect(["http://a.xyz/login", "http://a.xyz/other", "http://b.top/"], label=1, source="openphish",
                      age_lookup=lookup, now=now, existing=set(), sleep=lambda s: None)
    assert [r.domain_age_days for r in out] == [3.0, 3.0, 3.0] and all(r.collected_at == now for r in out)
    assert lookup.calls == ["a.xyz", "b.top"]          # 같은 도메인은 1회만 조회

def test_collect_skips_existing_and_invalid(): ...    # existing에 있는 정규화 URL과 "javascript:x"는 제외

def test_append_records_is_append_only(tmp_path):
    p = tmp_path / "f.csv"
    assert append_records(p, [LabeledURL("http://a.com/", 1, "t", None, 1.0)]) == 1
    append_records(p, [LabeledURL("http://b.com/", 0, "t", None, None)])
    lines = p.read_text(encoding="utf-8").splitlines()
    assert lines[0] == ",".join(LABELED_CSV_COLUMNS) and len(lines) == 3
    assert len(load_labeled_csv(p)) == 2

def test_fetch_tranco_slices_ranks(): ...             # 메모리 zip(rank,domain 5행)으로 start_rank=2,count=2 → 2·3위 도메인
```

- [ ] **Step 2: 실패 확인** — Run: `python -m pytest tests/test_collect_feed.py -v` → Expected: FAIL

- [ ] **Step 3: 구현** (CLI는 `argparse`. `existing`은 출력 파일이 있으면 `load_labeled_csv`로 채움.)

- [ ] **Step 4: 통과 확인** — Run: `python -m pytest tests/test_collect_feed.py -v` → Expected: PASS

- [ ] **Step 5: 실제 수집 시작** — Run: `python -m phishguard.training.collect_feed --source openphish --out data/raw/feed.csv`
Expected: `wrote N rows`(N은 수백). 이후 **하루 1회** 반복 실행한다(Windows 작업 스케줄러 등록 방법은 T18 README). 나이 포함 모델(Q7)을 위해 클래스별 1,000건 이상 모일 때까지 수집을 계속한다.

- [ ] **Step 6: Commit** — `git add src tests && git commit -m "feat: phishing/benign feed collector with domain age snapshot"`

---

### Task 14: 모델 학습과 아티팩트 저장

**Files:**
- Create: `src/phishguard/training/train.py`
- Test: `tests/test_train.py`

**Interfaces:**
- Consumes: T1 `FEATURE_NAMES`, `FEATURE_SCHEMA_VERSION`; T12 `FeatureMatrix`, `Split`, `three_way_split`, `featurize`, `load_labeled_csv`
- Produces:

```python
NETWORK_FEATURES: tuple[str, ...] = ("domain_age_days", "domain_age_unknown", "is_shortener", "redirect_count")
LEXICAL_FEATURES: tuple[str, ...]          # FEATURE_NAMES에서 NETWORK_FEATURES를 뺀 것, 순서 유지
DEFAULT_ML_THRESHOLDS: Mapping[str, float] = {"suspicious": 0.3, "dangerous": 0.7}
def make_pipeline(name: Literal["logreg", "hgb"], seed: int = 42) -> Pipeline
    # logreg: SimpleImputer(strategy="median") → StandardScaler() → LogisticRegression(max_iter=2000, class_weight="balanced", random_state=seed)
    # hgb:    HistGradientBoostingClassifier(class_weight="balanced", random_state=seed)   (NaN 기본 지원, D8)
@dataclass(frozen=True)
class TrainOutput:
    models: Mapping[str, Pipeline]      # "logreg", "hgb" — 둘 다 split.train으로 학습
    cv_pr_auc: Mapping[str, float]      # split.train에서 GroupKFold(n_splits=5) average_precision 평균
    feature_names: tuple[str, ...]
def train_models(fm: FeatureMatrix, split: Split, *, feature_names: Sequence[str] = FEATURE_NAMES, seed: int = 42) -> TrainOutput
def save_artifact(path: Path, pipeline: Pipeline, *, model_version: str, feature_names: Sequence[str],
                  thresholds: Mapping[str, float], metrics: Mapping[str, Any]) -> None
    # joblib.dump({"pipeline", "feature_names": list, "feature_schema_version": FEATURE_SCHEMA_VERSION,
    #              "sklearn_version": sklearn.__version__, "model_version", "thresholds", "trained_at": UTC ISO, "metrics"})
# CLI
# python -m phishguard.training.train --dataset data/processed/dataset.csv --out-dir models [--lexical-only]
#   → featurize → three_way_split(seed=42) → train_models → 두 모델을 models/{name}{-lexical}.joblib로 저장
#   → cv_pr_auc가 높은 모델을 models/model.joblib로도 저장 (model_version = f"{name}-{YYYYMMDD}")
```

학습에는 `split.train`만 사용한다. `split.val`은 T17 보정, `split.test`는 T15 평가 전용(학습·보정에 절대 사용 금지).

- [ ] **Step 1: 실패하는 테스트 작성 — `tests/test_train.py`**

픽스처 `synthetic_fm`: 600행, 그룹 120개, `is_ip_host`·`brand_in_subdomain`이 레이블과 강하게 상관, `domain_age_days`의 30%는 NaN, 나머지 특징은 난수(`np.random.default_rng(0)`).

```python
@pytest.mark.parametrize("name", ["logreg", "hgb"])
def test_pipeline_fits_with_nan(synthetic_fm, name):
    p = make_pipeline(name).fit(synthetic_fm.X, synthetic_fm.y)
    proba = p.predict_proba(synthetic_fm.X)[:, 1]
    assert proba.shape == (600,) and ((proba >= 0) & (proba <= 1)).all()

def test_train_models_uses_train_split_only(synthetic_fm):
    split = three_way_split(synthetic_fm)
    out = train_models(synthetic_fm, split)
    assert set(out.models) == {"logreg", "hgb"} and all(v > 0.8 for v in out.cv_pr_auc.values())

def test_lexical_feature_list():
    assert set(LEXICAL_FEATURES) | set(NETWORK_FEATURES) == set(FEATURE_NAMES)
    assert not set(LEXICAL_FEATURES) & set(NETWORK_FEATURES)

def test_artifact_roundtrip(tmp_path, synthetic_fm):
    p = make_pipeline("hgb").fit(synthetic_fm.X, synthetic_fm.y)
    save_artifact(tmp_path / "m.joblib", p, model_version="hgb-test", feature_names=FEATURE_NAMES,
                  thresholds=DEFAULT_ML_THRESHOLDS, metrics={})
    d = joblib.load(tmp_path / "m.joblib")
    assert d["feature_names"] == list(FEATURE_NAMES) and d["feature_schema_version"] == FEATURE_SCHEMA_VERSION
    assert d["sklearn_version"] == sklearn.__version__
```

- [ ] **Step 2: 실패 확인** — Run: `python -m pytest tests/test_train.py -v` → Expected: FAIL

- [ ] **Step 3: 구현** (lexical-only면 `fm.X[list(LEXICAL_FEATURES)]`로 학습하고 `feature_names=LEXICAL_FEATURES`로 저장)

- [ ] **Step 4: 통과 확인** — Run: `python -m pytest tests/test_train.py -v` → Expected: PASS

- [ ] **Step 5: 실제 학습** — Run: `python -m phishguard.training.train --dataset data/processed/dataset.csv --out-dir models` 그리고 `--lexical-only`로 한 번 더
Expected: `models/logreg.joblib`, `models/hgb.joblib`, `models/logreg-lexical.joblib`, `models/hgb-lexical.joblib`, `models/model.joblib` 생성, 각 CV PR-AUC 출력.

- [ ] **Step 6: Commit** — `git add src tests && git commit -m "feat: model training and artifact persistence"`

---

### Task 15: 성능 평가와 규칙 vs ML 비교 리포트

**Files:**
- Create: `src/phishguard/training/evaluate.py`
- Test: `tests/test_evaluate.py`
- Output(커밋함): `reports/evaluation.md`, `reports/metrics.json`

**Interfaces:**
- Consumes: T10 `RuleEngine`; T12 `FeatureMatrix`, `three_way_split`, `featurize`, `load_labeled_csv`; T14 아티팩트 형식; T4 `defang`
- Produces:

```python
@dataclass(frozen=True)
class Metrics:
    precision: float; recall: float; f1: float; fpr: float; roc_auc: float; pr_auc: float
    tn: int; fp: int; fn: int; tp: int
def binary_metrics(y_true: np.ndarray, scores: np.ndarray, threshold: float) -> Metrics
    # 예측 = scores >= threshold. roc_auc/pr_auc는 scores 원값(roc_auc_score, average_precision_score). 0으로 나누면 0.0
AGE_RULES: frozenset[str] = frozenset({"R06", "R07", "R08"})
def rule_scores(fm: FeatureMatrix, engine: RuleEngine, *, disabled: frozenset[str] = frozenset()) -> np.ndarray
    # 각 행으로 FeatureVector(values=row, evidence={}) 생성 → engine.evaluate(...).score
def bias_audit(fm: FeatureMatrix, split: Split) -> float
    # LogisticRegression을 split.train의 ["url_length", "path_length"]만으로 학습 → split.test ROC-AUC
def evaluate_all(fm: FeatureMatrix, split: Split, artifacts: Mapping[str, dict], engine: RuleEngine,
                 *, fresh: FeatureMatrix | None = None) -> dict[str, Any]
def write_report(results: Mapping[str, Any], md_path: Path, json_path: Path) -> None
# CLI
# python -m phishguard.training.evaluate --dataset data/processed/dataset.csv --models-dir models
#        [--fresh data/raw/fresh.csv] --out-dir reports
```

평가 대상(모두 **같은 `split.test`**, 같은 특징):

| 이름 | 점수 | 이진 판정 임계값 |
|---|---|---|
| `rules` | `rule_scores` | `score >= thresholds.suspicious` (보조: `>= dangerous`도 기록) |
| `rules-no-age` | `rule_scores(disabled=AGE_RULES)` — 과거 데이터는 나이가 전부 결측이라 공정 비교용 | 같음 |
| `logreg`, `hgb`, `logreg-lexical`, `hgb-lexical` | `predict_proba[:, 1]` | 아티팩트 `thresholds.suspicious` |

`reports/evaluation.md` 필수 섹션(이 제목 그대로):
1. `## 데이터 요약` — manifest의 입력 파일·해시, 클래스별 개수, train/val/test 크기
2. `## 테스트 세트 비교` — 위 표 6행 × {precision, recall, F1, FPR, ROC-AUC, PR-AUC}
3. `## 신규 수집 데이터 검증` — `--fresh`가 있으면 같은 표, 없으면 "신규 데이터 없음"
4. `## 편향 감사` — `bias_audit` 값. 0.90 초과면 "⚠ URL 길이만으로도 구분이 쉬움: 데이터셋 편향 가능성(리스크 K1)" 문구
5. `## 특징 중요도` — LR 계수 상위 10(부호 포함), HGB `permutation_importance`(test에서 최대 5,000행 샘플, `n_repeats=5`, `random_state=42`) 상위 10
6. `## 규칙과 데이터의 방향 비교` — 각 규칙의 대상 특징에 대한 LR 계수 부호가 음수(=데이터상 정상 쪽 신호)인 규칙 목록
7. `## 오분류 예시` — 최고 성능 모델의 미탐 10개, 오탐 10개. **URL은 `defang()` 처리**(리스크 K10)
8. `## 서빙 모델 권장` — Q7 기준 적용 결과(나이 포함 데이터가 클래스별 1,000건 미만이면 lexical 모델 권장)

**목표치(미달이어도 Task는 완료로 보되 원인 분석을 리포트 8번 섹션 아래에 기록):** 최고 ML 모델 test ROC-AUC ≥ 0.95, 최고 ML 모델 PR-AUC > `rules-no-age` PR-AUC.

- [ ] **Step 1: 실패하는 테스트 작성 — `tests/test_evaluate.py`**

```python
def test_binary_metrics_exact():
    m = binary_metrics(np.array([1, 1, 0, 0]), np.array([0.9, 0.4, 0.6, 0.1]), 0.5)
    assert (m.tp, m.fn, m.fp, m.tn) == (1, 1, 1, 1)
    assert m.precision == 0.5 and m.recall == 0.5 and m.fpr == 0.5 and m.roc_auc == 0.75

def test_binary_metrics_no_positive_predictions():
    m = binary_metrics(np.array([1, 0]), np.array([0.1, 0.2]), 0.5)
    assert m.precision == 0.0 and m.recall == 0.0

def test_rule_scores_with_empty_evidence(synthetic_fm):
    s = rule_scores(synthetic_fm, RuleEngine(load_resources()))
    assert s.shape == (len(synthetic_fm.y),) and (s >= 0).all()

def test_bias_audit_in_unit_interval(synthetic_fm):
    assert 0.0 <= bias_audit(synthetic_fm, three_way_split(synthetic_fm)) <= 1.0

def test_report_sections_and_defang(tmp_path, small_results):
    write_report(small_results, tmp_path / "e.md", tmp_path / "m.json")
    md = (tmp_path / "e.md").read_text(encoding="utf-8")
    for h in ["## 데이터 요약", "## 테스트 세트 비교", "## 신규 수집 데이터 검증", "## 편향 감사",
              "## 특징 중요도", "## 규칙과 데이터의 방향 비교", "## 오분류 예시", "## 서빙 모델 권장"]:
        assert h in md
    assert "http://evil" not in md and "hxxp://evil[.]" in md
    json.loads((tmp_path / "m.json").read_text(encoding="utf-8"))
```

(`synthetic_fm`은 T14 픽스처를 `tests/conftest.py`로 옮겨 공유. `small_results`는 `evaluate_all`을 `synthetic_fm`(urls에 `http://evil{i}.xyz/` 포함)과 T14 방식으로 학습한 작은 아티팩트로 실행한 결과.)

- [ ] **Step 2: 실패 확인** — Run: `python -m pytest tests/test_evaluate.py -v` → Expected: FAIL

- [ ] **Step 3: 구현**

- [ ] **Step 4: 통과 확인** — Run: `python -m pytest tests/test_evaluate.py -v` → Expected: PASS

- [ ] **Step 5: 실제 평가** — Run: `python -m phishguard.training.evaluate --dataset data/processed/dataset.csv --models-dir models --out-dir reports` (`data/raw/fresh.csv`가 있으면 `--fresh` 추가)
Expected: `reports/evaluation.md`에 8개 섹션 모두 채워짐. 결과 요약(최고 모델, ROC-AUC, 편향 감사 값, 서빙 모델 권장)을 사용자에게 보고.

- [ ] **Step 6: Commit** — `git add src tests reports && git commit -m "feat: evaluation and rule-vs-ML comparison report"`

---

### Task 16: ML 모델 서빙 통합

**Files:**
- Create: `src/phishguard/ml.py`
- Modify: `src/phishguard/analyzer.py` (예측 연결, `build_analyzer`에서 모델 로드)
- Test: `tests/test_ml.py`, `tests/test_analyzer.py`(추가)

**Interfaces:**
- Consumes: T1 `FeatureVector`, `ModelResult`, `Verdict`, `FEATURE_NAMES`, `FEATURE_SCHEMA_VERSION`; T14 아티팩트 형식; T11 `Analyzer`, `build_analyzer`
- Produces:

```python
class ModelLoadError(RuntimeError): ...
class PhishModel:
    def __init__(self, pipeline: Any, feature_names: Sequence[str], thresholds: Mapping[str, float], model_version: str) -> None
    @classmethod
    def load(cls, path: Path) -> "PhishModel"
        # ModelLoadError: 파일 없음 / feature_schema_version 불일치 / feature_names ⊄ FEATURE_NAMES /
        #                 sklearn major.minor 불일치 (리스크 K8)
    def predict(self, features: FeatureVector) -> ModelResult
        # 1행 DataFrame(columns=feature_names, 값은 features.values에서 이름으로 선택) → predict_proba[:, 1]
    def verdict_for(self, probability: float) -> Verdict     # >= dangerous → DANGEROUS, >= suspicious → SUSPICIOUS
```

`build_analyzer`: `PhishModel.load(settings.model_path)`를 시도하고 `ModelLoadError`면 `logging.warning` 후 `model=None`. `Analyzer.analyze` 6단계에서 `model = self.model.predict(features) if self.model else None`. 최종 판정은 `AnalysisResult.final_verdict`(D10)가 처리하므로 추가 로직 없음.

- [ ] **Step 1: 실패하는 테스트 작성**

```python
# tests/test_ml.py  (tiny_artifact 픽스처: synthetic_fm으로 hgb 학습 후 save_artifact)
def test_load_and_predict(tiny_artifact, sample_result):
    m = PhishModel.load(tiny_artifact)
    r = m.predict(sample_result.features)
    assert 0.0 <= r.probability <= 1.0 and r.model_version == "hgb-test"

@pytest.mark.parametrize("p, v", [(0.1, Verdict.SAFE), (0.3, Verdict.SUSPICIOUS), (0.7, Verdict.DANGEROUS)])
def test_verdict_thresholds(tiny_artifact, p, v):
    assert PhishModel.load(tiny_artifact).verdict_for(p) is v

def test_missing_file_raises(tmp_path):
    with pytest.raises(ModelLoadError): PhishModel.load(tmp_path / "none.joblib")

def test_schema_mismatch_raises(tmp_path, tiny_artifact):
    d = joblib.load(tiny_artifact); d["feature_schema_version"] = 999; joblib.dump(d, tmp_path / "x.joblib")
    with pytest.raises(ModelLoadError): PhishModel.load(tmp_path / "x.joblib")

def test_lexical_model_selects_subset(tmp_path, synthetic_fm, sample_result): ...
    # LEXICAL_FEATURES로 학습·저장한 모델도 전체 FeatureVector로 predict 가능

# tests/test_analyzer.py 추가
def test_analyzer_with_model_sets_model_result(tiny_artifact): ...   # result.model is not None, final_verdict == most_severe
def test_build_analyzer_without_model_file(tmp_path, monkeypatch): ...  # PHISHGUARD_MODEL_PATH=없는 경로 → analyzer.model is None
```

- [ ] **Step 2: 실패 확인** — Run: `python -m pytest tests/test_ml.py tests/test_analyzer.py -v` → Expected: FAIL

- [ ] **Step 3: 구현**

- [ ] **Step 4: 전체 통과 확인** — Run: `python -m pytest -v` → Expected: 전체 PASS

- [ ] **Step 5: 수동 확인** — `uvicorn phishguard.web.main:app` → `http://paypal-secure.com/login` 입력
Expected: 결과 화면에 규칙 판정과 함께 "ML 판정: NN% (위험/주의/안전)" 표시. `models/model.joblib`을 잠시 다른 이름으로 바꾸고 재시작하면 "학습된 모델 없음" 표시(서버는 정상 동작).

- [ ] **Step 6: Commit** — `git add src tests && git commit -m "feat: serve ML model alongside rule engine"`

**Phase 4 검증:** Phase별 완료 기준 표의 Phase 4 항목.

---

# Phase 5 — 리팩토링, 보정, 배포

### Task 17: 3단계 경계값의 데이터 기반 보정

명세 4번 문제점("규칙 점수와 3단계 경계값을 정하는 기준이 주관적")에 대한 대응. 가중치는 사람이 정한 값을 유지하되(설명 가능성), **경계값은 검증 세트에서 명시적 기준으로 결정**한다.

**Files:**
- Create: `src/phishguard/training/calibrate.py`
- Modify: `src/phishguard/resources/rules.yaml` (CLI 실행 결과), `models/model.joblib` (thresholds 갱신), `reports/evaluation.md` (섹션 추가)
- Test: `tests/test_calibrate.py`

**Interfaces:**
- Consumes: T12 `three_way_split`, `featurize`; T14 `save_artifact` 형식; T15 `rule_scores`, `binary_metrics`, `evaluate_all`, `write_report`
- Produces:

```python
MIN_PRECISION_DANGEROUS: float = 0.95   # "위험"이라고 하면 95% 이상 실제 피싱
MAX_MISS_RATE_SAFE: float = 0.05        # 피싱 중 "안전"으로 빠지는 비율 5% 이하
MIN_SUPPORT: int = 10
def calibrate_thresholds(scores: np.ndarray, y: np.ndarray, *,
                         min_precision_dangerous: float = MIN_PRECISION_DANGEROUS,
                         max_miss_rate_safe: float = MAX_MISS_RATE_SAFE) -> tuple[float, float] | None
def update_rules_yaml(path: Path, thresholds: tuple[int, int]) -> None   # weights는 그대로 보존
def update_model_thresholds(path: Path, thresholds: tuple[float, float]) -> None
# CLI
# python -m phishguard.training.calibrate --dataset data/processed/dataset.csv --model models/model.joblib
#        --rules-yaml src/phishguard/resources/rules.yaml --report reports/evaluation.md
```

알고리즘 (`candidates = sorted(set(scores))`):
1. `dangerous` = `scores >= t`인 표본이 `MIN_SUPPORT` 이상이고 그 precision이 `min_precision_dangerous` 이상인 **가장 작은** `t`.
2. `suspicious` = `t <= dangerous`이고 `(y == 1) & (scores < t)`의 개수 / `(y == 1)`의 개수가 `max_miss_rate_safe` 이하인 **가장 큰** `t`.
3. 둘 중 하나라도 없으면 `None` → CLI는 기존 값을 유지하고 "보정 불가: <이유>"를 리포트에 기록.
4. 규칙 점수는 정수이므로 `int`로 저장. 반드시 `split.val`만 사용하고, 보정 후 `split.test`로 다시 평가해 리포트의 `## 경계값 보정` 섹션에 보정 전/후 지표 표, 사용한 기준 2개, 새 경계값을 기록.

- [ ] **Step 1: 실패하는 테스트 작성 — `tests/test_calibrate.py`**

```python
def test_calibrate_thresholds():
    # 정상: 점수 0 ×90, 40 ×10 / 피싱: 20 ×5, 40 ×15, 80 ×80
    y = np.array([0] * 100 + [1] * 100)
    s = np.array([0.0] * 90 + [40.0] * 10 + [20.0] * 5 + [40.0] * 15 + [80.0] * 80)
    # dangerous: t=40이면 precision 95/105=0.905 < 0.95, t=80이면 1.0 → 80
    # suspicious: t=80이면 놓치는 피싱 20/100=0.20, t=40이면 5/100=0.05 → 40
    assert calibrate_thresholds(s, y) == (40.0, 80.0)          # 반환 순서 (suspicious, dangerous)

def test_calibrate_returns_none_when_precision_unreachable():
    y = np.array([0, 1] * 50); s = np.ones(100)
    assert calibrate_thresholds(s, y) is None

def test_update_rules_yaml_preserves_weights(tmp_path): ...
    # 기본 rules.yaml 복사 → update_rules_yaml(p, (25, 55)) → load 결과 thresholds == (25, 55), weights 동일
```

분리가 완벽한 데이터에서는 2번 단계가 `t <= dangerous` 제약 때문에 `suspicious == dangerous`(주의 구간 없음)가 될 수 있으며, 이는 정상 동작이다.

- [ ] **Step 2: 실패 확인** — Run: `python -m pytest tests/test_calibrate.py -v` → Expected: FAIL

- [ ] **Step 3: 구현**

- [ ] **Step 4: 통과 확인** — Run: `python -m pytest -v` → Expected: 전체 PASS (`rules.yaml` 값이 바뀌면 T2 `test_load_default_resources`의 `(30, 60)` 단언과 T10의 등급 단언이 깨질 수 있으므로, 해당 테스트는 `load_resources()`가 아닌 **고정 thresholds `(30, 60)`을 주입한 Resources**를 쓰도록 이 Step에서 수정)

- [ ] **Step 5: 실제 보정 실행** — Run: 위 CLI
Expected: `rules.yaml`·`model.joblib` 경계값 갱신, 리포트에 `## 경계값 보정` 섹션 추가. 새 경계값을 사용자에게 보고.

- [ ] **Step 6: Commit** — `git add src tests reports && git commit -m "feat: data-driven calibration of 3-level thresholds"`

---

### Task 18: 리팩토링, 성능, Docker, 문서

**Files:**
- Modify: `src/phishguard/redirect.py` (선택적 리다이렉트 캐시), `src/phishguard/web/main.py` (로깅), `src/phishguard/analyzer.py`
- Move: `src/phishguard/web/stub.py`의 내용을 `tests/fakes.py`로 합침 (프로덕션 패키지에서 스텁 제거, import 경로 수정)
- Create: `Dockerfile`, `.dockerignore`, `README.md`
- Test: `tests/test_redirect.py`(추가), 전체 회귀

**Interfaces:**
- Consumes: 전체
- Produces: `RedirectResolver.__init__(..., cache: TTLCache | None = None)` — 키 `redir:{normalized}`, TTL 3600초, `complete=True` 결과만 캐시. 그 외 공개 인터페이스는 **변경 금지**.

- [ ] **Step 1: 리다이렉트 캐시 테스트 추가 후 실패 확인**

```python
def test_redirect_result_is_cached():
    # 같은 bit.ly URL을 두 번 resolve → respx route.call_count == 1, 두 결과 동일
```
Run: `python -m pytest tests/test_redirect.py::test_redirect_result_is_cached -v` → Expected: FAIL

- [ ] **Step 2: 캐시 구현, `build_analyzer`에서 같은 `TTLCache` 주입** → 같은 테스트 PASS

- [ ] **Step 3: 스텁 이동과 정리**

`web/stub.py`의 `StubAnalyzer`·`make_sample_result`를 `tests/fakes.py`로 옮기고 `stub.py`를 삭제한 뒤 모든 import를 수정. 로깅: `logging.basicConfig(level=INFO)`를 `web/main.py`에서 설정하고, 분석 1건당 `registered_domain`, `final_verdict`, 소요 시간(ms)만 기록(전체 URL·쿼리 문자열은 개인정보·피싱 토큰 포함 가능성 때문에 기록하지 않음). 50줄을 넘는 함수는 의미 단위로 분리. 모든 공개 함수에 타입 힌트.
Run: `python -m pytest -v` → Expected: 전체 PASS, `python -c "import phishguard.web.stub"` → `ModuleNotFoundError`

- [ ] **Step 4: Dockerfile 작성**

`python:3.11-slim` 기반, `WORKDIR /app`, `pyproject.toml`과 `src/` 복사 후 `pip install --no-cache-dir .`, `models/`가 있으면 복사(`COPY models/ /app/models/` — 빈 폴더 대비 `models/.gitkeep` 추가), `ENV PHISHGUARD_CACHE_PATH=/app/data/cache.sqlite3`, `EXPOSE 8000`, `CMD ["uvicorn", "phishguard.web.main:app", "--host", "0.0.0.0", "--port", "8000"]`. `.dockerignore`: `.venv`, `data/raw`, `data/processed`, `tests`, `.git`, `__pycache__`.

현재 개발 PC에는 Docker가 설치되어 있지 않다. Docker Desktop이 설치된 경우에만 다음을 실행하고, 없으면 이 검증을 건너뛰었다고 사용자에게 보고한다.
Run: `docker build -t phishguard .` → `docker run --rm -p 8000:8000 phishguard`
Expected: `http://127.0.0.1:8000/healthz` → `{"status":"ok"}`

- [ ] **Step 5: README 작성** — 섹션: 소개, 설치(venv), 데이터 준비(PhiUSIIL 다운로드 링크, 수집기 사용법, Windows 작업 스케줄러 예: `schtasks /Create /SC DAILY /TN phishguard-collect /TR "<프로젝트>\.venv\Scripts\python.exe -m phishguard.training.collect_feed --source openphish --out <프로젝트>\data\raw\feed.csv" /ST 09:00`), 학습→평가→보정 순서, 서버 실행, Docker, 판정 방식 설명(규칙 표 요약, ML, 최종 판정 정책 D10), 한계(리스크 K1·K3·K6), 고지문.

- [ ] **Step 6: 최종 검증**

Run: `python -m pytest -v` → Expected: 전체 PASS
Run: `python -m pytest -m network -v` → Expected: 결과를 사용자에게 그대로 보고(실패 항목 포함)
Run: `uvicorn phishguard.web.main:app` → 브라우저로 정상 URL 1개, 브랜드 사칭 URL 1개, 단축 URL 1개 확인

- [ ] **Step 7: Commit** — `git add -A && git commit -m "refactor: cache redirects, remove stub from package, add Docker and README"`

**Phase 5 검증:** Phase별 완료 기준 표의 Phase 5 항목.

---

## 부록 A — 요구사항 추적표

| 명세 요구사항 | 구현 Task | 검증 |
|---|---|---|
| URL 형식 정리 | T5 | `test_messy_inputs`, `test_refang`, `test_idn_host_is_punycoded` |
| 단축 URL 리다이렉트 추적·최종 주소 확인 | T7, T11, T18 | `test_resolves_bitly_single_hop`, `test_resolves_korean_shortener`, `test_end_to_end_smishing_shortener` |
| URL 구성 요소 분해 + PSL 기반 등록 도메인 | T6 | `test_multi_label_suffix`, `test_private_suffix_shared_hosting` |
| IP 주소 사용 특징 | T6, T9, T10(R01) | `test_parse_ip_host`, `test_ip_and_userinfo`, `test_ip_rule` |
| 서브도메인 개수 특징 | T9, T10(R09) | `test_num_subdomains_excludes_www` |
| 등록 도메인이 아닌 위치의 브랜드명 | T9, T10(R03–R05) | `test_brand_in_subdomain`, `test_brand_in_path`, `test_combosquat` |
| 도메인 생성일 특징 | T8, T9, T10(R06–R08) | `test_rdap_success_and_cache_hit`, `test_age_rules_are_exclusive` |
| 규칙 기반 베이스라인 | T10 | `tests/test_rules.py` |
| 동일 특징으로 ML 학습 | T12, T14 | `test_featurize_columns_and_offline`, `test_train_models_uses_train_split_only` |
| 성능 비교 | T15 | `reports/evaluation.md` `## 테스트 세트 비교` |
| 위험 여부와 이유 표시(웹) | T3, T4, T11, T16 | `test_result_page_shows_verdict_reasons_and_disclaimer` |
| 3단계 경계값의 주관성 문제 | T17 | `tests/test_calibrate.py`, 리포트 `## 경계값 보정` |
| 새로 수집한 피싱 URL로 성능 확인 | T13, T15 | 리포트 `## 신규 수집 데이터 검증` |
| 공개 피싱 URL 목록 활용 | T12, T13 | manifest.json |
| Docker | T18 | `docker build` (Docker 설치 시) |

## 부록 B — 새 세션에서 이 계획서를 사용하는 방법

1. 새 세션에 이 파일 전체를 컨텍스트로 넣고 "IMPLEMENTATION_PLAN.md의 Task N을 구현하라"고 지시한다. 한 세션(또는 하위 에이전트)에 **Task 하나**씩 맡기는 것을 권장한다.
2. 각 Task는 **Files / Interfaces / Steps** 만으로 구현 가능하도록 작성되었다. 다른 Task의 코드를 볼 필요가 있으면 그 Task의 Interfaces 블록만 참조한다.
3. Task 순서는 의존 관계 순서다. T12–T15의 "실제 데이터로 실행" Step은 데이터 파일이 있어야 하므로, 없으면 단위 테스트까지만 완료하고 사용자에게 데이터 준비를 요청한다.
4. Open Questions의 답이 나오면 해당 Task 설명을 먼저 수정한 뒤 구현한다.
5. Interfaces의 이름·시그니처를 바꿔야 할 이유가 생기면, 구현 전에 이 계획서의 해당 Interfaces 블록과 이를 Consumes하는 모든 Task를 함께 수정한다.
