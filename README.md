# 보안 로그 분석 AI Agent - 1단계: 로그 데이터 분석 기반 구축

[Zenodo russellmitchell 데이터셋](https://zenodo.org/records/19483937)(AIT Log Data Suite 시나리오)의
실제 로그를 Python으로 읽고 파싱하여, 이후 AI Agent가 공통으로 활용할 수 있는
**Normalized Event** 형태로 변환하는 기반을 구축하는 단계입니다.

이 단계에서는 웹페이지, API 서버, 시각화, 보고서, LLM/Agent/RAG/VectorDB를 구현하지 않습니다.
Parser는 로그를 구조화하는 역할만 담당하며, 공격 탐지나 보안 판단 로직은 포함하지 않습니다.

## 프로젝트 구조

```
project/
├── data/                 # 데이터셋을 놓는 위치 (git에는 커밋하지 않음, data/README.md 참고)
├── src/
│   ├── loader/           # log_loader.py(russellmitchell) + gaia_loader.py(GAIA) — 각 데이터셋의
│   │                     # 디렉터리 구조를 탐색해 지원 대상 파일의 원본 내용을 읽는다
│   ├── parser/           # 형식별 파서(syslog_auth/dnsmasq/.../gaia_metric/gaia_trace/gaia_log)
│   │                     # + 파일 경로 -> 파서 매핑(registry, 두 데이터셋 공용)
│   ├── models/            # RawLogLine, NormalizedEvent 데이터 모델 (두 데이터셋 공용)
│   └── skills/            # 정규화된 이벤트에 대한 구조적 요약 등, Agent가 재사용할 기능
├── tests/                 # 각 모듈에 대한 단위 테스트 (fixtures/ 는 실제 데이터에서 발췌한 샘플)
├── requirements.txt
└── main.py                # russellmitchell 파이프라인(로드 -> 파싱 -> 정규화 -> 요약) 진입점
                            # (GAIA는 아직 CLI로 연결하지 않았다 — 아래 GAIA 섹션 참고)
```

## 지원하는 로그 형식

실제 데이터셋을 확인해 존재가 확인된 형식만 구현했습니다.

| source_type | 원본 파일 | 형식 |
|---|---|---|
| `syslog_auth` | `<host>/logs/auth.log*` | 표준 syslog (sshd/CRON/su/sudo/systemd-logind/systemd) |
| `dnsmasq` | `<host>/logs/dnsmasq.log` | dnsmasq 쿼리/응답 로그 |
| `auditd` | `<host>/logs/audit/audit.log` | Linux auditd |
| `apache_access` | `<host>/logs/apache2/*access.log*` | Apache Combined / vhost_combined (`other_vhosts_access.log*`는 앞에 `vhost:port` 접두부가 붙음) |
| `apache_error` | `<host>/logs/apache2/*error.log*` | Apache error log |
| `openvpn` | `<host>/logs/openvpn.log` | OpenVPN 서버 로그 (클라이언트 접두부 3가지 형태) |

metricbeat 기반 시스템 메트릭 로그(`system.cpu.log` 등)는 이산적인 보안 이벤트가 아닌
시계열 수치 데이터라 이번 단계 범위에서 제외했습니다.

전체 데이터셋 기준 **82개 파일, 680,166줄(빈 줄 제외)이 모두 NormalizedEvent로 변환**됩니다
(미파싱 0건). `apache_error`에는 Apache가 쓴 형식 외에 그 아래에서 실행된 프로세스의 stderr가
섞여 들어오는데(samba 메시지, wget 진행률 등), 이런 라인은 필드를 지어내지 않고
`event_type="apache_error_unstructured"`로 원문만 보존합니다.

## Normalized Event

```python
NormalizedEvent(
    event_id,       # f"{host}:{source_type}:{line_number}"
    source_type, host, source_path, line_number,  # 어느 파일의 몇 번째 줄에서 왔는지
    timestamp,      # tz-aware datetime | None
    raw,            # 원본 라인 전체 (손실 없이 보존)
    process, pid, user, src_ip, dst_ip,
    event_type,     # 파서가 구조적으로 분류한 이벤트 종류 (예: ssh_accepted, dns_query, http_request)
    message,        # 사람이 읽을 핵심 메시지
    extra,          # 형식별 고유 필드 (예: apache의 status/method, auditd의 audit_type/res 등)
)
```

`line_number`는 원본 `gather/<host>/logs/...` 파일의 1-based 줄 번호이며, 데이터셋의
`labels/<host>/logs/...` 정답 라벨 파일(`{"line": N, "labels": [...]}` 형식)과 그대로 조인할 수
있도록 보존했습니다.

`event_id`는 `"<source_path>:<line_number>"` 형식입니다. host와 source_type만으로 만들면
로테이션 파일(`auth.log`와 `auth.log.1` 등)이 줄 번호를 각각 1부터 다시 매기기 때문에
충돌합니다. 경로를 포함하면 전체 680,166건에서 중복이 없고, 정답 라벨의 조인 키와도 일치합니다.

## 실행 방법

### 1. 의존성 설치

```bash
python -m venv .venv
.venv\Scripts\activate       # Windows
pip install -r requirements.txt
```

(이 환경에서는 `uv venv .venv && uv pip install --python .venv -r requirements.txt` 로 구성했습니다.)

### 2. 데이터셋 경로 지정

코드에는 절대경로를 하드코딩하지 않았습니다. 다음 중 하나로 데이터셋 위치를 지정하세요.

- `data/` 디렉터리 바로 아래에 데이터셋 내용(`dataset.yaml`, `gather/`, `labels/` 등)을 복사/연결
- `LOG_AGENT_DATASET_ROOT` 환경변수로 지정
- `main.py` 실행 시 `--dataset-root` 인자로 지정

```bash
python main.py --dataset-root "../Data/russellmitchell"
```

### 3. 정규화 결과 저장 / 재사용

기본 실행은 이벤트를 메모리에 쌓지 않고 흘려보내며 요약만 출력합니다. 결과를 파일로 남기려면
`--output`을 주고, 확장자로 형식을 고릅니다.

```bash
python main.py --output output/events.pkl                    # 단일 파일 (pickle)
python main.py --output output/events.jsonl                  # 단일 파일 (JSON Lines)
python main.py --output output/events.pkl --split-by-date    # UTC 날짜별로 분할
```

`--split-by-date`를 주면 `events_2022-01-21.pkl` 처럼 날짜별 파일이 생깁니다.
데이터셋 실제 분포는 아래와 같아, `dataset.yaml`이 선언한 구간(01-21 ~ 01-25) **바깥에도
데이터가 있습니다**. 선언 구간만 만들면 43,640건(6.4%)이 사라지므로 실제 존재하는 날짜를
모두 생성하고, `timestamp`가 없는 이벤트(`apache_error_unstructured`)도 버리지 않고
`events_undated.pkl`에 모읍니다.

| 파일 | 건수 | 크기 |
|---|---:|---:|
| `events_2022-01-20.pkl` | 34,100 | 13.8 MB |
| `events_2022-01-21.pkl` | 162,164 | 75.0 MB |
| `events_2022-01-22.pkl` | 158,042 | 75.4 MB |
| `events_2022-01-23.pkl` | 165,287 | 77.9 MB |
| `events_2022-01-24.pkl` | 151,033 | 66.9 MB |
| `events_2022-01-25.pkl` | 4,783 | 1.4 MB |
| `events_undated.pkl` | 4,757 | 0.9 MB |

저장한 파일은 다시 파싱하지 않고 바로 불러올 수 있습니다.

```python
from src.models import load_events
from src.skills import summarize_events

events = load_events("output/events.pkl")               # 제너레이터 (메모리에 전부 올리지 않음)
day = load_events("output/events_2022-01-24.pkl")       # 날짜별 파일도 동일하게 사용
print(summarize_events(day).total_events)
```

전체 데이터셋(680,166건) 기준 실측값입니다.

| 방식 | 파일 크기 | 적재+집계 시간 |
|---|---:|---:|
| 원본 로그 재파싱 | — | 약 20초 |
| `events.pkl` | 297 MB | **5.3초** |
| `events.jsonl` | 482 MB | 11.2초 |

pickle이 더 빠르고 작지만 파이썬 전용이며, **신뢰할 수 없는 pickle 파일은 열지 마세요**
(역직렬화 과정에서 임의 코드가 실행될 수 있습니다). 다른 도구와 주고받거나 내용을 눈으로
확인해야 한다면 JSON Lines를 쓰세요.

### 4. 테스트 실행

```bash
pytest
```

## 알려진 제약/가정

- syslog 계열(`auth.log`, `dnsmasq.log`)과 OpenVPN 로그는 형식 자체에 연도가 없어, 데이터셋
  관측 기간(`dataset.yaml`: 2022-01-21 ~ 2022-01-25)을 근거로 기본 연도를 2022로 가정했습니다.
- 원본 로그에 타임존 표기가 없는 경우(syslog, auditd epoch, Apache error log), 같은 이벤트를
  auditd epoch(UTC 고정)와 대조해 시스템 시각이 UTC로 설정되어 있음을 확인한 뒤 UTC로 정규화했습니다.
- 이 데이터셋에 실제로 존재하지 않는 메시지 형태(예: `auth.log`의 SSH `Failed password`,
  auditd의 `EXECVE` 타입)는 구현하지 않았습니다.

## GAIA MicroSS 지원

보안 위협뿐 아니라 일반적인 시스템/서비스 장애도 다루기 위해, [GAIA(MicroSS)
데이터셋](https://github.com/CloudWise-OpenSource/GAIA-DataSet)의 metric/trace/business
로그를 같은 NormalizedEvent 파이프라인으로 읽어오는 Loader/Parser를 추가했습니다.
russellmitchell용 기존 `log_loader.py`와 6개 파서는 전혀 수정하지 않았고, GAIA는 별도
Loader(`src/loader/gaia_loader.py`)와 파서 3종(`gaia_metric`, `gaia_trace`, `gaia_log`)으로
추가했습니다. `get_parser()`/`parse_lines()`는 source_type만 보고 동작하는 공용 함수라
양쪽 데이터셋에 그대로 재사용됩니다.

| source_type | 원본 파일 | 형식 |
|---|---|---|
| `gaia_metric` | `metric/<service>_<ip>_<metric_name>_<시작일>_<종료일>.csv` | `timestamp,value` (13자리 ms 타임스탬프 + 수치) |
| `gaia_trace` | `trace/trace_table_<service>_2021-07.csv` | 11개 컬럼의 서비스 호출 스팬(trace_id/span_id/parent_id/status_code 등) |
| `gaia_log` | `business/business_table_*.csv` | `datetime,service,message` 3컬럼(2021-07) 또는 `id,datetime,service,message` 4컬럼(2021-08) — message 안에 다시 파이프(`\|`)로 구분된 애플리케이션 로그 한 줄이 들어있음 |

**GAIA 데이터는 압축 해제가 먼저 필요합니다.** GitHub 배포본에서 metric/trace/business는
분할 zip(`business_split.z01 ...` + `business_split.zip`)으로 되어 있어, Bandizip/7-Zip 등으로
미리 압축을 풀어 `gaia_root/metric/`, `gaia_root/trace/`, `gaia_root/business/` 가 보이는
상태로 만들어야 `gaia_loader`가 읽을 수 있습니다(압축 해제 자체는 Loader의 책임이 아닙니다).

### 실제 데이터에서 확인한 구조적 특징

- **호스트 디렉터리가 없습니다.** russellmitchell은 `gather/<host>/logs/...`였지만, GAIA는
  `gaia_root` 바로 아래에 metric/trace/business가 평평하게 있습니다. metric은 파일명에서,
  trace/business는 행(row)의 `service_name`/`service` 컬럼에서 host를 얻습니다.
- **CSV 행이 물리적으로 여러 줄에 걸칠 수 있습니다.** trace/business의 `message` 필드가
  따옴표로 감싸인 채 줄바꿈을 그대로 담고 있어(로그 메시지 끝 개행), 텍스트 줄 단위로 읽으면
  레코드가 깨집니다. 그래서 이 둘은 `csv.DictReader`로 논리적 행 단위로 읽고, `line_number`는
  텍스트 줄 번호가 아니라 헤더를 제외한 데이터 행 번호입니다.
- **business의 컬럼 구성이 파일마다 다릅니다.** 2021-07 파일은 3컬럼(`datetime,service,message`),
  2021-08 파일은 4컬럼(`id,datetime,service,message` 또는 `,datetime,service,message`)입니다.
  `csv.DictReader`로 이름 기준으로 읽어 이 차이를 흡수합니다.
- **business의 message 내부 파이프 필드는 자리마다 의미가 다릅니다.** 예를 들어 어떤 줄은
  4번째 필드가 컨테이너 IP고 5번째가 서비스명이지만, 다른 줄은 4번째가 곧바로 서비스명이고
  5번째가 "파일명 -> 함수명 -> 줄번호" 형태의 소스 위치입니다. 실제로 확인된 것 이상으로
  의미를 추측하지 않기 위해 타임스탬프/레벨/메시지만 이름을 붙이고, 가운데 필드는
  `extra["fields"]`에 순서 그대로 리스트로 보존합니다.
- **metric 파일명의 서비스/지표명은 위치로 자를 수 없습니다.** 둘 다 언더스코어를 포함할 수
  있어(`redisservice1`, `system_network_summary_tcp_OutRsts`), 파일명에 항상 등장하는 IPv4
  토큰을 기준으로 앞을 service, 뒤를 metric_name으로 나눕니다. metric_name은 2,215개 이상의
  서로 다른 값이 있어 더 세분화하지 않고 문자열 그대로 보존합니다.
- **run/ 디렉터리(anomaly injection 기록/ground truth)는 의도적으로 읽지 않습니다.** 이
  디렉터리는 일반 시스템 로그와 실제 주입한 장애(`[memory_anomalies]` 등) 기록이 섞여 있는데,
  이를 일반 탐지 파이프라인에 넣으면 Agent가 정답을 미리 보고 판단하는 꼴이 됩니다. 향후
  평가(Evaluation) 단계에서만 별도로 읽어야 합니다 — russellmitchell의 `labels/`를 Parser가
  아예 건드리지 않는 것과 같은 원칙입니다.

### dataset 필드

`NormalizedEvent`에 `dataset: str = "russellmitchell"` 필드를 추가했습니다(기존 6개
russellmitchell 파서는 수정 없이 기본값을 그대로 씁니다. GAIA 파서 3종만 `dataset="gaia"`를
명시합니다). russellmitchell과 GAIA는 서로 다른 환경에서 수집된 독립적인 데이터셋이라
timestamp만으로 이벤트를 엮어 하나의 Incident로 잘못 묶으면 안 되는데, source_type만으로도
데이터셋을 구분할 수는 있지만(이름이 겹치지 않음) 그 판단을 암묵적인 명명 규칙에 맡기는
대신 명시적인 필드로 남기는 편이 안전하다고 판단했습니다.

### 테스트

```bash
pytest tests/test_gaia_loader.py tests/test_gaia_parsers.py tests/test_gaia_end_to_end.py
```

`tests/fixtures/gaia_*.csv`는 실제 GAIA 파일에서 그대로 발췌한 내용입니다(3컬럼/4컬럼 business
변형, parent_id가 0인 스팬과 0이 아닌 스팬, 정수/실수 value 등을 모두 포함). end-to-end
테스트는 이 fixture들을 metric/trace/business 디렉터리 구조로 배치해 `gaia_loader` ->
`parse_lines` -> `summarize_events`까지 실제로 통과시킵니다.

### 아직 다루지 않은 GAIA 데이터

- **run/**: 위에서 설명한 대로 ground truth라 의도적으로 제외했습니다.
- **시스템 로그(순수 텍스트)**: GAIA README의 변경 이력에는 "다음 업데이트에서 시스템 로그를
  추가하겠다"는 계획이 적혀 있지만, 현재 내려받은 버전(V1.10, 2021-07~08 데이터)에는 별도의
  OS 텍스트 로그 파일이 실제로 없습니다. `system_*` 접두 파일은 모두 metricbeat류 수치
  메트릭(csv)이며 로그 텍스트가 아닙니다 — 존재하지 않는 형식을 추측해 만들지 않았습니다.
- **Companion_Data**: MicroSS와 무관한 별도 데이터셋(익명화된 메트릭/로그 벤치마크)이라
  이번 범위에 포함하지 않았습니다.
- **request/처리량 지표**: "요청 수" 같은 지표는 metric CSV에 별도로 없습니다. 필요하다면
  trace 스팬을 집계해서 구해야 하는데, 이는 파서가 아니라 이후 분석(Skill) 단계의 일입니다.
