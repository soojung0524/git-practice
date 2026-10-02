# Application Analysis Skill

## 1. Skill 이름

`application_analysis`

## 2. 목적

애플리케이션 계층에서 관측되는 이상을 찾는다.

- 웹 요청량 급증
- 단일 출발 IP의 스캐닝 패턴
- 애플리케이션/비즈니스 로그의 ERROR 비율 증가
- 서비스 응답 지연(latency) 이상

## 3. 언제 사용하는지

- 웹 서버나 애플리케이션 서비스의 이상 여부를 확인할 때
- 특정 host나 service, 특정 기간의 애플리케이션 동작을 점검할 때
- 보안 관점 분석 전에 먼저 애플리케이션 Finding을 만들어야 할 때
  (`security_analysis` Skill은 이 Skill이 만든 Finding을 입력으로 받는다)

## 4. 입력

`Iterable[NormalizedEvent]`

선택 인자로 분석 입력 범위를 지정할 수 있다.

| 인자 | 의미 |
|---|---|
| `dataset` | `NormalizedEvent.dataset`이 이 값인 이벤트만 사용 |
| `host` | `NormalizedEvent.host`가 이 값인 이벤트만 사용 |
| `service` | GAIA 이벤트의 service 이름(`NormalizedEvent.host`에 저장돼 있다)과 비교 |
| `start_time` / `end_time` | 이 기간(경계 포함)의 이벤트만 사용 |
| `source_types` | 아래 source_type 중 일부만 사용 |

## 5. 출력

`list[Finding]`

기존 `Finding` 모델을 그대로 쓴다. Agent 전용 결과 모델은 없다.
`finding_id`, `dataset`, `category`, `finding_type`, `start_time`, `end_time`, `host`,
`service`, `severity`, `summary`, `metrics`, `evidence`, `entities`, `detector`를 모두
detector가 만든 값 그대로 유지한다.

생성될 수 있는 Finding:

| finding_type | category | detector |
|---|---|---|
| `request_spike` | availability | find_request_spike |
| `repeated_source_ip_scan` | security | find_scan_pattern |
| `log_error_rate_spike` | error | find_log_error_spike |
| `service_latency_spike` | performance | find_latency_anomaly |

## 6. 사용하는 기존 detector 함수

- `find_request_spike` — host별 분당 요청 수가 자기 baseline(p99)보다 뚜렷하게 많은 구간
- `find_scan_pattern` — 출발 IP별 경로 다양성과 404 비율이 다른 IP들보다 높은 경우
- `find_log_error_spike` — service별 ERROR 로그 비율이 급증한 60초 창
- `find_latency_anomaly` — service별 span 소요시간이 자기 p99보다 뚜렷하게 큰 구간

## 7. 사용 가능한 source_type / event_type

- source_type: `apache_access`, `gaia_log`, `gaia_trace`
- event_type: `find_log_error_spike`는 `gaia_log` 중 `gaia_log_entry`만 사용한다
  (`gaia_log_unstructured` 행은 detector 내부에서 제외된다).
  `find_latency_anomaly`는 `gaia_trace_span`을 사용한다.

## 8. 제약사항

- **범위 지정은 결과 필터가 아니라 분석 입력 범위 지정이다.** `start_time`/`end_time`,
  `host`, `dataset` 등을 지정하면 그 범위의 이벤트만 detector 입력으로 들어가고,
  `find_request_spike`의 요청 수 baseline과 `find_latency_anomaly`/`find_log_error_spike`의
  percentile baseline도 **그 범위에서 다시 계산된다**. 따라서 전체 기간으로 호출한 결과의
  부분집합이 아니며, 범위를 바꾸면 Finding 자체가 달라질 수 있다.
- `dataset`은 입력 이벤트를 고르는 용도다. `Finding.dataset`은 detector가 정한 값을 그대로
  쓰며 wrapper가 덮어쓰지 않는다.
- `dataset`을 지정하지 않으면 russellmitchell(apache)과 GAIA(log/trace) Finding이 한
  리스트에 섞여 나온다. 서로 다른 데이터셋의 Finding을 하나의 사건으로 엮지 말 것.
- 해당 source_type 이벤트가 하나도 없으면 그 detector는 호출되지 않는다(빈 결과).
- `service`를 지정하면 russellmitchell 이벤트는 남지 않는다. russellmitchell 이벤트의
  `host`는 장비 이름이고 service 개념이 없다.
- 기간을 지정하면 timestamp가 없는 이벤트는 제외된다(범위 안인지 확인할 수 없다).
- threshold와 severity 규칙은 `src/skills`의 것이며 이 Skill에서 바꿀 수 없다.

## 9. 사용하면 안 되는 경우

- 근본 원인(root cause) 판단이 필요할 때 — 이 Skill은 관측된 이상만 보고한다.
- 서로 다른 dataset 또는 여러 Finding을 엮는 상관분석이 필요할 때.
- threshold나 severity를 조정하고 싶을 때 — 이 Skill로는 불가능하다.
- Ground Truth와 비교해 성능을 측정할 때 — `evaluation/` 모듈이 담당한다.
- 인증, DNS, VPN, 권한 상승 분석 — 해당 detector가 아직 없다.

## 10. 실행 script

`scripts/run_application_analysis.py`

```python
from agent_skills.application_analysis.scripts.run_application_analysis import (
    run_application_analysis,
)

findings = run_application_analysis(events, dataset="gaia", service="webservice1")
```

script는 (1) 입력 범위 적용, (2) source_type별 분리, (3) 기존 detector 호출,
(4) Finding 반환만 한다. 새로운 탐지 규칙이나 판정은 없다.
