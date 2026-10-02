# Network Analysis Skill

## 1. Skill 이름

`network_analysis`

## 2. 목적

네트워크 관련 metric의 이상 구간만 골라 본다.

**전용 network detector는 아직 없다.** 현재 가능한 범위는 `find_metric_anomaly`가 network
metric에서 만든 Finding(`category == "network"`)을 선별하는 것까지다.

## 3. 언제 사용하는지

- 수신 패킷 수 등 network metric이 평소와 다른지 확인할 때
- metric 전체가 아니라 network 관련 Finding만 보고 싶을 때

DNS, VPN, 방화벽, 포트 스캔 분석에는 사용할 수 없다(해당 detector 없음).

## 4. 입력

`Iterable[NormalizedEvent]`

선택 인자로 분석 입력 범위를 지정할 수 있다.

| 인자 | 의미 |
|---|---|
| `dataset` | `NormalizedEvent.dataset`이 이 값인 이벤트만 사용 |
| `host` | `NormalizedEvent.host`가 이 값인 이벤트만 사용 |
| `service` | GAIA metric의 service 이름(`NormalizedEvent.host`에 저장돼 있다)과 비교 |
| `start_time` / `end_time` | 이 기간(경계 포함)의 이벤트만 사용 |
| `source_types` | 아래 source_type 중 일부만 사용 |

이미 metric Finding을 만들어 둔 경우에는 `select_network_findings(findings)`를 쓴다
(입력이 `Iterable[Finding]`이며 detector를 다시 실행하지 않는다).

## 5. 출력

`list[Finding]`

기존 `Finding` 모델을 그대로 쓴다. 선별만 하고 필드를 수정하지 않는다.

생성될 수 있는 Finding:

| finding_type | category |
|---|---|
| `network_usage_anomaly` | network |

## 6. 사용하는 기존 detector 함수

- `find_metric_anomaly` — 호출한 뒤 `category == "network"` Finding만 선별한다

## 7. 사용 가능한 source_type / event_type

- source_type: `gaia_metric`
- event_type: metric 이벤트에는 별도 event_type 구분이 없다. 현재 network 계열로 분류되는
  지원 metric은 `docker_network_in_packets` 하나뿐이다.

## 8. 제약사항

- **전용 network detector가 없다.** 이 Skill은 resource metric 분석 결과 중 network로
  분류된 부분을 보여줄 뿐이며, 독립적인 네트워크 탐지 로직이 아니다.
- **이미 metric Finding이 있는 workflow에서는 detector를 다시 실행하지 말 것.**
  `server_analysis`를 이미 실행했다면 그 결과에 `select_network_findings()`를 적용하는 것이
  같은 결과를 주면서 중복 실행을 피한다. 어느 쪽을 쓸지 고르는 orchestration 최적화는
  이번 단계에서 구현하지 않았으므로 호출자가 판단해야 한다.
- **범위 지정은 결과 필터가 아니라 분석 입력 범위 지정이다.** 기간을 좁히면 baseline(p99)도
  그 범위에서 다시 계산된다.
- `docker_network_in_packets`는 NIC 대역폭 같은 용량 기준을 데이터에서 알 수 없어, 통계적으로
  크게 튀어도 severity가 `low`로 유지된다. 실제 편차는 `Finding.metrics`에서 확인한다.
- 이 metric을 gauge(수집 주기당 수신량)로 해석하고 있다. 누적 counter였을 경우의 rate/delta
  처리는 구현되지 않았다.
- `dataset`은 입력 이벤트를 고르는 용도다. `Finding.dataset`은 detector 값을 유지한다.
- threshold와 severity 규칙은 `src/skills`의 것이며 이 Skill에서 바꿀 수 없다.

## 9. 사용하면 안 되는 경우

- DNS 이상, VPN 접속 이상, 포트 스캔 탐지 — 해당 detector가 아직 없다.
  (`dnsmasq`, `openvpn` 파서는 있지만 분석 detector가 없다.)
- 네트워크 이상이 장애의 원인인지 판단해야 할 때.
- CPU/메모리/디스크 분석 — `server_analysis` Skill을 쓴다.
- HTTP 요청 급증이나 스캐닝 패턴 — `application_analysis` Skill을 쓴다.

## 10. 실행 script

`scripts/run_network_analysis.py`

```python
from agent_skills.network_analysis.scripts.run_network_analysis import (
    run_network_analysis,
    select_network_findings,
)

findings = run_network_analysis(events)

# metric Finding이 이미 있다면 detector를 다시 돌리지 않는다
findings = select_network_findings(existing_metric_findings)
```
