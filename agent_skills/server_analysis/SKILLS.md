# Server Analysis Skill

## 1. Skill 이름

`server_analysis`

## 2. 목적

서버 resource metric의 이상 구간을 찾는다.

- CPU 사용률 이상
- 메모리 점유 이상
- 파일시스템 사용률 이상

## 3. 언제 사용하는지

- 특정 service/host의 자원 사용량이 평소와 다른지 확인할 때
- 애플리케이션 지연이나 에러가 자원 부족과 함께 나타났는지 확인할 때
  (단, 인과 판단은 하지 않는다 — 각각의 Finding만 얻는다)

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

## 5. 출력

`list[Finding]`

기존 `Finding` 모델을 그대로 쓴다. detector가 만든 값을 수정하지 않는다.

생성될 수 있는 Finding:

| finding_type | category |
|---|---|
| `cpu_usage_anomaly` | resource |
| `memory_usage_anomaly` | resource |
| `disk_usage_anomaly` | resource |
| `network_usage_anomaly` | network |

`Finding.service`에는 metric 파일명에서 얻은 service 이름이 들어간다.

## 6. 사용하는 기존 detector 함수

- `find_metric_anomaly` — (service, metric_name)별로 자기 baseline(p99) 대비 뚜렷하게 튄 구간

## 7. 사용 가능한 source_type / event_type

- source_type: `gaia_metric`
- event_type: metric 이벤트에는 별도 event_type 구분을 쓰지 않는다. 분석 대상은
  `extra["metric_name"]`이 `find_metric_anomaly`의 `SUPPORTED_METRICS`에 있는 이벤트뿐이다.

지원 metric (5종, `src/skills/gaia_metric_anomaly.py`의 `SUPPORTED_METRICS`가 기준):

- `system_cpu_total_norm_pct`
- `docker_cpu_user_pct`
- `docker_memory_stats_active_anon`
- `docker_network_in_packets`
- `system_filesystem_used_pct`

## 8. 제약사항

- **범위 지정은 결과 필터가 아니라 분석 입력 범위 지정이다.** 기간이나 host를 좁히면 그
  범위의 metric 값만 들어가고 baseline(p99)도 **그 범위에서 다시 계산된다**. 좁은 기간으로
  호출하면 넓은 기간 결과의 부분집합이 아닌 다른 Finding이 나올 수 있다.
- 위 5종 외의 metric은 분석하지 않는다. 의미를 데이터로 확인하지 못한 metric과 누적
  counter로 의심되는 metric은 detector가 의도적으로 제외한다.
- 누적 counter metric의 rate/delta 분석은 아직 구현되지 않았다.
- 메모리 바이트 수나 패킷 수처럼 위험한 절대치를 알 수 없는 metric은 통계적으로 크게
  튀어도 severity가 `low`로 유지된다. severity가 낮다는 것이 "튀지 않았다"는 뜻은 아니며,
  실제 편차는 `Finding.metrics`에서 확인해야 한다.
- `dataset`은 입력 이벤트를 고르는 용도다. `Finding.dataset`은 detector 값을 유지한다.
- metric 표본이 30건 미만인 (service, metric) 조합은 분석되지 않는다.
- threshold와 severity 규칙은 `src/skills`의 것이며 이 Skill에서 바꿀 수 없다.

## 9. 사용하면 안 되는 경우

- 자원 이상이 장애의 원인인지 판단해야 할 때 — 인과 분석은 하지 않는다.
- 지원 목록에 없는 metric을 분석해야 할 때.
- 애플리케이션 로그/요청/지연 분석 — `application_analysis` Skill을 쓴다.
- threshold 조정, Ground Truth 기반 재튜닝.

## 10. 실행 script

`scripts/run_server_analysis.py`

```python
from agent_skills.server_analysis.scripts.run_server_analysis import run_server_analysis

findings = run_server_analysis(events, service="dbservice2")
```

script는 (1) 입력 범위 적용, (2) `gaia_metric` 이벤트 분리, (3) `find_metric_anomaly` 호출,
(4) Finding 반환만 한다.
