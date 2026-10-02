# Security Analysis Skill

## 1. Skill 이름

`security_analysis`

## 2. 목적

이미 생성된 Finding 중 보안 관련 Finding만 골라낸다.

**이 Skill은 단순 selector다.** detector를 실행하지 않고, 새로운 보안 판단도 하지 않는다.
보안 전용 detector는 아직 없다.

## 3. 언제 사용하는지

- `application_analysis` 등으로 Finding을 이미 만든 뒤, 보안 관점에서 볼 Finding만
  추리고 싶을 때

## 4. 입력

`Iterable[Finding]`

다른 Skill과 달리 `NormalizedEvent`를 받지 않는다. 이미 만들어진 Finding을 받는다.
입력 범위 지정 인자(`dataset`, `host`, `start_time` 등)도 없다 — 이벤트를 읽지 않기
때문이다.

## 5. 출력

`list[Finding]`

입력 Finding 중 `category == "security"`인 것을 **입력 순서 그대로** 반환한다.
Finding의 어떤 필드도 수정하지 않는다: `severity`, `category`, `finding_type`, `metrics`,
`evidence`, `entities`, `summary`, `detector` 모두 그대로다.

현재 선별되는 Finding:

| finding_type | category | 만든 detector |
|---|---|---|
| `repeated_source_ip_scan` | security | find_scan_pattern (application_analysis Skill) |

## 6. 사용하는 기존 detector 함수

- 없음 (이 Skill은 detector를 실행하지 않고 이미 만들어진 Finding만 선별한다)

## 7. 사용 가능한 source_type / event_type

- source_type: 없음 (이벤트를 입력으로 받지 않는다)
- event_type: 없음

## 8. 제약사항

- **selector일 뿐이다.** 보안 판단, 위협 등급 재산정, Finding 병합, 공격 단계 추정, 여러
  Finding 간 상관분석을 하지 않는다.
- 입력에 없는 Finding은 나올 수 없다. 보안 Finding을 얻으려면 먼저
  `application_analysis`를 실행해야 한다.
- `repeated_source_ip_scan` Finding은 **관측 전체 기간에 대한 출발 IP별 집계**다. 짧은
  시간창 단위 탐지가 아니므로 시간 정밀도가 없다. 평가 단계에서 측정한 결과, 이 Finding의
  시간 폭은 관측 기간의 95.1%에 달했다. 따라서 이 Finding의 `start_time`/`end_time`을
  "공격이 일어난 시각"으로 해석하면 안 되고, 근거는 `entities`의 출발 IP와 `evidence`로
  확인해야 한다.
- 빈 결과는 "보안 이상이 없다"가 아니라 "입력 Finding 중 보안 category가 없었다"는 뜻이다.
- 인증, DNS, VPN, 권한 상승 관련 보안 Finding은 해당 detector가 없어 애초에 생성되지 않는다.

## 9. 사용하면 안 되는 경우

- 새로운 보안 탐지가 필요할 때 — 이 Skill은 탐지하지 않는다.
- Finding을 보안 관점으로 재분류하거나 severity를 올리고 싶을 때.
- 공격 시각을 특정해야 할 때 — 위 제약사항 참고.
- 사건 상관분석, 근본 원인 분석, 침해 사고 보고서 작성 — 모두 미구현이다.

## 10. 실행 script

`scripts/run_security_analysis.py`

```python
from agent_skills.application_analysis.scripts.run_application_analysis import (
    run_application_analysis,
)
from agent_skills.security_analysis.scripts.run_security_analysis import (
    run_security_analysis,
)

findings = run_application_analysis(events)
security_findings = run_security_analysis(findings)
```

`select_security_findings()`는 `run_security_analysis()`와 동일한 동작을 하는 별칭 수준의
순수 선별 함수다.
