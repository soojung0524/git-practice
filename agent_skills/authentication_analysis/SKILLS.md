# Authentication Analysis Skill

## 1. Skill 이름

`authentication_analysis`

## 2. 목적

인증 관련 이벤트(로그인 실패, 권한 상승, VPN 접속 등)를 분석하는 것이 목적이다.

**현재 연결된 detector 없음 — 추후 확장 예정.** 이 Skill은 지금 어떤 분석도 하지 않고
항상 빈 결과를 반환한다.

## 3. 언제 사용하는지

현재는 사용할 상황이 없다. 인증 detector가 구현되기 전까지 이 Skill을 호출하면 항상
빈 리스트가 돌아온다.

Agent는 인증 분석이 필요할 때 이 Skill이 아직 미구현임을 인지하고, 결과가 없다는 것을
"이상이 없다"로 해석하지 않아야 한다.

## 4. 입력

`Iterable[NormalizedEvent]`

다른 Skill과 동일한 signature(`dataset`, `host`, `service`, `start_time`, `end_time`,
`source_types`)를 유지하지만, 현재는 입력을 사용하지 않는다(순회조차 하지 않는다).

## 5. 출력

`list[Finding]`

항상 빈 리스트(`[]`)다. **가짜 Finding을 만들지 않는다.**

## 6. 사용하는 기존 detector 함수

- 없음 (현재 연결된 detector 없음)

## 7. 사용 가능한 source_type / event_type

- source_type: 없음 (이 Skill은 아직 어떤 이벤트도 소비하지 않는다)
- event_type: 없음

참고로 인증 관련 로그를 읽는 **parser는 이미 존재한다.** 아래는 detector가 구현될 때
사용할 수 있는 재료이며, 현재 이 Skill이 소비하는 대상은 아니다.

- `syslog_auth` parser: `su_success`, `sudo_command`, `dovecot_auth_failure`, `auth_other`
- `auditd` parser
- `openvpn` parser

## 8. 제약사항

- 연결된 detector가 없어 분석 기능이 없다.
- 결과가 비어 있는 것은 "인증 이상이 없다"는 뜻이 **아니다**. 분석을 수행하지 않았다는
  뜻이다.
- parser는 있으나 분석 로직이 없으므로, 인증 이벤트는 현재 Finding으로 전환되지 않는다.

## 9. 사용하면 안 되는 경우

- 인증 이상 유무를 판단해야 할 때 — 판단할 수 없다. 미구현 상태를 그대로 보고해야 한다.
- 이 Skill의 빈 결과를 정상 판정 근거로 쓰는 경우.

## 10. 실행 script

`scripts/run_authentication_analysis.py`

```python
from agent_skills.authentication_analysis.scripts.run_authentication_analysis import (
    IMPLEMENTED,
    run_authentication_analysis,
)

assert IMPLEMENTED is False
findings = run_authentication_analysis(events)  # 항상 []
```

script는 다른 Skill과 같은 함수 signature만 유지한다. 인증 detector가 구현되면 이 함수
내부와 `DETECTORS`/`SOURCE_TYPES`, 그리고 이 문서의 6·7번 절을 함께 갱신한다.

## 미구현 기능 (참고)

아래 분석 기능은 아직 구현되지 않았다. 이름만 기록해 두며, 존재하는 함수로 가정하지
말 것.

- 로그인 실패 급증 분석
- brute force 패턴 분석
- 권한 상승 이벤트 분석
- VPN 접속 이상 분석
