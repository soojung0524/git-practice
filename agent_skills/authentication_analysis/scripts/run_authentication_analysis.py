"""Authentication Analysis Skill wrapper - 현재 not implemented.

인증 관련 로그를 읽는 parser는 이미 있지만(syslog_auth / auditd / openvpn), 인증 이벤트를
분석하는 detector는 아직 src/skills에 없다. 그래서 이 Skill은 인터페이스만 유지하고
항상 빈 리스트를 반환한다.

가짜 Finding을 만들지 않는다. 존재하지 않는 detector를 호출하지 않는다.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from src.models import Finding, NormalizedEvent

SKILL_NAME = "authentication_analysis"

# 연결된 detector가 없다. 구현되면 여기에 추가하고 SKILLS.md도 같이 고친다.
DETECTORS: tuple[str, ...] = ()

# 분석 대상이 될 수 있는 source_type이지만, 아직 이 Skill이 소비하지 않는다.
SOURCE_TYPES: tuple[str, ...] = ()

IMPLEMENTED = False


def run_authentication_analysis(
    events: Iterable[NormalizedEvent],
    *,
    dataset: str | None = None,
    host: str | None = None,
    service: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    source_types: Iterable[str] | None = None,
) -> list[Finding]:
    """항상 빈 리스트를 반환한다(연결된 detector 없음).

    다른 Skill과 같은 signature를 유지해 두어, 인증 detector가 구현되면 호출부를 바꾸지
    않고 이 함수 안만 채우면 되게 했다. 입력 이벤트를 순회하지도 않는다 - 할 일이 없다.
    """
    return []
