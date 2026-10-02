"""Authentication Agent - 현재 연결된 detector가 없다.

구조만 구현하고 항상 빈 Finding 리스트를 반환한다. 가짜 Finding을 만들지 않으며,
login/bruteforce/privilege detector를 새로 구현하지 않는다.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from agent_skills.authentication_analysis.scripts import (
    run_authentication_analysis as skill,
)
from agents.base import AgentResult, CountingIterator
from src.models import NormalizedEvent

_NOT_IMPLEMENTED_NOTE = (
    "인증 분석 detector가 아직 구현되지 않았다. 결과가 비어 있는 것은 "
    "인증 이상이 없다는 뜻이 아니라 분석을 수행하지 않았다는 뜻이다."
)


class AuthenticationAgent:
    """인증 이벤트 분석을 담당할 Agent (현재 미구현).

    분석 범위와 제약은 agent_skills/authentication_analysis/SKILLS.md를 따른다.
    syslog_auth / auditd / openvpn parser는 존재하지만 이를 분석하는 detector가 없어,
    입력이 있든 없든 status는 항상 "not_implemented"다.
    """

    AGENT_NAME = "authentication_agent"
    SKILL_NAME = skill.SKILL_NAME
    DETECTORS = skill.DETECTORS  # ()

    def run(
        self,
        events: Iterable[NormalizedEvent],
        *,
        dataset: str | None = None,
        host: str | None = None,
        service: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        source_types: Iterable[str] | None = None,
    ) -> AgentResult:
        """항상 not_implemented를 반환한다.

        Skill은 입력을 소비하지 않지만(할 일이 없다), 전달된 입력 item 수는 drain()으로
        정확히 기록한다. status는 입력 수와 무관하게 not_implemented다 - 입력이 0건이어서가
        아니라 분석 기능이 없어서 결과가 비어 있기 때문이다.
        """
        counter = CountingIterator(events)
        findings = skill.run_authentication_analysis(
            counter,
            dataset=dataset,
            host=host,
            service=service,
            start_time=start_time,
            end_time=end_time,
            source_types=source_types,
        )
        counter.drain()

        return AgentResult(
            agent_name=self.AGENT_NAME,
            status="not_implemented",
            findings=findings,
            input_item_count=counter.count,
            skills_used=(self.SKILL_NAME,),
            detectors_used=self.DETECTORS,
            notes=(_NOT_IMPLEMENTED_NOTE,),
        )
