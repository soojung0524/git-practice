"""Application Agent - application_analysis Skill만 사용한다.

새로운 detector를 구현하지 않고, Skill이 반환한 Finding을 그대로 사용한다.
threshold/severity 변경, Finding 재작성, root cause 판단, correlation, RAG 없음.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from agent_skills.application_analysis.scripts import run_application_analysis as skill
from agents.base import AgentResult, CountingIterator
from src.models import NormalizedEvent


class ApplicationAgent:
    """웹 요청 급증 / 스캐닝 패턴 / 애플리케이션 ERROR 증가 / 서비스 지연을 분석한다.

    분석 범위와 제약은 agent_skills/application_analysis/SKILLS.md를 따른다.
    """

    AGENT_NAME = "application_agent"
    SKILL_NAME = skill.SKILL_NAME
    DETECTORS = skill.DETECTORS

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
        """Skill을 호출하고 결과를 AgentResult에 담는다.

        범위 지정 인자는 Skill에 그대로 전달한다. 이것은 결과 필터가 아니라 분석 입력
        범위 지정이며, 범위를 좁히면 detector의 baseline도 그 범위에서 다시 계산된다
        (SKILLS.md 제약사항 참고).
        """
        counter = CountingIterator(events)
        findings = skill.run_application_analysis(
            counter,
            dataset=dataset,
            host=host,
            service=service,
            start_time=start_time,
            end_time=end_time,
            source_types=source_types,
        )
        counter.drain()

        if counter.count == 0:
            return AgentResult(
                agent_name=self.AGENT_NAME,
                status="no_input",
                findings=[],
                input_item_count=0,
                skills_used=(self.SKILL_NAME,),
                detectors_used=self.DETECTORS,
                notes=("입력 이벤트가 0건이라 분석을 수행하지 않았다.",),
            )

        return AgentResult(
            agent_name=self.AGENT_NAME,
            status="ok",
            findings=findings,
            input_item_count=counter.count,
            skills_used=(self.SKILL_NAME,),
            detectors_used=self.DETECTORS,
        )
