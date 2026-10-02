"""Server Agent - server_analysis Skill만 사용한다.

새로운 resource detector를 추가하지 않는다. 지원 metric 목록과 severity 규칙은
src/skills/gaia_metric_anomaly.py의 것을 그대로 따른다.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from agent_skills.server_analysis.scripts import run_server_analysis as skill
from agents.base import AgentResult, CountingIterator
from src.models import NormalizedEvent


class ServerAgent:
    """CPU / memory / filesystem 등 resource metric의 이상 구간을 분석한다.

    분석 범위와 제약은 agent_skills/server_analysis/SKILLS.md를 따른다.
    """

    AGENT_NAME = "server_agent"
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
        counter = CountingIterator(events)
        findings = skill.run_server_analysis(
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
