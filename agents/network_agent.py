"""Network Agent - network_analysis Skill만 사용한다.

전용 network detector는 아직 없다. find_metric_anomaly가 network metric에서 만든
Finding(category == "network")을 처리하는 범위까지만 담당한다.
DNS / VPN / firewall 분석 기능을 임의로 추가하지 않는다.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from agent_skills.network_analysis.scripts import run_network_analysis as skill
from agents.base import AgentResult, CountingIterator
from src.models import NormalizedEvent

_PARTIAL_NOTE = (
    "전용 network detector가 없다. find_metric_anomaly의 network metric 결과"
    "(category == network)만 처리한 결과이며, DNS/VPN/firewall 분석은 수행하지 않았다."
)


class NetworkAgent:
    """network metric의 이상 구간만 분석한다.

    분석 범위와 제약은 agent_skills/network_analysis/SKILLS.md를 따른다.
    입력이 있으면 status는 항상 "partially_implemented"다 - 결과가 비어 있어도
    "네트워크 이상 없음"으로 해석하면 안 되고, 전용 detector가 없다는 사실을 함께
    고려해야 한다.
    """

    AGENT_NAME = "network_agent"
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
        findings = skill.run_network_analysis(
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
                notes=("입력 이벤트가 0건이라 분석을 수행하지 않았다.", _PARTIAL_NOTE),
            )

        return AgentResult(
            agent_name=self.AGENT_NAME,
            status="partially_implemented",
            findings=findings,
            input_item_count=counter.count,
            skills_used=(self.SKILL_NAME,),
            detectors_used=self.DETECTORS,
            notes=(_PARTIAL_NOTE,),
        )
