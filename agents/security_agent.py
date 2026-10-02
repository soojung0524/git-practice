"""Security Agent - security_analysis Skill만 사용한다.

이미 만들어진 Finding 중 category == "security"인 것을 선별하는 범위만 구현한다.
위협 등급 재계산, 공격 단계 추정, 새로운 Security Finding 생성, RAG 호출,
Supabase/VectorDB 검색, AWS 문서 검색, RAG 답변 생성은 하지 않는다.

향후 팀원이 만든 RAG Agent가 연결될 수 있도록 결과를 Finding 형태로 유지한다
(AgentResult.findings). 이번 단계에서 실제 연결은 하지 않는다.
"""

from __future__ import annotations

from collections.abc import Iterable

from agent_skills.security_analysis.scripts import run_security_analysis as skill
from agents.base import AgentResult, CountingIterator
from src.models import Finding

_SELECTOR_NOTE = (
    "현재 Security Agent는 selector다. 이미 생성된 Finding 중 category == security인 "
    "것을 그대로 선별하며, 새로운 보안 판단을 하지 않는다."
)


class SecurityAgent:
    """이미 생성된 Finding 중 보안 관련 Finding만 선별한다.

    다른 Agent와 달리 NormalizedEvent가 아니라 Finding을 입력으로 받는다. 범위 지정
    인자도 없다 - 이벤트를 읽지 않기 때문이다.

    분석 범위와 제약은 agent_skills/security_analysis/SKILLS.md를 따른다.
    """

    AGENT_NAME = "security_agent"
    SKILL_NAME = skill.SKILL_NAME
    DETECTORS = skill.DETECTORS  # ()

    def run(self, findings: Iterable[Finding]) -> AgentResult:
        """입력 Finding을 한 번만 순회하며 보안 Finding을 선별한다.

        input_item_count는 입력으로 받은 Finding의 수다(선별된 수가 아니다).
        선별된 Finding은 원본 객체를 그대로 담으며, 어떤 필드도 수정하지 않는다.
        """
        counter = CountingIterator(findings)
        selected = skill.run_security_analysis(counter)
        counter.drain()

        if counter.count == 0:
            return AgentResult(
                agent_name=self.AGENT_NAME,
                status="no_input",
                findings=[],
                input_item_count=0,
                skills_used=(self.SKILL_NAME,),
                detectors_used=self.DETECTORS,
                notes=("입력 Finding이 0건이라 선별할 대상이 없었다.", _SELECTOR_NOTE),
            )

        return AgentResult(
            agent_name=self.AGENT_NAME,
            status="ok",
            findings=selected,
            input_item_count=counter.count,
            skills_used=(self.SKILL_NAME,),
            detectors_used=self.DETECTORS,
            notes=(_SELECTOR_NOTE,),
        )
