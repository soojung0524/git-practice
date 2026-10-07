"""Security Guidance 결과 모델.

근거 문서는 AWS Security Incident Response User Guide다. 따라서 결과를 법적·컴플라이언스
"규정"으로 표현하지 않는다. 문서가 실제로 명시한 전제조건은 기존 rag_agent의
SYSTEM_PROMPT가 이미 그대로 표현하도록 지시하고 있어, 이 계층에서 가공하지 않는다.

RAG 응답은 요약하거나 재작성하지 않는다. [Page N] 인용도 원문 그대로 보존한다.

이 모듈은 rag_agent / rag_tool / langchain / supabase를 import하지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GuidanceResponse:
    """provider 한 번 호출의 결과.

    provider 경계의 반환형이다. 어떤 RAG 구현을 쓰든 이 형태로만 돌려준다.
    """

    response: str
    provider_name: str
    model: str | None = None


@dataclass(frozen=True)
class IncidentSecurityGuidance:
    """focused incident 하나에 대한 guidance."""

    incident_id: str
    # 생성한 질문 원문. deterministic하게 만들어지므로 재현·검증할 수 있다.
    question: str
    # RAG 응답 원문. 요약하거나 재작성하지 않는다.
    response: str
    provider_name: str
    model: str | None = None


@dataclass(frozen=True)
class SecurityGuidanceResult:
    """한 번의 조사에서 만든 guidance 전체.

    focused incident가 여러 개면 incident마다 독립적인 질문 1개를 쓴다. 한 질문에 여러
    incident를 섞지 않는다.
    """

    focused_incident_ids: tuple[str, ...]
    guidance: tuple[IncidentSecurityGuidance, ...]
    failed_incident_ids: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not self.guidance

    @property
    def has_failures(self) -> bool:
        return bool(self.failed_incident_ids)

    def guidance_for(self, incident_id: str) -> IncidentSecurityGuidance | None:
        for item in self.guidance:
            if item.incident_id == incident_id:
                return item
        return None
