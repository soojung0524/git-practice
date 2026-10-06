"""Focused Incident -> AWS 문서 근거 Security Guidance.

CorrelatedIncident (focused)
    -> build_security_guidance_question()   template 기반 순수 함수
    -> SecurityGuidanceProvider.generate()  경계
    -> SecurityGuidanceResult

기존 SecurityAgent(security category Finding selector)와 역할이 다르다. 둘을 합치지
않는다.

이 패키지는 rag_agent / rag_tool / langchain / supabase를 import하지 않는다.
실제 RAG 호출은 RagSecurityGuidanceProvider.generate() 안에서 lazy import로만 일어난다.

의존 방향: guidance -> correlation -> scenario -> src.models
"""

from .models import (
    GuidanceResponse,
    IncidentSecurityGuidance,
    SecurityGuidanceResult,
)
from .provider import (
    PROVIDER_NAME_RAG,
    RagSecurityGuidanceProvider,
    SecurityGuidanceProvider,
    UnexpectedRagResponseError,
    extract_response_text,
)
from .question import (
    DEFAULT_MAX_TIMELINE_ENTRIES,
    build_security_guidance_question,
)

__all__ = [
    "GuidanceResponse",
    "IncidentSecurityGuidance",
    "SecurityGuidanceResult",
    "SecurityGuidanceProvider",
    "RagSecurityGuidanceProvider",
    "UnexpectedRagResponseError",
    "extract_response_text",
    "PROVIDER_NAME_RAG",
    "build_security_guidance_question",
    "DEFAULT_MAX_TIMELINE_ENTRIES",
]
