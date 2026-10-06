"""Security Guidance provider 경계.

=== lazy import ===

이 모듈은 최상단에서 rag_agent / rag_tool / langchain / supabase를 import하지 않는다.
rag_tool은 import만 해도 .env를 읽고 SUPABASE_URL/KEY를 확인하고(없으면 ValueError)
Supabase 클라이언트와 OpenAIEmbeddings를 만든다. rag_agent는 추가로 ChatOpenAI와
agent를 즉시 생성한다.

따라서 RagSecurityGuidanceProvider는 생성자에서도 import하지 않고, generate()가
실제로 호출될 때만 import한다. provider를 주지 않으면 RAG 모듈 import가 한 번도
일어나지 않는다.

=== 실측 기반 응답 추출 ===

rag_agent는 langchain.agents.create_agent()의 반환값이며 실측 타입은
langgraph.graph.state.CompiledStateGraph다(Pregel, Runnable 상속).
  - input  schema keys : ["messages"]
  - output schema keys : ["messages", "structured_response"]
  - graph nodes        : ["__start__", "model", "tools", "__end__"]

따라서 호출은 invoke({"messages": [{"role": "user", "content": question}]})이고,
최종 답변은 result["messages"][-1].content다.

content가 str인지 content block 리스트인지는 모델 응답에 따라 달라질 수 있어 두 경우를
모두 처리하고, 그 외 구조는 UnexpectedRagResponseError로 드러낸다(조용히 빈 문자열을
돌려주지 않는다).
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from .models import GuidanceResponse

PROVIDER_NAME_RAG = "rag_agent"


class UnexpectedRagResponseError(RuntimeError):
    """rag_agent 반환 구조가 예상과 다르다.

    외부 시스템 응답 형태 문제이므로 programming error가 아니다 - orchestration의
    error policy에 따라 errors에 기록되고 workflow는 계속된다.
    """


@runtime_checkable
class SecurityGuidanceProvider(Protocol):
    """질문 하나를 받아 답을 돌려주는 경계.

    테스트에서는 이 Protocol만 만족하는 fake를 주입한다 - 실제 OpenAI/Supabase를
    호출하지 않고 검증할 수 있다.
    """

    def generate(self, question: str) -> GuidanceResponse: ...


def extract_response_text(result: Any) -> str:
    """rag_agent.invoke() 결과에서 최종 답변 문자열을 꺼낸다.

    실측한 output schema는 {"messages", "structured_response"}이고 최종 답변은
    messages의 마지막 항목에 있다.
    """
    if not isinstance(result, dict):
        raise UnexpectedRagResponseError(
            f"dict를 기대했는데 {type(result).__name__}를 받았다"
        )

    messages = result.get("messages")
    if not messages:
        raise UnexpectedRagResponseError(
            f"반환값에 messages가 없거나 비어 있다 (키: {sorted(result)})"
        )

    content = getattr(messages[-1], "content", None)
    if content is None and isinstance(messages[-1], dict):
        content = messages[-1].get("content")

    if isinstance(content, str):
        return content

    if isinstance(content, list):
        # content block 리스트인 경우 텍스트 블록만 이어 붙인다.
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict) and block.get("type") == "text":
                text = block.get("text")
                if isinstance(text, str):
                    parts.append(text)
        if parts:
            return "".join(parts)
        raise UnexpectedRagResponseError(
            "content 리스트에서 텍스트 블록을 찾지 못했다"
        )

    raise UnexpectedRagResponseError(
        f"content 타입을 처리할 수 없다: {type(content).__name__}"
    )


class RagSecurityGuidanceProvider:
    """기존 rag/rag_agent.py를 그대로 호출하는 provider.

    search_runbook을 재구현하지 않고, hybrid -> vector fallback도 중복 구현하지 않는다.
    둘 다 기존 rag_tool이 이미 처리한다.
    """

    def __init__(self) -> None:
        # 여기서 rag_agent를 import하지 않는다. provider 객체를 만들어 두기만 해도
        # Supabase/OpenAI 클라이언트가 생기면 안 된다.
        self.provider_name = PROVIDER_NAME_RAG

    def generate(self, question: str) -> GuidanceResponse:
        """호출 시점에만 rag_agent를 import해 질문을 넘긴다.

        필수 dependency가 없으면(langchain 미설치 등) ImportError가 그대로 올라간다 -
        숨기지 않는다. 설정 오류를 조용히 넘기면 "RAG를 켰는데 결과가 없다"가 된다.
        """
        from rag.rag_agent import rag_agent  # noqa: PLC0415 (의도적 lazy import)

        result = rag_agent.invoke(
            {"messages": [{"role": "user", "content": question}]}
        )
        text = extract_response_text(result)
        return GuidanceResponse(
            response=text,
            provider_name=self.provider_name,
            model=_resolve_model_name(result),
        )


def _resolve_model_name(result: Any) -> str | None:
    """응답이 알려 주는 실제 모델 이름. 없으면 None (지어내지 않는다)."""
    try:
        metadata = getattr(result["messages"][-1], "response_metadata", None)
        if isinstance(metadata, dict):
            name = metadata.get("model_name") or metadata.get("model")
            if isinstance(name, str):
                return name
    except Exception:
        return None
    return None
