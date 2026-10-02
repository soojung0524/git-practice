"""LLM(OpenAI) 해석 계층.

Finding -> InterpretationAgent -> 자연어 분석

이 계층은 탐지를 하지 않는다. 통계 detector가 만든 Finding을 읽어 해석할 뿐이며,
Finding을 수정하거나 severity를 바꾸거나 새 Finding을 만들지 않는다.

모델 버전은 llm/config.py의 DEFAULT_MODEL 한 곳에서 관리한다(.env의 OPENAI_MODEL로
덮어쓸 수 있다). Agent마다 모델 이름을 따로 적지 않는다.

의존 방향: orchestration -> llm -> src/models
"""

from .client import LLMNotConfiguredError, LLMResponse, OpenAIClient
from .config import (
    DEFAULT_MAX_OUTPUT_TOKENS,
    DEFAULT_MODEL,
    DEFAULT_TEMPERATURE,
    LLMConfig,
    is_configured,
    load_llm_config,
)
from .interpreter import (
    DEFAULT_MAX_FINDINGS_IN_PROMPT,
    SYSTEM_PROMPT,
    FindingInterpretation,
    InterpretationAgent,
    agent_statuses_from_results,
    build_digest,
    interpret_findings,
)

__all__ = [
    "DEFAULT_MODEL",
    "DEFAULT_TEMPERATURE",
    "DEFAULT_MAX_OUTPUT_TOKENS",
    "LLMConfig",
    "load_llm_config",
    "is_configured",
    "OpenAIClient",
    "LLMResponse",
    "LLMNotConfiguredError",
    "InterpretationAgent",
    "FindingInterpretation",
    "interpret_findings",
    "build_digest",
    "agent_statuses_from_results",
    "SYSTEM_PROMPT",
    "DEFAULT_MAX_FINDINGS_IN_PROMPT",
]
