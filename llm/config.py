"""OpenAI 설정을 한 곳에서 관리한다.

모델 버전은 DEFAULT_MODEL 상수 하나로 관리한다. 바꾸고 싶으면 두 가지 방법이 있다.
  1. .env에 OPENAI_MODEL=... 을 넣는다 (코드 수정 없이 바꿀 수 있어 권장)
  2. 아래 DEFAULT_MODEL 값을 바꾼다

Agent마다 모델 이름을 따로 적지 않는다 - 모든 LLM 호출이 이 설정을 공유한다.

API 키는 .env의 OPENAI_API_KEY에서 읽는다. 키 값은 로그나 예외 메시지에 절대 넣지
않는다(레포지토리에 남거나 콘솔에 찍히면 그대로 유출이다).
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# 모델 버전을 관리하는 단일 지점
# ---------------------------------------------------------------------------
DEFAULT_MODEL = "gpt-4.1-mini"

# 분석 보고는 매번 같은 입력에 같은 결론이 나오는 편이 좋으므로 낮게 둔다.
DEFAULT_TEMPERATURE = 0.0
DEFAULT_MAX_OUTPUT_TOKENS = 1500
DEFAULT_TIMEOUT_SECONDS = 60.0

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_ENV_LOADED = False


def _ensure_env_loaded() -> None:
    """프로젝트 루트의 .env를 한 번만 읽는다. 이미 설정된 환경변수는 덮어쓰지 않는다."""
    global _ENV_LOADED
    if not _ENV_LOADED:
        load_dotenv(_PROJECT_ROOT / ".env", override=False)
        _ENV_LOADED = True


@dataclass(frozen=True)
class LLMConfig:
    """LLM 호출 설정. api_key가 None이면 호출하지 않고 건너뛴다."""

    model: str = DEFAULT_MODEL
    api_key: str | None = None
    temperature: float = DEFAULT_TEMPERATURE
    max_output_tokens: int = DEFAULT_MAX_OUTPUT_TOKENS
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS

    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)

    def __repr__(self) -> str:
        # api_key가 repr/로그에 찍히지 않게 막는다.
        return (
            f"LLMConfig(model={self.model!r}, api_key={'<set>' if self.api_key else None}, "
            f"temperature={self.temperature}, max_output_tokens={self.max_output_tokens})"
        )


def load_llm_config(
    *,
    model: str | None = None,
    temperature: float | None = None,
    max_output_tokens: int | None = None,
    timeout_seconds: float | None = None,
) -> LLMConfig:
    """.env와 환경변수에서 설정을 읽는다.

    우선순위: 함수 인자 > 환경변수(OPENAI_MODEL) > DEFAULT_MODEL
    """
    _ensure_env_loaded()
    api_key = os.environ.get("OPENAI_API_KEY") or None
    return LLMConfig(
        model=model or os.environ.get("OPENAI_MODEL") or DEFAULT_MODEL,
        api_key=api_key,
        temperature=DEFAULT_TEMPERATURE if temperature is None else temperature,
        max_output_tokens=(
            DEFAULT_MAX_OUTPUT_TOKENS if max_output_tokens is None else max_output_tokens
        ),
        timeout_seconds=(
            DEFAULT_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
        ),
    )


def is_configured() -> bool:
    """API 키가 준비돼 있는지. 키가 없으면 LLM 단계를 건너뛴다(실패로 처리하지 않는다)."""
    return load_llm_config().is_configured
