"""OpenAI 호출을 감싸는 얇은 래퍼.

여기서 하는 일은 "메시지를 보내고 텍스트를 받는 것"뿐이다. 프롬프트 구성이나 결과
해석은 interpreter.py가 담당한다.

API 키는 이 모듈 밖으로 나가지 않는다. 예외 메시지에도 키를 넣지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass

from .config import LLMConfig, load_llm_config


class LLMNotConfiguredError(RuntimeError):
    """OPENAI_API_KEY가 없다. 호출자는 LLM 단계를 건너뛰어야 한다."""


@dataclass(frozen=True)
class LLMResponse:
    """LLM 한 번 호출의 결과."""

    text: str
    model: str
    # 실제로 응답을 만든 모델 이름(OpenAI가 별칭을 구체 버전으로 바꿔 돌려줄 수 있다).
    resolved_model: str
    prompt_tokens: int | None
    completion_tokens: int | None


class OpenAIClient:
    """OpenAI Chat Completions를 호출한다.

    테스트에서는 이 클래스 대신 complete(system, user) -> LLMResponse 를 만족하는
    아무 객체나 주입하면 된다(네트워크 호출 없이 검증하기 위해서다).
    """

    def __init__(self, config: LLMConfig | None = None) -> None:
        self.config = config or load_llm_config()
        if not self.config.is_configured:
            raise LLMNotConfiguredError(
                ".env에 OPENAI_API_KEY가 없다. LLM 해석 단계를 사용할 수 없다."
            )
        # import를 생성자 안에 두어, LLM을 쓰지 않는 실행 경로에서는 openai 패키지를
        # 불러오지 않게 한다.
        from openai import OpenAI

        self._client = OpenAI(
            api_key=self.config.api_key,
            timeout=self.config.timeout_seconds,
        )

    def complete(self, system: str, user: str) -> LLMResponse:
        response = self._client.chat.completions.create(
            model=self.config.model,
            temperature=self.config.temperature,
            max_completion_tokens=self.config.max_output_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        choice = response.choices[0]
        usage = response.usage
        return LLMResponse(
            text=(choice.message.content or "").strip(),
            model=self.config.model,
            resolved_model=getattr(response, "model", self.config.model),
            prompt_tokens=getattr(usage, "prompt_tokens", None) if usage else None,
            completion_tokens=getattr(usage, "completion_tokens", None) if usage else None,
        )
