"""Agent 계층 공통 실행 결과 모델.

Agent는 Skill을 호출하고 그 결과를 담기만 한다. Finding 모델은 변경하지 않으며,
AgentResult는 Finding을 담는 그릇일 뿐 새로운 분석 결과 모델이 아니다.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from typing import Literal, TypeVar

from src.models import Finding

AgentStatus = Literal[
    "ok",
    "no_input",
    "not_implemented",
    "partially_implemented",
]

_T = TypeVar("_T")


@dataclass(frozen=True)
class AgentResult:
    """Agent 한 번의 실행 결과.

    findings가 비어 있을 때 그것만 보고 "이상 없음"이라고 판단하면 안 된다. status를
    반드시 함께 봐야 한다 - 분석 기능이 아예 없어서(not_implemented) 비어 있는 경우와
    분석했지만 이상이 없어서(ok) 비어 있는 경우가 구분되기 때문이다.
    """

    agent_name: str
    status: AgentStatus
    # 기존 Finding 모델 그대로다. Agent가 어떤 필드도 수정하지 않는다.
    findings: list[Finding]
    # Agent에 전달된 입력 item의 수. Application/Server/Network/Authentication은
    # NormalizedEvent 수, Security는 Finding 수다.
    # Skill 내부의 source_type/dataset/time filtering을 통과한 이벤트 수가 아니다 -
    # 그 수는 Agent가 알 수 없고 추측하지도 않는다.
    input_item_count: int
    skills_used: tuple[str, ...]
    # 이 Agent에 연결된 detector 이름. Skill이 선언한 값을 그대로 인용한다.
    # "이번 실행에서 실제로 Finding을 만든 detector"가 아니라 "연결된 detector"다.
    detectors_used: tuple[str, ...]
    # 상태를 사람이 읽을 수 있게 설명하는 문장들(미구현 사유, 제약 등).
    notes: tuple[str, ...] = field(default_factory=tuple)


class CountingIterator(Iterator[_T]):
    """순회한 item 수를 세면서 그대로 흘려보내는 얇은 iterator.

    입력 전체를 list로 복사하지 않기 위한 것이다(GAIA는 1천만 건 이상이다).
    Skill에 이 iterator를 넘기면 Skill이 소비한 만큼 count가 올라간다.

    Skill이 입력을 끝까지 읽지 않는 경우(예: 쓸 source_type이 하나도 없어 즉시 반환,
    또는 입력을 아예 읽지 않는 authentication Skill)에도 "전달된 입력 item 수"를 정확히
    알아야 하므로, 호출자가 drain()으로 남은 item을 소진시킨다. 이미 끝까지 읽혔다면
    drain()은 아무 일도 하지 않는다. 어느 경우든 입력은 한 번만 순회된다.
    """

    def __init__(self, source: Iterable[_T]) -> None:
        self._iterator = iter(source)
        self.count = 0

    def __iter__(self) -> "CountingIterator[_T]":
        return self

    def __next__(self) -> _T:
        item = next(self._iterator)
        self.count += 1
        return item

    def drain(self) -> int:
        for _ in self._iterator:
            self.count += 1
        return self.count
