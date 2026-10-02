"""Analysis Skill이 만들어내는 결과물인 Finding과, 그 근거를 가리키는 EvidenceReference.

NormalizedEvent는 관측 사실만 담고 판단을 하지 않는다(정규화 단계 원칙). Finding은 그
반대로 "무엇이 이상/주목할 만한가"에 대한 판단 결과를 담는 별도의 모델이며, Analysis
Skill(순수 함수)만 만들어낸다. 아직 Correlation/Root Cause 단계가 없으므로 Finding은
서로 다른 Skill의 결과를 엮어 원인을 추정하지 않는다 — 그래서 root_cause 필드가 없다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

# severity는 4단계로 고정한다. 각 Skill이 임의로 새 단계를 만들지 않도록 명시적으로 검증한다.
SEVERITY_LEVELS = ("low", "medium", "high", "critical")

# 아직 실제로 쓰는 Skill이 나온 값만 담는다. 필요해지기 전에 미리 늘리지 않는다.
CATEGORIES = (
    "security",
    "availability",
    "performance",
    "error",
    "authentication",
    "resource",
    "network",
)


@dataclass(frozen=True)
class EvidenceReference:
    """Finding 하나의 근거가 된 NormalizedEvent를 원본까지 추적하기 위한 참조.

    NormalizedEvent를 통째로 복사하지 않고, 원본을 다시 찾아갈 수 있는 최소 정보만 담는다.
    """

    source_type: str
    source_file: str  # NormalizedEvent.source_path
    line_number: int  # russellmitchell: 텍스트 줄 번호 / GAIA: 헤더 제외 CSV 데이터 행 번호
    timestamp: datetime | None
    event_id: str  # NormalizedEvent.event_id (source_file:line_number 재조합 없이 바로 참조)


@dataclass
class Finding:
    finding_id: str
    dataset: str
    category: str
    finding_type: str
    start_time: datetime
    end_time: datetime
    host: str | None
    service: str | None
    severity: str
    summary: str
    # 이 탐지에 실제로 쓰인 정량적 값만 담는다(예: window_seconds, observed_count,
    # baseline, ratio). Skill마다 무엇을 담을지 다르므로 자유 형식으로 둔다.
    metrics: dict[str, Any] = field(default_factory=dict)
    # 대표 evidence만 제한적으로 담는다. 전체 매칭 건수는 metrics["evidence_count"]에 둔다.
    evidence: list[EvidenceReference] = field(default_factory=list)
    # 실제로 관측된 값만 담는다. 관측되지 않은 entity 종류는 키 자체를 넣지 않는다.
    entities: dict[str, list[str]] = field(default_factory=dict)
    detector: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_LEVELS:
            raise ValueError(f"unknown severity: {self.severity!r} (expected one of {SEVERITY_LEVELS})")
        if self.category not in CATEGORIES:
            raise ValueError(f"unknown category: {self.category!r} (expected one of {CATEGORIES})")


def make_finding_id(*, detector: str, dataset: str, group_key: str, start_time: datetime) -> str:
    """Finding을 결정적으로(재실행해도 같은 값) 식별하는 문자열을 만든다.

    같은 입력(detector, dataset, group_key, start_time)이면 항상 같은 finding_id가
    나와야 재실행 시 중복 없이 비교/재현할 수 있다(작업 지시의 "deterministic 결과").
    """
    safe_group = str(group_key).replace(":", "_").replace(" ", "_")
    return f"{dataset}:{detector}:{safe_group}:{start_time.isoformat()}"
