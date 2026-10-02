"""Scenario Finding Projection 모델.

Finding을 수정하지 않고, scenario의 dataset window를 기준으로 한 상대시간 표현만
별도 모델로 만든다. 실제 scenario/window 설정값은 이 파일에 두지 않고
scenario/definitions.py에 둔다(모델과 설정을 섞지 않는다).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime

from src.models import Finding

from .alignment import AnalysisWindow


@dataclass(frozen=True)
class ScenarioDatasetWindow:
    """scenario 안에서 한 dataset이 차지하는 분석 Window. window_start가 T+0이다.

    window_end는 필수다. clip과 span_ratio가 둘 다 Window 길이를 요구하므로, 길이를
    모르는 Window는 이 계층에서 쓸 수 없다(AnalysisWindow에서는 optional이지만 여기서는
    아니다).
    """

    dataset: str
    window_start: datetime
    window_end: datetime

    def __post_init__(self) -> None:
        if not self.dataset.strip():
            raise ValueError("dataset 이름이 비어 있다")
        if self.window_start.tzinfo is None or self.window_end.tzinfo is None:
            raise ValueError(
                f"{self.dataset}: window_start/window_end에는 timezone이 있어야 한다"
            )
        if self.window_end <= self.window_start:
            raise ValueError(
                f"{self.dataset}: window_end가 window_start보다 뒤여야 한다 "
                "(길이 0 Window는 span_ratio를 정의할 수 없다)"
            )

    @property
    def window_length_seconds(self) -> float:
        return (self.window_end - self.window_start).total_seconds()

    def as_analysis_window(self, scenario_id: str | None = None) -> AnalysisWindow:
        return AnalysisWindow(
            window_start=self.window_start,
            window_end=self.window_end,
            scenario_id=scenario_id,
        )

    def relative_seconds(self, moment: datetime) -> float:
        """T+0 기준 상대초.

        Event쪽 상대시간(extra["relative_seconds"])과 같은 코드 경로를 쓰기 위해
        AnalysisWindow.relative_seconds()에 위임한다 - 두 정의가 갈라질 수 없게 한다.
        """
        value = self.as_analysis_window().relative_seconds(moment)
        assert value is not None  # moment가 None이 아니므로 항상 값이 있다
        return value

    def contains_interval(self, start: datetime, end: datetime) -> bool:
        """구간이 Window와 조금이라도 겹치는지. 경계는 포함으로 본다."""
        return not (end < self.window_start or start > self.window_end)


@dataclass(frozen=True)
class ScenarioDefinition:
    """하나의 scenario와, 그 안에서 각 dataset이 쓰는 Window들."""

    scenario_id: str
    windows: tuple[ScenarioDatasetWindow, ...]

    def __post_init__(self) -> None:
        if not self.scenario_id.strip():
            raise ValueError("scenario_id가 비어 있다. 묶지 않으려면 real mode를 쓴다")
        datasets = [window.dataset for window in self.windows]
        duplicates = sorted({name for name in datasets if datasets.count(name) > 1})
        if duplicates:
            raise ValueError(
                f"같은 dataset의 Window가 중복됐다: {duplicates} "
                "(어느 Window를 적용할지 모호해진다)"
            )

    @property
    def datasets(self) -> tuple[str, ...]:
        return tuple(sorted(window.dataset for window in self.windows))

    def window_for(self, dataset: str) -> ScenarioDatasetWindow | None:
        """해당 dataset의 Window. 없으면 None (추측해서 만들지 않는다)."""
        for window in self.windows:
            if window.dataset == dataset:
                return window
        return None


@dataclass(frozen=True)
class ScenarioFinding:
    """Finding 하나를 scenario 시간축에 올린 표현.

    원본 Finding을 참조로 들고 있을 뿐이며 수정하지 않는다. Finding은 frozen이 아니지만
    이 계층은 어떤 필드도 건드리지 않는다(테스트로 고정한다).

    relative_start/end_seconds는 clip 전 원본 interval 기준이고,
    relative_effective_start/end_seconds는 Window로 clip한 구간 기준이다.
    correlation은 effective 쪽을 쓰고, 원본 쪽은 "원래 언제였는가"를 남기기 위한 값이다.
    """

    scenario_id: str
    finding: Finding

    relative_start_seconds: float
    relative_end_seconds: float

    effective_start_time: datetime
    effective_end_time: datetime
    relative_effective_start_seconds: float
    relative_effective_end_seconds: float
    was_clipped: bool

    window_start: datetime
    window_end: datetime
    window_length_seconds: float

    # --- 원본 Finding에 위임하는 property (값을 복사하지 않는다) ---

    @property
    def finding_id(self) -> str:
        return self.finding.finding_id

    @property
    def dataset(self) -> str:
        return self.finding.dataset

    @property
    def original_start_time(self) -> datetime:
        return self.finding.start_time

    @property
    def original_end_time(self) -> datetime:
        return self.finding.end_time

    @property
    def original_span_seconds(self) -> float:
        return (self.finding.end_time - self.finding.start_time).total_seconds()

    @property
    def effective_span_seconds(self) -> float:
        return (self.effective_end_time - self.effective_start_time).total_seconds()

    @property
    def span_ratio(self) -> float:
        """effective span / Window 길이.

        scenario mode의 long-span 판정 분모는 관측된 Finding 전체 폭이 아니라 선택된
        Window 길이다 - 묶은 dataset 구성에 따라 분모가 흔들리지 않게 하기 위해서다
        (alignment.long_span_basis_seconds()와 같은 기준).
        """
        return self.effective_span_seconds / self.window_length_seconds

    def sort_key(self) -> tuple[float, float, str]:
        return (self.relative_start_seconds, self.relative_end_seconds, self.finding_id)


@dataclass(frozen=True)
class ScenarioProjection:
    """projection 결과.

    projection은 Finding을 버릴 수 있다(Window 밖, Window 누락). 몇 건을 왜 버렸는지
    함께 돌려주지 않으면 correlation 입력이 조용히 줄어든 것을 알 수 없으므로, 버린
    목록을 결과에 남긴다.
    """

    scenario_id: str
    findings: tuple[ScenarioFinding, ...]
    excluded_out_of_window: tuple[str, ...]
    skipped_missing_window: tuple[str, ...]
    clipped_count: int
    notes: tuple[str, ...] = ()

    def __iter__(self) -> Iterator[ScenarioFinding]:
        return iter(self.findings)

    def __len__(self) -> int:
        return len(self.findings)

    @property
    def finding_ids(self) -> tuple[str, ...]:
        return tuple(item.finding_id for item in self.findings)
