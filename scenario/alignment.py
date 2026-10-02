"""분석 Window 기준 상대시간(relative seconds)을 이벤트에 붙인다.

=== 규칙 ===

1. 원본 timestamp는 수정하지 않는다. NormalizedEvent.timestamp는 그대로 둔다.
2. T+0 = 사용자가 지정한 분석 Window 시작(AnalysisWindow.window_start).
3. 상대시간은 초 단위(float)로 저장한다.
4. 원본시간과 상대시간을 모두 보존한다. 상대시간은 extra에 넣어 NormalizedEvent
   모델 자체를 바꾸지 않는다(기존 Parser/Skill/Agent가 그대로 동작한다).
5. 여러 dataset을 묶을 때는 반드시 명시적인 scenario_id를 쓴다.
6. Scenario mode(scenario_id 있음)에서만 dataset 간 correlation을 허용한다.
7. Real mode(scenario_id 없음)에서는 기존 dataset boundary를 그대로 유지한다.
8. Correlation의 300초 window는 scenario mode에서도 relative seconds 기준 300초를
   그대로 쓸 수 있다(단위가 초로 같기 때문이다).
9. long-span 판정의 분모는 real mode에서는 관측된 Finding 전체 폭, scenario mode에서는
   선택된 Window 길이다 - long_span_basis_seconds() 참고.
10. Ground Truth의 timestamp는 이 정렬 과정에 사용하지 않는다. 이 모듈은 evaluation을
    import하지 않으며 Ground Truth를 읽지 않는다.

=== 왜 extra에 넣는가 ===

NormalizedEvent는 관측 사실만 담는 모델이고, 지금까지 모든 단계에서 수정하지 않는다는
전제로 Parser/Skill/Agent/Orchestrator가 쌓여 있다. 상대시간은 "분석 Window를 어떻게
잡았는가"에 따라 달라지는 파생값이므로, 원본 필드를 건드리지 않고 extra에 보존하는 것이
기존 구조와 일관된다. 기존 코드는 extra의 새 키를 무시하므로 영향이 없다.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone

from src.models import NormalizedEvent

# extra에 쓰는 키 이름. 코드 여러 곳에 문자열을 흩지 않기 위해 상수로 둔다.
RELATIVE_SECONDS_KEY = "relative_seconds"
WINDOW_START_KEY = "window_start"
SCENARIO_ID_KEY = "scenario_id"

MODE_REAL = "real"
MODE_SCENARIO = "scenario"


class AlignmentError(ValueError):
    """정렬 설정이 잘못됐다."""


@dataclass(frozen=True)
class AnalysisWindow:
    """분석 Window. window_start가 T+0이다.

    scenario_id가 있으면 scenario mode다 - 여러 dataset을 같은 T+0에 맞춰 묶는 경우이며,
    이때만 dataset 간 correlation이 허용된다. scenario_id가 None이면 real mode이고
    기존 dataset boundary를 유지한다.

    window_end는 선택이지만, scenario mode에서 long-span 판정 분모로 쓰이므로 scenario
    mode에서는 지정할 것을 권한다.
    """

    window_start: datetime
    window_end: datetime | None = None
    scenario_id: str | None = None

    def __post_init__(self) -> None:
        if self.window_start.tzinfo is None:
            raise AlignmentError("window_start에는 timezone이 있어야 한다(UTC 기준으로 맞춘다)")
        if self.window_end is not None:
            if self.window_end.tzinfo is None:
                raise AlignmentError("window_end에는 timezone이 있어야 한다")
            if self.window_end < self.window_start:
                raise AlignmentError("window_end가 window_start보다 이르다")
        if self.scenario_id is not None and not self.scenario_id.strip():
            raise AlignmentError("scenario_id가 빈 문자열이다. 묶지 않으려면 None을 쓴다")

    @property
    def mode(self) -> str:
        return MODE_SCENARIO if self.scenario_id else MODE_REAL

    @property
    def duration_seconds(self) -> float | None:
        if self.window_end is None:
            return None
        return (self.window_end - self.window_start).total_seconds()

    def relative_seconds(self, moment: datetime | None) -> float | None:
        """T+0 기준 상대초. timestamp가 없는 이벤트는 None을 돌려준다(지어내지 않는다)."""
        if moment is None:
            return None
        return (moment - self.window_start).total_seconds()


def align_event(event: NormalizedEvent, window: AnalysisWindow) -> NormalizedEvent:
    """이벤트 하나에 상대시간을 붙인 새 이벤트를 만든다.

    원본 event를 변경하지 않고, timestamp/dataset 등 기존 필드를 그대로 복사한다.
    extra만 새 dict로 만들어 상대시간 정보를 추가한다.
    """
    extra = dict(event.extra)
    extra[RELATIVE_SECONDS_KEY] = window.relative_seconds(event.timestamp)
    extra[WINDOW_START_KEY] = window.window_start.isoformat()
    if window.scenario_id is not None:
        extra[SCENARIO_ID_KEY] = window.scenario_id

    return NormalizedEvent(
        event_id=event.event_id,
        source_type=event.source_type,
        host=event.host,
        source_path=event.source_path,
        line_number=event.line_number,
        timestamp=event.timestamp,  # 원본 그대로
        raw=event.raw,
        dataset=event.dataset,
        process=event.process,
        pid=event.pid,
        user=event.user,
        src_ip=event.src_ip,
        dst_ip=event.dst_ip,
        event_type=event.event_type,
        message=event.message,
        extra=extra,
    )


def align_events(
    events: Iterable[NormalizedEvent], window: AnalysisWindow
) -> Iterator[NormalizedEvent]:
    """이벤트 스트림에 상대시간을 붙인다.

    전체를 list로 모으지 않고 흘려보낸다(GAIA는 1천만 건 이상이다).
    """
    for event in events:
        yield align_event(event, window)


# ---------------------------------------------------------------------------
# 읽기 helper
# ---------------------------------------------------------------------------


def get_relative_seconds(event: NormalizedEvent) -> float | None:
    """정렬된 이벤트의 상대초. 정렬되지 않은 이벤트면 None."""
    return event.extra.get(RELATIVE_SECONDS_KEY)


def get_scenario_id(event: NormalizedEvent) -> str | None:
    return event.extra.get(SCENARIO_ID_KEY)


def is_aligned(event: NormalizedEvent) -> bool:
    return RELATIVE_SECONDS_KEY in event.extra


def correlation_boundary_key(event: NormalizedEvent) -> str:
    """correlation에서 "같은 묶음인가"를 판단할 때 쓸 경계 키.

    - scenario mode(scenario_id 있음): scenario_id를 돌려준다. 서로 다른 dataset의
      이벤트라도 같은 scenario_id면 같은 경계 안이라 correlation이 허용된다.
    - real mode: dataset을 돌려준다. 기존 dataset boundary가 그대로 유지된다.
    """
    scenario_id = get_scenario_id(event)
    return scenario_id if scenario_id else event.dataset


def long_span_basis_seconds(
    window: AnalysisWindow | None, observed_span_seconds: float
) -> float:
    """long-span 판정에 쓸 분모(초)를 정한다.

    scenario mode에서는 "선택된 Window 길이"를 쓴다. 관측된 Finding 폭을 쓰면 묶은
    dataset 구성에 따라 분모가 흔들려서, 같은 Finding이 어떤 때는 long-span이고 어떤
    때는 아니게 된다.

    real mode이거나 window_end가 없으면 관측된 폭을 쓴다(기존 동작 유지).
    """
    if window is not None and window.mode == MODE_SCENARIO:
        duration = window.duration_seconds
        if duration and duration > 0:
            return duration
    return observed_span_seconds


def utc(year: int, month: int, day: int, hour: int = 0, minute: int = 0, second: int = 0) -> datetime:
    """UTC datetime을 짧게 만드는 helper(스크립트/테스트에서 쓴다)."""
    return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
