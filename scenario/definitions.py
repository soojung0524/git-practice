"""실제 scenario / Window 설정값.

=== 두 가지를 같은 개념으로 취급하지 않는다 ===

1. **aligned source 기본 범위** (ALIGNED_SOURCE_*)
   output/aligned/*.pkl을 만들 때 쓴 Window다. "각 dataset의 전체 관측 구간 시작을
   T+0에 맞춘다"는 뜻일 뿐이고, 두 dataset에서 같은 상대초가 "같은 사건 시점"을
   뜻하지는 않는다. RM은 6일, GAIA는 62일로 길이도 다르다.
   용도: 상대시간을 보존한 source data 생성.

2. **incident 분석 Window** (make_analysis_scenario)
   실제로 dataset 간 사건을 비교할 때 쓰는, 분석자가 직접 고른 좁은 구간이다.
   "RM의 공격 구간 2시간"과 "GAIA의 장애 구간 2시간"을 각각 T+0에 맞춰 놓고 비교하는
   경우가 여기에 해당한다.
   용도: Evidence Correlation에서 dataset 간 비교.

1번을 그대로 correlation에 쓰면, 길이가 10배 다른 두 Window의 상대초를 같은 눈금으로
비교하는 셈이 된다. 그래서 2번을 만들 수 있는 구조를 분리해 둔다.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta

from .alignment import utc
from .models import ScenarioDatasetWindow, ScenarioDefinition

# ---------------------------------------------------------------------------
# 1. aligned source 기본 범위 - output/aligned/*.pkl과 일치하는 값
#    scripts/build_aligned_events.py에 넘긴 --window-start/--window-end와 같다.
# ---------------------------------------------------------------------------

ALIGNED_SOURCE_SCENARIO_ID = "scenario-001"

# dataset -> (window_start, window_end)
ALIGNED_SOURCE_WINDOWS: Mapping[str, tuple[datetime, datetime]] = {
    # russellmitchell 최초 이벤트가 2022-01-20이라 그 날 00:00을 T+0으로 잡았다.
    "russellmitchell": (utc(2022, 1, 20), utc(2022, 1, 26)),
    # GAIA는 2021-07-01 ~ 2021-08-31 관측이라 7/1 00:00을 T+0으로 잡았다.
    "gaia": (utc(2021, 7, 1), utc(2021, 9, 1)),
}


def aligned_source_scenario() -> ScenarioDefinition:
    """output/aligned/*.pkl을 만든 Window 그대로의 ScenarioDefinition.

    주의: 이것은 incident 분석 Window가 아니다. dataset 간 사건 비교에는
    make_analysis_scenario()로 좁은 Window를 따로 만들 것.
    """
    return make_scenario(ALIGNED_SOURCE_SCENARIO_ID, ALIGNED_SOURCE_WINDOWS)


# ---------------------------------------------------------------------------
# 2. incident 분석 Window
# ---------------------------------------------------------------------------


def make_scenario(
    scenario_id: str, windows: Mapping[str, tuple[datetime, datetime]]
) -> ScenarioDefinition:
    """dataset -> (start, end) 매핑으로 ScenarioDefinition을 만든다."""
    return ScenarioDefinition(
        scenario_id=scenario_id,
        windows=tuple(
            ScenarioDatasetWindow(dataset=dataset, window_start=start, window_end=end)
            for dataset, (start, end) in sorted(windows.items())
        ),
    )


def make_analysis_scenario(
    scenario_id: str,
    *,
    anchors: Mapping[str, datetime],
    duration: timedelta,
    lead: timedelta = timedelta(0),
) -> ScenarioDefinition:
    """dataset별 기준 시각(anchor)을 T+0에 맞춘 좁은 분석 Window를 만든다.

    anchors
        dataset -> 그 dataset에서 비교 기준으로 삼을 시각(예: 공격 시작, 장애 시작).
        분석자가 직접 고른다 - Ground Truth에서 가져오지 않는다.
    duration
        Window 길이. 모든 dataset에 같은 길이를 적용하므로 상대초가 같은 눈금에 놓인다.
    lead
        anchor 이전을 얼마나 포함할지. T+0 = anchor - lead가 된다.

    모든 dataset이 같은 Window 길이를 갖는다는 점이 aligned source 범위와의 핵심 차이다.
    """
    if duration <= timedelta(0):
        raise ValueError("duration은 0보다 커야 한다")
    if lead < timedelta(0):
        raise ValueError("lead는 음수일 수 없다")

    windows = {
        dataset: (anchor - lead, anchor - lead + duration)
        for dataset, anchor in anchors.items()
    }
    return make_scenario(scenario_id, windows)
