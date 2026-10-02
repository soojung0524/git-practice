"""분석 Window 기준 상대시간 정렬.

원본 timestamp를 유지한 채 T+0 기준 상대초를 함께 보존한다. 여러 dataset을 하나의
scenario로 묶을 때만 scenario_id를 명시하며, scenario mode에서만 dataset 간 correlation을
허용한다. Ground Truth는 사용하지 않는다.

의존 방향: scenario -> src.models
"""

from .definitions import (
    ALIGNED_SOURCE_SCENARIO_ID,
    ALIGNED_SOURCE_WINDOWS,
    aligned_source_scenario,
    make_analysis_scenario,
    make_scenario,
)
from .finding_projection import (
    ON_MISSING_ERROR,
    ON_MISSING_SKIP,
    MissingDatasetWindowError,
    NaiveDatetimeError,
    project_findings,
)
from .models import (
    ScenarioDatasetWindow,
    ScenarioDefinition,
    ScenarioFinding,
    ScenarioProjection,
)
from .alignment import (
    MODE_REAL,
    MODE_SCENARIO,
    RELATIVE_SECONDS_KEY,
    SCENARIO_ID_KEY,
    WINDOW_START_KEY,
    AlignmentError,
    AnalysisWindow,
    align_event,
    align_events,
    correlation_boundary_key,
    get_relative_seconds,
    get_scenario_id,
    is_aligned,
    long_span_basis_seconds,
    utc,
)

__all__ = [
    # Event 상대시간 정렬
    "AnalysisWindow",
    "AlignmentError",
    "align_event",
    "align_events",
    "get_relative_seconds",
    "get_scenario_id",
    "is_aligned",
    "correlation_boundary_key",
    "long_span_basis_seconds",
    "utc",
    "RELATIVE_SECONDS_KEY",
    "WINDOW_START_KEY",
    "SCENARIO_ID_KEY",
    "MODE_REAL",
    "MODE_SCENARIO",
    # Finding projection 모델
    "ScenarioDatasetWindow",
    "ScenarioDefinition",
    "ScenarioFinding",
    "ScenarioProjection",
    # projection
    "project_findings",
    "MissingDatasetWindowError",
    "NaiveDatetimeError",
    "ON_MISSING_ERROR",
    "ON_MISSING_SKIP",
    # 실제 설정값
    "ALIGNED_SOURCE_SCENARIO_ID",
    "ALIGNED_SOURCE_WINDOWS",
    "aligned_source_scenario",
    "make_scenario",
    "make_analysis_scenario",
]
