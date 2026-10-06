"""Evidence Correlation.

ScenarioProjection -> CorrelationEdge -> CorrelatedIncident
                                      -> EvidenceGraph / Timeline
                                      -> HypothesisCandidate / ImpactScope

새로운 anomaly를 탐지하지 않는다. 이미 만들어진 Finding 사이의 관계만 찾으며,
Finding을 수정하거나 severity를 바꾸거나 새 Finding을 만들지 않는다.

의존 방향: correlation -> scenario -> src.models
agents / agent_skills / orchestration / evaluation / Ground Truth / RAG를 쓰지 않는다.
"""

from .config import (
    GROUPING_IDENTITY_RELATIONS,
    LONG_SPAN_RATIO,
    NEAR_IN_TIME_SECONDS,
    RELATION_SAME_HOST,
    RELATION_SAME_SERVICE,
    RELATION_SHARED_ENTITY,
    RELATION_SHARED_EVIDENCE,
    RELATION_TEMPORAL_NEAR,
    RELATION_TEMPORAL_OVERLAP,
    RELATION_TEMPORAL_WEAK_LONG_SPAN,
    TEMPORAL_OVERLAPS,
    TEMPORAL_PRECEDES,
)
from .correlate import (
    HYPOTHESIS_RULES,
    build_edges,
    build_hypotheses,
    build_impact,
    build_timeline,
    correlate_scenario,
    is_long_span,
)
from .focus import (
    InconsistentCorrelationError,
    IncidentSelectionResult,
    InvestigationFocus,
    focus_on,
    select_incidents,
)
from .graph import build_evidence_graph, make_node_id
from .models import (
    CorrelatedIncident,
    CorrelationEdge,
    CorrelationResult,
    EvidenceGraph,
    GraphEdge,
    GraphNode,
    HypothesisCandidate,
    ImpactScope,
    TimelineEntry,
)

__all__ = [
    # 최상위
    "correlate_scenario",
    "CorrelationResult",
    # focus / selection
    "InvestigationFocus",
    "IncidentSelectionResult",
    "focus_on",
    "select_incidents",
    "InconsistentCorrelationError",
    # 모델
    "CorrelationEdge",
    "CorrelatedIncident",
    "TimelineEntry",
    "HypothesisCandidate",
    "ImpactScope",
    "GraphNode",
    "GraphEdge",
    "EvidenceGraph",
    # 구성 함수
    "build_edges",
    "build_timeline",
    "build_impact",
    "build_hypotheses",
    "build_evidence_graph",
    "make_node_id",
    "is_long_span",
    "HYPOTHESIS_RULES",
    # 상수
    "NEAR_IN_TIME_SECONDS",
    "LONG_SPAN_RATIO",
    "GROUPING_IDENTITY_RELATIONS",
    "RELATION_SAME_HOST",
    "RELATION_SAME_SERVICE",
    "RELATION_SHARED_ENTITY",
    "RELATION_SHARED_EVIDENCE",
    "RELATION_TEMPORAL_OVERLAP",
    "RELATION_TEMPORAL_NEAR",
    "RELATION_TEMPORAL_WEAK_LONG_SPAN",
    "TEMPORAL_OVERLAPS",
    "TEMPORAL_PRECEDES",
]
