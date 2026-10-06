"""Evidence Correlation 결과 모델.

Finding / ScenarioFinding을 모델 안에 복사 저장하지 않는다. finding_id 참조를 쓰고,
표시용 값이 꼭 필요한 TimelineEntry만 예외적으로 복사한다(읽기용 산출물이라 매번
Finding을 되찾게 하면 사용성이 크게 떨어진다).

숫자 strength/confidence 필드를 두지 않는다. 학습되지 않은 가중치는 근거처럼 보이지만
근거가 아니다. 대신 어떤 rule이 왜 성립했는지를 그대로 저장한다.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class CorrelationEdge:
    """ScenarioFinding 두 개 사이에 성립한 관계 기록.

    is_grouping_relation=False인 edge도 버리지 않고 보존한다 - "관계는 있지만 하나의
    incident로 묶을 근거는 못 된다"는 사실 자체가 정보다.
    """

    edge_id: str
    scenario_id: str
    source_finding_id: str  # canonical 순서상 앞
    target_finding_id: str

    relation_types: tuple[str, ...]

    temporal_relation: str | None  # "overlaps" | "precedes" | None
    overlap_seconds: float
    time_gap_seconds: float | None

    shared_entities: dict[str, tuple[str, ...]]
    shared_evidence_event_ids: tuple[str, ...]

    source_was_clipped: bool
    target_was_clipped: bool
    weak_temporal: bool

    is_grouping_relation: bool
    notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class TimelineEntry:
    """timeline 한 줄. 표시 시간은 scenario 상대초, 추적용으로 원본 절대시각도 담는다."""

    finding_id: str
    dataset: str
    # relative_effective_* 값이다(correlation이 쓰는 시간과 같다).
    relative_start_seconds: float
    relative_end_seconds: float
    # 사람이 추적할 수 있도록 남기는 원본 시각. correlation 계산에는 쓰지 않는다.
    original_start_time: datetime
    original_end_time: datetime
    category: str
    finding_type: str
    severity: str
    host: str | None
    service: str | None
    summary: str
    was_clipped: bool
    is_long_span: bool


@dataclass(frozen=True)
class HypothesisCandidate:
    """rule 기반 가설 후보. 최종 Root Cause가 아니다.

    statement는 template으로만 만들며 인과를 확정하지 않는다. supporting_* 는 비어 있을
    수 없다 - 근거 없는 가설을 만들지 않는다.
    """

    hypothesis_id: str
    rule_name: str
    statement: str
    supporting_finding_ids: tuple[str, ...]
    supporting_edge_ids: tuple[str, ...]
    shared_identity: dict[str, tuple[str, ...]]
    caveats: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.supporting_finding_ids:
            raise ValueError(f"{self.rule_name}: supporting_finding_ids가 비어 있다")
        if not self.supporting_edge_ids:
            raise ValueError(f"{self.rule_name}: supporting_edge_ids가 비어 있다")


@dataclass(frozen=True)
class ImpactScope:
    """입력 ScenarioFinding에 실제로 등장한 값만 집계한다.

    severity를 새로 계산하지 않고 분포만 센다. 관측되지 않은 자산을 추측해 넣지 않는다.
    """

    affected_hosts: tuple[str, ...]
    affected_services: tuple[str, ...]
    affected_ips: tuple[str, ...]
    affected_users: tuple[str, ...]
    datasets: tuple[str, ...]
    categories: tuple[str, ...]
    finding_type_counts: dict[str, int]
    severity_counts: dict[str, int]
    relative_start_seconds: float
    relative_end_seconds: float


@dataclass(frozen=True)
class CorrelatedIncident:
    """grouping edge로 연결된 ScenarioFinding 묶음.

    연결되지 않은 Finding도 버리지 않고 single-Finding incident가 된다.
    """

    incident_id: str
    scenario_id: str
    datasets: tuple[str, ...]  # provenance. scenario mode에서는 2개 이상일 수 있다
    finding_ids: tuple[str, ...]
    edge_ids: tuple[str, ...]
    relative_start_seconds: float
    relative_end_seconds: float
    timeline: tuple[TimelineEntry, ...]
    hypotheses: tuple[HypothesisCandidate, ...]
    impact: ImpactScope
    grouping_basis: tuple[str, ...]
    long_span_finding_ids: tuple[str, ...]

    @property
    def finding_count(self) -> int:
        return len(self.finding_ids)

    @property
    def is_single_finding(self) -> bool:
        return len(self.finding_ids) == 1


@dataclass(frozen=True)
class GraphNode:
    """Evidence Graph 노드.

    entity 노드는 dataset으로 namespace하지 않는다. dataset별로 나누면 두 dataset이 같은
    entity를 공유해도 그래프에서 서로 다른 노드가 되어, scenario mode의 목적(dataset 간
    연결 관찰)이 그래프에서 사라진다. provenance는 datasets 필드로 보존한다.

    주의(실험적 규칙): "같은 entity type + 같은 문자열 value = scenario 안의 같은 논리적
    entity"로 취급한다. 이것은 현재 단계의 실험적 identity matching 규칙이다. 서로 다른
    환경에서 수집된 dataset이 우연히 같은 문자열(예: 같은 사설 IP, 같은 서비스 이름)을
    쓰는 경우 서로 무관한 자산이 한 노드로 합쳐질 수 있다. 실제 자산 식별자(asset
    inventory)로 검증된 매칭이 아니다.
    """

    node_id: str
    node_type: str
    label: str
    datasets: tuple[str, ...]


@dataclass(frozen=True)
class GraphEdge:
    source_node_id: str
    target_node_id: str
    edge_type: str
    scenario_id: str


@dataclass(frozen=True)
class EvidenceGraph:
    nodes: tuple[GraphNode, ...]
    edges: tuple[GraphEdge, ...]

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def nodes_of_type(self, node_type: str) -> tuple[GraphNode, ...]:
        return tuple(node for node in self.nodes if node.node_type == node_type)

    def edges_of_type(self, edge_type: str) -> tuple[GraphEdge, ...]:
        return tuple(edge for edge in self.edges if edge.edge_type == edge_type)


@dataclass(frozen=True)
class CorrelationResult:
    scenario_id: str
    incidents: tuple[CorrelatedIncident, ...]
    edges: tuple[CorrelationEdge, ...]  # grouping에 쓰이지 않은 weak edge까지 전부
    graph: EvidenceGraph
    timeline: tuple[TimelineEntry, ...]  # 전체 timeline
    finding_count: int
    datasets: tuple[str, ...]
    long_span_finding_ids: tuple[str, ...]
    notes: tuple[str, ...] = field(default_factory=tuple)

    def __iter__(self) -> Iterator[CorrelatedIncident]:
        return iter(self.incidents)

    @property
    def grouping_edges(self) -> tuple[CorrelationEdge, ...]:
        return tuple(edge for edge in self.edges if edge.is_grouping_relation)

    @property
    def multi_finding_incidents(self) -> tuple[CorrelatedIncident, ...]:
        return tuple(item for item in self.incidents if not item.is_single_finding)

    @property
    def single_finding_incidents(self) -> tuple[CorrelatedIncident, ...]:
        return tuple(item for item in self.incidents if item.is_single_finding)

    @property
    def hypotheses(self) -> tuple[HypothesisCandidate, ...]:
        return tuple(h for item in self.incidents for h in item.hypotheses)

    def incident_by_id(self, incident_id: str) -> CorrelatedIncident | None:
        """incident_id로 incident를 찾는다.

        IncidentSelectionResult가 ID만 들고 있으므로(복사 저장을 피하려고) 실제 객체를
        찾을 때 쓴다.
        """
        for incident in self.incidents:
            if incident.incident_id == incident_id:
                return incident
        return None
