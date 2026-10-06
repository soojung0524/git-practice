"""Evidence Graph 생성.

현재 실제 데이터에서 관측 가능한 관계만 만든다. 관측되지 않은 관계를 추측해서 만들지
않는다. 인과를 뜻하는 edge(triggered 등)는 만들지 않는다.

=== 만들지 않는 것과 이유 ===

- Event 노드   : Finding.evidence로 충분하고, 전체 이벤트를 노드로 만들면 수백만 개가 된다
- Process 노드 : 어떤 detector도 process를 Finding에 담지 않는다
- triggered    : 인과 단정이다. correlation은 인과를 판단하지 않는다
- authenticated_as : authentication detector가 없어 관측 자체가 없다
- connected_to : 네트워크 연결 관계를 관측하지 않는다
"""

from __future__ import annotations

from collections.abc import Sequence

from scenario import ScenarioFinding

from .config import (
    EDGE_AFFECTS,
    EDGE_CORRELATED_WITH,
    EDGE_INVOLVES,
    EDGE_OBSERVED_ON,
    EDGE_PRECEDED,
    ENTITY_KEY_NODE_TYPES,
    NODE_FINDING,
    NODE_HOST,
    NODE_SERVICE,
    TEMPORAL_PRECEDES,
)
from .models import CorrelatedIncident, CorrelationEdge, EvidenceGraph, GraphEdge, GraphNode


def make_node_id(scenario_id: str, node_type: str, value: str) -> str:
    """deterministic node id.

    entity 노드는 dataset으로 namespace하지 않는다 - dataset별로 나누면 두 dataset이 같은
    entity를 공유해도 서로 다른 노드가 되어, scenario mode에서 dataset 간 연결을 관찰하려는
    목적이 그래프에서 사라진다. provenance는 GraphNode.datasets에 기록한다.

    Finding 노드는 finding_id에 dataset이 이미 들어 있어 충돌하지 않는다.
    """
    return f"{scenario_id}:{node_type}:{value}"


class _NodeAccumulator:
    """같은 node_id로 여러 번 등장하는 entity의 dataset을 모아 둔다."""

    def __init__(self, scenario_id: str) -> None:
        self._scenario_id = scenario_id
        self._nodes: dict[str, tuple[str, str, set[str]]] = {}

    def add(self, node_type: str, value: str, dataset: str) -> str:
        node_id = make_node_id(self._scenario_id, node_type, value)
        if node_id not in self._nodes:
            self._nodes[node_id] = (node_type, value, set())
        self._nodes[node_id][2].add(dataset)
        return node_id

    def build(self) -> tuple[GraphNode, ...]:
        return tuple(
            GraphNode(
                node_id=node_id,
                node_type=node_type,
                label=label,
                datasets=tuple(sorted(datasets)),
            )
            for node_id, (node_type, label, datasets) in sorted(self._nodes.items())
        )


def build_evidence_graph(
    findings: Sequence[ScenarioFinding],
    edges: Sequence[CorrelationEdge],
    incidents: Sequence[CorrelatedIncident],
    scenario_id: str,
) -> EvidenceGraph:
    """Finding과 그 식별자, 그리고 Finding 사이 관계를 그래프로 만든다."""
    nodes = _NodeAccumulator(scenario_id)
    graph_edges: dict[tuple[str, str, str], GraphEdge] = {}

    def add_edge(source_node_id: str, target_node_id: str, edge_type: str) -> None:
        key = (edge_type, source_node_id, target_node_id)
        if key not in graph_edges:
            graph_edges[key] = GraphEdge(
                source_node_id=source_node_id,
                target_node_id=target_node_id,
                edge_type=edge_type,
                scenario_id=scenario_id,
            )

    finding_node_ids: dict[str, str] = {}

    for item in findings:
        finding = item.finding
        finding_node_id = nodes.add(NODE_FINDING, finding.finding_id, item.dataset)
        finding_node_ids[finding.finding_id] = finding_node_id

        if finding.host is not None:
            host_node_id = nodes.add(NODE_HOST, finding.host, item.dataset)
            add_edge(finding_node_id, host_node_id, EDGE_OBSERVED_ON)

        if finding.service is not None:
            service_node_id = nodes.add(NODE_SERVICE, finding.service, item.dataset)
            add_edge(finding_node_id, service_node_id, EDGE_AFFECTS)

        for key, values in sorted(finding.entities.items()):
            node_type = ENTITY_KEY_NODE_TYPES.get(key)
            if node_type is None:
                continue  # 매핑이 없는 entity 키는 노드를 만들지 않는다
            for value in sorted(values):
                entity_node_id = nodes.add(node_type, value, item.dataset)
                add_edge(finding_node_id, entity_node_id, EDGE_INVOLVES)

    for edge in edges:
        source_node_id = finding_node_ids.get(edge.source_finding_id)
        target_node_id = finding_node_ids.get(edge.target_finding_id)
        if source_node_id is None or target_node_id is None:
            continue

        # preceded: 시간 순서가 의미 있을 때만. long-span Finding은 인과 순서에 쓰지 않는다.
        if edge.temporal_relation == TEMPORAL_PRECEDES and not edge.weak_temporal:
            add_edge(source_node_id, target_node_id, EDGE_PRECEDED)

        if edge.is_grouping_relation:
            add_edge(source_node_id, target_node_id, EDGE_CORRELATED_WITH)

    return EvidenceGraph(
        nodes=nodes.build(),
        edges=tuple(graph_edges[key] for key in sorted(graph_edges)),
    )
