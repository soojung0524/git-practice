"""LangGraph 기반 Investigation workflow.

NormalizedEvent -> InvestigationState -> Orchestrator(graph) -> 전문 Agent 실행
-> AgentResult 수집 -> Finding 병합 -> SecurityAgent -> 최종 InvestigationState

의존 방향: orchestration -> agents -> agent_skills -> src/skills -> src/models
evaluation과 Ground Truth는 이 계층에서 사용하지 않는다.
"""

from .graph import PARALLEL_AGENT_NODES, build_graph, run_investigation
from .nodes import (
    AUTHENTICATION_ROUTING_SOURCE_TYPES,
    ConflictingFindingError,
    NODE_APPLICATION,
    NODE_AUTHENTICATION,
    NODE_COLLECT,
    NODE_INTERPRET,
    NODE_NETWORK,
    NODE_ROUTE,
    NODE_SECURITY,
    NODE_SERVER,
    deduplicate_findings,
    select_agents,
)
from .state import (
    EventSource,
    InvestigationState,
    merge_errors,
    merge_findings,
    new_state,
    scope_kwargs,
)

__all__ = [
    "InvestigationState",
    "EventSource",
    "new_state",
    "scope_kwargs",
    "merge_findings",
    "merge_errors",
    "build_graph",
    "run_investigation",
    "select_agents",
    "deduplicate_findings",
    "ConflictingFindingError",
    "PARALLEL_AGENT_NODES",
    "AUTHENTICATION_ROUTING_SOURCE_TYPES",
    "NODE_ROUTE",
    "NODE_APPLICATION",
    "NODE_SERVER",
    "NODE_NETWORK",
    "NODE_AUTHENTICATION",
    "NODE_COLLECT",
    "NODE_INTERPRET",
    "NODE_SECURITY",
]
