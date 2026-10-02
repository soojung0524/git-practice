"""LangGraph workflow 정의와 실행.

START -> route -(conditional fan-out)-> [application | server | network | authentication]
      -> collect_findings (fan-in barrier) -> security_agent -> END

checkpointer, interrupt, human-in-the-loop, LLM routing은 사용하지 않는다.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import datetime

from langgraph.graph import END, START, StateGraph

from src.models import NormalizedEvent

from .nodes import (
    NODE_APPLICATION,
    NODE_INTERPRET,
    NODE_AUTHENTICATION,
    NODE_COLLECT,
    NODE_NETWORK,
    NODE_ROUTE,
    NODE_SECURITY,
    NODE_SERVER,
    application_node,
    authentication_node,
    collect_findings_node,
    interpret_node,
    network_node,
    route_node,
    route_selector,
    security_node,
    server_node,
)
from .state import EventSource, InvestigationState, new_state

# 병렬 fan-out 대상 Agent node (서로의 결과에 의존하지 않는다).
PARALLEL_AGENT_NODES = (
    NODE_APPLICATION,
    NODE_SERVER,
    NODE_NETWORK,
    NODE_AUTHENTICATION,
)


def build_graph(*, interpret: bool = False):
    """workflow graph를 만들어 compile한다.

    interpret=True면 SecurityAgent 뒤에 LLM 해석 node를 붙인다. 기본값이 False인 이유는
    LLM 호출이 외부 네트워크와 비용을 수반하기 때문이다 - 명시적으로 켜야 한다.
    탐지 결과(findings)는 interpret 값과 무관하게 동일하다.
    """
    graph = StateGraph(InvestigationState)

    graph.add_node(NODE_ROUTE, route_node)
    graph.add_node(NODE_APPLICATION, application_node)
    graph.add_node(NODE_SERVER, server_node)
    graph.add_node(NODE_NETWORK, network_node)
    graph.add_node(NODE_AUTHENTICATION, authentication_node)
    graph.add_node(NODE_COLLECT, collect_findings_node)
    graph.add_node(NODE_SECURITY, security_node)

    graph.add_edge(START, NODE_ROUTE)
    # route가 돌려준 node들로 fan-out한다. 실행할 Agent가 없으면 collect로 직행한다.
    graph.add_conditional_edges(
        NODE_ROUTE,
        route_selector,
        [*PARALLEL_AGENT_NODES, NODE_COLLECT],
    )
    # 각 Agent branch는 collect로 모인다(fan-in barrier).
    for node_name in PARALLEL_AGENT_NODES:
        graph.add_edge(node_name, NODE_COLLECT)
    graph.add_edge(NODE_COLLECT, NODE_SECURITY)

    if interpret:
        graph.add_node(NODE_INTERPRET, interpret_node)
        graph.add_edge(NODE_SECURITY, NODE_INTERPRET)
        graph.add_edge(NODE_INTERPRET, END)
    else:
        graph.add_edge(NODE_SECURITY, END)

    return graph.compile()


def run_investigation(
    *,
    event_source: EventSource | None = None,
    events: Iterable[NormalizedEvent] | None = None,
    investigation_id: str | None = None,
    dataset: str | None = None,
    host: str | None = None,
    service: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    source_types: Iterable[str] | None = None,
    interpret: bool = False,
) -> InvestigationState:
    """workflow를 한 번 실행하고 최종 State를 돌려준다.

    event_source
        호출하면 새 Iterable을 주는 공급자. 대규모 데이터는 이 방식을 쓴다.
        예: lambda: load_events("output/events.pkl")
    events
        이미 메모리에 있는 이벤트. workflow가 여러 번 순회해야 하므로 내부에서 list로
        한 번 materialize한다. 수백만 건 규모에서는 event_source를 쓸 것.

    interpret
        True면 마지막에 LLM(OpenAI)으로 Finding을 해석해 state["interpretation"]에 담는다.
        외부 API를 호출하고 비용이 발생하므로 기본값은 False다. 탐지 결과는 이 값과
        무관하게 같다.

    둘 중 정확히 하나를 줘야 한다.
    """
    if (event_source is None) == (events is None):
        raise ValueError("event_source 또는 events 중 정확히 하나를 지정해야 한다")

    if event_source is None:
        materialized = list(events)  # type: ignore[arg-type]

        def event_source() -> Iterable[NormalizedEvent]:  # type: ignore[misc]
            return iter(materialized)

    initial = new_state(
        investigation_id=investigation_id or str(uuid.uuid4()),
        event_source=event_source,
        dataset=dataset,
        host=host,
        service=service,
        start_time=start_time,
        end_time=end_time,
        source_types=source_types,
    )

    graph = build_graph(interpret=interpret)
    return graph.invoke(initial)
