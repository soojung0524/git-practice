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

from correlation import InvestigationFocus
from guidance import SecurityGuidanceProvider
from report import NarrativeSummaryProvider
from scenario import ScenarioDefinition
from src.models import NormalizedEvent

from .nodes import (
    NODE_APPLICATION,
    NODE_EVIDENCE_CORRELATION,
    NODE_INCIDENT_REPORT,
    NODE_INTERPRET,
    NODE_SCENARIO_PROJECTION,
    NODE_SECURITY_GUIDANCE,
    NODE_SELECT_INCIDENT,
    NODE_AUTHENTICATION,
    NODE_COLLECT,
    NODE_NETWORK,
    NODE_ROUTE,
    NODE_SECURITY,
    NODE_SERVER,
    application_node,
    authentication_node,
    collect_findings_node,
    evidence_correlation_node,
    interpret_node,
    make_incident_report_node,
    make_security_guidance_node,
    network_node,
    route_node,
    route_selector,
    scenario_projection_node,
    security_node,
    select_incident_node,
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


def build_graph(
    *,
    interpret: bool = False,
    scenario: bool = False,
    security_guidance_provider: SecurityGuidanceProvider | None = None,
    build_report: bool = False,
    narrative_summary_provider: NarrativeSummaryProvider | None = None,
):
    """workflow graph를 만들어 compile한다.

    scenario=True면 SecurityAgent 뒤에 scenario 단계 3개를 직렬로 붙인다.
    interpret=True면 그 뒤에 LLM 해석 node를 붙인다.

    security_guidance_provider를 주면 select_incident 뒤에 security_guidance node를
    붙인다. 별도 boolean flag를 두지 않는다 - provider가 있으면 enabled, 없으면
    disabled다. provider는 State가 아니라 node closure로 주입된다.

    둘 다 기본값이 False인 이유: scenario는 ScenarioDefinition이 필요하고 interpret은
    외부 API 호출과 비용을 수반한다. 명시적으로 켜야 한다. False일 때는 해당 node를
    graph에 추가조차 하지 않으므로 기존 graph와 node 집합이 완전히 동일하다.

    최종 경로 4가지:
      scenario=False, interpret=False : security_agent -> END
      scenario=False, interpret=True  : security_agent -> interpret_findings -> END
      scenario=True,  interpret=False : security_agent -> scenario_projection
                                        -> evidence_correlation -> select_incident -> END
      scenario=True,  interpret=True  : ... -> select_incident -> interpret_findings -> END
    provider가 있으면 select_incident와 그 뒤 사이에 security_guidance가 들어간다.

    END와 interpret_findings로 동시에 fan-out하지 않는다 - 경로는 항상 하나다.
    """
    if narrative_summary_provider is not None and not build_report:
        raise ValueError(
            "narrative_summary_provider는 build_report=True일 때만 쓸 수 있다"
        )
    if security_guidance_provider is not None and not scenario:
        raise ValueError(
            "security_guidance_provider는 scenario mode에서만 쓸 수 있다 "
            "(focused incident가 없으면 질문을 만들 수 없다)"
        )
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

    # security_agent 다음 구간을 직렬로 잇는다. 마지막 node만 END로 간다.
    tail = NODE_SECURITY

    if scenario:
        graph.add_node(NODE_SCENARIO_PROJECTION, scenario_projection_node)
        graph.add_node(NODE_EVIDENCE_CORRELATION, evidence_correlation_node)
        graph.add_node(NODE_SELECT_INCIDENT, select_incident_node)
        graph.add_edge(tail, NODE_SCENARIO_PROJECTION)
        graph.add_edge(NODE_SCENARIO_PROJECTION, NODE_EVIDENCE_CORRELATION)
        graph.add_edge(NODE_EVIDENCE_CORRELATION, NODE_SELECT_INCIDENT)
        tail = NODE_SELECT_INCIDENT

    if security_guidance_provider is not None:
        graph.add_node(
            NODE_SECURITY_GUIDANCE,
            make_security_guidance_node(security_guidance_provider),
        )
        graph.add_edge(tail, NODE_SECURITY_GUIDANCE)
        tail = NODE_SECURITY_GUIDANCE

    if build_report:
        graph.add_node(
            NODE_INCIDENT_REPORT,
            make_incident_report_node(narrative_summary_provider),
        )
        graph.add_edge(tail, NODE_INCIDENT_REPORT)
        tail = NODE_INCIDENT_REPORT

    if interpret:
        graph.add_node(NODE_INTERPRET, interpret_node)
        graph.add_edge(tail, NODE_INTERPRET)
        tail = NODE_INTERPRET

    graph.add_edge(tail, END)

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
    scenario_definition: "ScenarioDefinition | None" = None,
    investigation_focus: "InvestigationFocus | None" = None,
    security_guidance_provider: SecurityGuidanceProvider | None = None,
    build_report: bool = False,
    narrative_summary_provider: NarrativeSummaryProvider | None = None,
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
    scenario_definition
        주면 scenario mode로 실행한다(projection -> correlation -> selection).
        없으면 기존 workflow와 완전히 동일하게 동작한다 - scenario 기능은 opt-in이다.
    investigation_focus
        조사 대상 anchor Finding. scenario_definition과 함께 줘야 한다. 주지 않으면
        incident_selection은 None으로 남는다(selection을 요청하지 않은 것).
    security_guidance_provider
        주면 focused incident마다 AWS 문서 근거 guidance를 만든다. scenario_definition과
        함께 줘야 한다. 주지 않으면 RAG 모듈 import가 일어나지 않는다.
    build_report
        True면 결정론적 IncidentReport를 만들어 state["incident_report"]에 담는다.
        기본값 False - 기존 workflow 동작을 바꾸지 않는다.
    narrative_summary_provider
        주면 보고서에 LLM 자연어 요약을 붙인다. build_report=True여야 한다. 요약이
        실패해도 결정론적 보고서는 보존된다.

    event_source와 events는 둘 중 정확히 하나를 줘야 한다.
    """
    if narrative_summary_provider is not None and not build_report:
        raise ValueError(
            "narrative_summary_provider는 build_report=True와 함께 줘야 한다"
        )
    if security_guidance_provider is not None and scenario_definition is None:
        raise ValueError(
            "security_guidance_provider는 scenario_definition과 함께 줘야 한다 "
            "(focused incident가 없으면 질문을 만들 수 없다)"
        )
    if investigation_focus is not None and scenario_definition is None:
        raise ValueError(
            "investigation_focus는 scenario_definition과 함께 줘야 한다 "
            "(correlation 결과가 없으면 incident를 고를 수 없다)"
        )

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
        scenario_definition=scenario_definition,
        investigation_focus=investigation_focus,
    )

    graph = build_graph(
        interpret=interpret,
        scenario=scenario_definition is not None,
        security_guidance_provider=security_guidance_provider,
        build_report=build_report,
        narrative_summary_provider=narrative_summary_provider,
    )
    return graph.invoke(initial)
