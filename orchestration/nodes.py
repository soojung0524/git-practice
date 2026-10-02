"""LangGraph node 함수들.

node는 Agent를 호출하고 결과를 State에 담기만 한다. 로그 파싱, anomaly detection,
threshold 계산, severity 변경, Finding 수정, root cause 판단, correlation, RAG 검색을
하지 않는다.
"""

from __future__ import annotations

import traceback
from collections.abc import Iterable
from typing import Any

from agent_skills.application_analysis.scripts import run_application_analysis as _app_skill
from agent_skills.network_analysis.scripts import run_network_analysis as _net_skill
from agent_skills.server_analysis.scripts import run_server_analysis as _srv_skill
from agents import (
    AgentResult,
    ApplicationAgent,
    AuthenticationAgent,
    NetworkAgent,
    SecurityAgent,
    ServerAgent,
)

from llm import InterpretationAgent, agent_statuses_from_results
from src.models import Finding

from .state import InvestigationState, scope_kwargs

# node 이름. graph.py와 테스트가 같은 상수를 쓴다.
NODE_ROUTE = "route"
NODE_APPLICATION = "application_agent"
NODE_SERVER = "server_agent"
NODE_NETWORK = "network_agent"
NODE_AUTHENTICATION = "authentication_agent"
NODE_COLLECT = "collect_findings"
NODE_SECURITY = "security_agent"
NODE_INTERPRET = "interpret_findings"

# routing 조건을 하드코딩하지 않고 각 Agent Skill이 선언한 SOURCE_TYPES를 그대로 쓴다.
_AGENT_SOURCE_TYPES: dict[str, frozenset[str]] = {
    NODE_APPLICATION: frozenset(_app_skill.SOURCE_TYPES),
    NODE_SERVER: frozenset(_srv_skill.SOURCE_TYPES),
    NODE_NETWORK: frozenset(_net_skill.SOURCE_TYPES),
}

# authentication Skill은 아직 어떤 이벤트도 소비하지 않아 SOURCE_TYPES가 비어 있다.
# 그래서 교집합 규칙으로는 절대 실행되지 않는다. "인증 관련 로그가 데이터에 있으면
# 실행하고 not_implemented를 정상 결과로 받는다"는 요구를 만족시키기 위해 이 Agent만
# routing 전용 상수를 둔다. 값은 authentication SKILLS.md 7절의 참고 parser 목록과
# 같으며, 두 곳이 어긋나지 않는지 테스트로 대조한다.
AUTHENTICATION_ROUTING_SOURCE_TYPES = frozenset({"syslog_auth", "auditd", "openvpn"})

# State에 AgentResult를 저장할 키.
_RESULT_KEY = {
    NODE_APPLICATION: "application_result",
    NODE_SERVER: "server_result",
    NODE_NETWORK: "network_result",
    NODE_AUTHENTICATION: "authentication_result",
    NODE_SECURITY: "security_result",
}

# 코드 버그로 보아야 하는 예외. State에 숨기지 않고 그대로 올린다.
# (KeyboardInterrupt/SystemExit은 BaseException이라 애초에 except Exception에 안 걸린다.)
_PROGRAMMING_ERRORS = (
    AssertionError,
    NameError,
    AttributeError,
    TypeError,
    ImportError,
)


def _run_agent_node(state: InvestigationState, node_name: str, agent: Any) -> dict:
    """Agent를 실행하고 결과를 State 갱신 dict로 만든다.

    데이터 문제로 실패하면 errors에 traceback 전문을 기록하고 workflow는 계속 진행한다.
    코드 버그로 보이는 예외는 다시 raise해서 개발 단계에서 숨지 않게 한다.
    """
    try:
        result = agent.run(state["event_source"](), **scope_kwargs(state))
    except _PROGRAMMING_ERRORS:
        raise
    except Exception:
        return {"errors": {node_name: traceback.format_exc()}}

    return {_RESULT_KEY[node_name]: result, "agent_findings": result.findings}


def route_node(state: InvestigationState) -> dict:
    """이벤트를 한 번만 스캔해 존재하는 source_type 집합과 실행할 Agent를 정한다.

    이벤트를 저장하지 않고 source_type만 모으므로 메모리 사용이 상수다.
    """
    available: set[str] = set()
    dataset = state["dataset"]
    for event in state["event_source"]():
        if dataset is not None and event.dataset != dataset:
            continue
        available.add(event.source_type)

    available_frozen = frozenset(available)
    routed = select_agents(available_frozen)
    return {"available_source_types": available_frozen, "routed_agents": routed}


def select_agents(available_source_types: frozenset[str]) -> tuple[str, ...]:
    """존재하는 source_type을 근거로 실행할 Agent node 이름을 정한다(deterministic).

    Agent Skill이 선언한 SOURCE_TYPES와 교집합이 있으면 실행한다.
    AuthenticationAgent만 SOURCE_TYPES가 비어 있어 별도 상수를 쓴다(위 주석 참고).
    """
    selected: list[str] = []
    for node_name in (NODE_APPLICATION, NODE_SERVER, NODE_NETWORK):
        if _AGENT_SOURCE_TYPES[node_name] & available_source_types:
            selected.append(node_name)
    if AUTHENTICATION_ROUTING_SOURCE_TYPES & available_source_types:
        selected.append(NODE_AUTHENTICATION)
    return tuple(selected)


def route_selector(state: InvestigationState) -> list[str]:
    """conditional edge의 목적지. 실행할 Agent node 이름 리스트를 돌려준다.

    실행할 Agent가 없으면 collect_findings로 직행한다(graph는 정상 완주한다).
    LangGraph 1.2.x에서 리스트를 반환하면 그 node들이 하나의 superstep으로 실행되고,
    collect_findings는 실제로 실행된 branch가 모두 끝난 뒤 정확히 한 번 실행된다
    (동적 부분집합 포함 - tests/test_orchestration.py에서 검증한다).
    """
    routed = state["routed_agents"]
    return list(routed) if routed else [NODE_COLLECT]


def application_node(state: InvestigationState) -> dict:
    return _run_agent_node(state, NODE_APPLICATION, ApplicationAgent())


def server_node(state: InvestigationState) -> dict:
    return _run_agent_node(state, NODE_SERVER, ServerAgent())


def network_node(state: InvestigationState) -> dict:
    return _run_agent_node(state, NODE_NETWORK, NetworkAgent())


def authentication_node(state: InvestigationState) -> dict:
    return _run_agent_node(state, NODE_AUTHENTICATION, AuthenticationAgent())


class ConflictingFindingError(RuntimeError):
    """같은 finding_id인데 내용이 다른 Finding이 발견됐다.

    finding_id는 (detector, dataset, group_key, start_time)으로 결정되므로 같은 id면
    같은 관측 사실이어야 한다. 내용이 다르다면 detector나 finding_id 생성 규칙에 문제가
    있다는 뜻이므로, 조용히 하나를 버리지 않고 오류로 드러낸다.
    """


# 중복 판정에 쓰는 비교 대상 필드. finding_id를 제외한 Finding의 모든 의미 필드다
# (summary는 metrics로부터 생성되는 설명 문장이라 함께 비교한다).
def _comparable(finding: Finding) -> tuple:
    return (
        finding.dataset,
        finding.category,
        finding.finding_type,
        finding.start_time,
        finding.end_time,
        finding.host,
        finding.service,
        finding.severity,
        finding.summary,
        tuple(sorted(finding.metrics.items(), key=lambda kv: kv[0])),
        tuple(
            (e.source_type, e.source_file, e.line_number, e.timestamp, e.event_id)
            for e in finding.evidence
        ),
        tuple(sorted((k, tuple(v)) for k, v in finding.entities.items())),
        finding.detector,
    )


def deduplicate_findings(findings: Iterable[Finding]) -> list[Finding]:
    """finding_id 기준 first-wins로 중복을 제거한다.

    ServerAgent와 NetworkAgent가 모두 find_metric_anomaly를 실행하므로, network metric
    Finding은 같은 finding_id로 두 번 수집된다(실측 확인). 내용이 같으면 하나만 남긴다.

    같은 finding_id인데 내용이 다르면 ConflictingFindingError를 올린다 - 조용히 하나를
    버리면 진짜 문제를 놓친다.

    Finding 객체를 수정하지 않는다. 먼저 등장한 객체를 그대로 유지하며, 등장 순서도
    보존한다(dict의 삽입 순서).
    """
    unique: dict[str, Finding] = {}
    for finding in findings:
        existing = unique.get(finding.finding_id)
        if existing is None:
            unique[finding.finding_id] = finding
            continue
        if _comparable(existing) != _comparable(finding):
            raise ConflictingFindingError(
                f"같은 finding_id인데 내용이 다르다: {finding.finding_id!r} "
                f"(detector={existing.detector!r} vs {finding.detector!r})"
            )
    return list(unique.values())


def collect_findings_node(state: InvestigationState) -> dict:
    """병렬 branch의 join 지점(barrier)이며, 여기서 Finding 중복을 제거한다.

    agent_findings는 reducer가 순수 concat으로 누적한 값(중복 포함)이고, 이 node가
    finding_id 기준으로 중복을 제거해 findings에 넣는다. SecurityAgent는 findings를
    입력으로 받으므로 중복 제거 이후의 Finding만 보게 된다.

    LangGraph 1.2.x에서 이 node는 실제로 실행된 branch가 모두 끝난 뒤 정확히 한 번
    실행된다(tests/test_orchestration.py에서 검증).
    """
    return {"findings": deduplicate_findings(state["agent_findings"])}


def security_node(state: InvestigationState) -> dict:
    """수집된 Finding으로 SecurityAgent를 실행한다.

    결과를 findings에 되넣지 않는다 - 이미 findings에 있는 Finding의 부분집합이므로
    다시 넣으면 중복이 된다.
    """
    try:
        result: AgentResult = SecurityAgent().run(state["findings"])
    except _PROGRAMMING_ERRORS:
        raise
    except Exception:
        return {"errors": {NODE_SECURITY: traceback.format_exc()}}

    return {_RESULT_KEY[NODE_SECURITY]: result}


def interpret_node(state: InvestigationState) -> dict:
    """수집된 Finding을 LLM으로 해석한다(선택 단계).

    Finding을 수정하지 않고, severity를 바꾸지 않고, 새 Finding을 만들지 않는다.
    결과는 interpretation에만 담긴다.

    API 키가 없거나 호출이 실패해도 예외를 올리지 않는다 - LLM은 부가 기능이므로
    탐지 결과가 그것 때문에 사라지면 안 된다. 상태는 FindingInterpretation.status로
    확인한다.
    """
    statuses = agent_statuses_from_results(
        {
            "application_agent": state["application_result"],
            "server_agent": state["server_result"],
            "network_agent": state["network_result"],
            "authentication_agent": state["authentication_result"],
            "security_agent": state["security_result"],
        }
    )
    interpretation = InterpretationAgent().run(state["findings"], agent_statuses=statuses)
    return {"interpretation": interpretation}
