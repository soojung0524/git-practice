"""LangGraph workflow가 공유하는 InvestigationState.

=== 이벤트를 State에 담지 않는 이유 ===

russellmitchell은 68만 건, GAIA는 1천만 건 이상이다. 이벤트 list를 State에 넣으면
LangGraph가 node마다 갱신분을 병합할 때 참조가 반복 복사되고, checkpointer를 쓰면
직렬화까지 일어난다. 그래서 State에는 이벤트가 아니라 "호출하면 새 Iterator를 주는
공급자"(EventSource)만 담는다.

각 Agent node는 state["event_source"]()를 호출해 자기만의 fresh iterator를 얻는다.
이미 소비된 iterator를 다시 쓰는 버그가 구조적으로 불가능하고, 총 순회 횟수는
route 1회 + 실행되는 Agent 수로 Agent를 직접 순차 실행할 때와 같다.

=== 향후 확장 필드 (지금은 넣지 않는다) ===

timeline, root_causes, hypotheses, impact, report는 해당 기능이 구현될 때 추가한다.
쓰지 않는 필드를 미리 만들어 두지 않는다.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from typing import Annotated, Any, Protocol, TypedDict

from agents import AgentResult
from correlation import (
    CorrelationResult,
    IncidentSelectionResult,
    InvestigationFocus,
)
from guidance import SecurityGuidanceResult
from llm import FindingInterpretation
from report import IncidentReport
from scenario import ScenarioDefinition, ScenarioProjection
from src.models import Finding, NormalizedEvent


class EventSource(Protocol):
    """호출할 때마다 처음부터 순회 가능한 새 Iterable을 주는 공급자.

    예:
        lambda: load_events(path)      # EventStore 파일에서 매번 새로 읽는다
        lambda: iter(events_list)      # 이미 메모리에 있는 경우(소규모/테스트)
    """

    def __call__(self) -> Iterable[NormalizedEvent]: ...


def merge_findings(current: list[Finding], new: list[Finding]) -> list[Finding]:
    """병렬 Agent branch가 각각 반환한 Finding을 이어붙인다(agent_findings 전용).

    순수 concat이다. 여기서 중복을 제거하지 않는다 - 병렬 State 병합과 Finding 의미
    중복 제거는 다른 문제이므로 섞지 않는다. 의미 중복 제거는 collect_findings node의
    deduplicate_findings()가 담당한다.
    """
    return current + new


def merge_errors(current: dict[str, str], new: dict[str, str]) -> dict[str, str]:
    """병렬 Agent branch가 동시에 실패해도 모든 error가 보존되도록 병합한다.

    dict를 그대로 덮어쓰면 같은 superstep에서 발생한 다른 Agent의 error가 사라진다.
    같은 키가 겹치는 경우는 Agent 이름이 키라서 실제로는 발생하지 않지만, 겹치면
    나중 값을 남긴다.
    """
    merged = dict(current)
    merged.update(new)
    return merged


class InvestigationState(TypedDict):
    """workflow 전체가 공유하는 상태."""

    investigation_id: str

    # --- 분석 입력 범위 ---
    # 이벤트 자체가 아니라 공급자. 위 docstring 참고.
    event_source: EventSource
    # Agent Skill에 그대로 전달할 범위 지정 값들. None이면 제한하지 않는다.
    dataset: str | None
    host: str | None
    service: str | None
    start_time: datetime | None
    end_time: datetime | None
    source_types: tuple[str, ...] | None

    # --- routing 판단 근거 (route node가 1회 스캔해 채운다) ---
    available_source_types: frozenset[str]
    routed_agents: tuple[str, ...]

    # --- Agent 실행 결과 (그대로 보존. Orchestrator가 재해석하지 않는다) ---
    # None = 실행되지 않음. 실패한 경우도 None이며 errors에 기록된다.
    application_result: AgentResult | None
    server_result: AgentResult | None
    network_result: AgentResult | None
    authentication_result: AgentResult | None
    security_result: AgentResult | None

    # --- 수집 결과 ---
    # 병렬 Agent branch가 반환한 Finding을 그대로 누적한 것(중복 포함).
    # ServerAgent와 NetworkAgent가 모두 find_metric_anomaly를 쓰므로 같은 finding_id가
    # 두 번 들어올 수 있다. reducer는 순수 concat이다.
    agent_findings: Annotated[list[Finding], merge_findings]
    # collect_findings node가 agent_findings를 finding_id 기준으로 중복 제거한 최종 결과.
    # 이 키는 collect_findings만 쓰므로 reducer가 필요 없다.
    findings: list[Finding]
    errors: Annotated[dict[str, str], merge_errors]

    # --- scenario mode (선택, opt-in) ---
    # scenario_definition이 None이면 scenario 단계를 건너뛴다 = 기존 workflow와 동일하다.
    scenario_definition: ScenarioDefinition | None
    # 조사 대상 anchor. None이면 selection을 요청하지 않은 것이며 incident_selection도
    # None으로 남는다(빈 결과를 만들지 않는다).
    investigation_focus: InvestigationFocus | None
    # 아래 3개는 scenario node들이 채운다. 각 키의 writer가 하나뿐이라 reducer가 없다.
    scenario_projection: ScenarioProjection | None
    correlation_result: CorrelationResult | None
    incident_selection: IncidentSelectionResult | None

    # --- Security Guidance (선택) ---
    # security_guidance_provider를 줬을 때만 채워진다. provider 객체 자체는 State에
    # 넣지 않는다(직렬화 대상에 외부 client가 들어가면 안 된다) - build_graph가 node
    # closure로 주입한다.
    security_guidance: SecurityGuidanceResult | None

    # --- Incident Report (선택) ---
    # build_report=True일 때만 채워진다. 결정론적 섹션은 LLM 없이도 완성된다.
    incident_report: IncidentReport | None

    # --- LLM 해석 (선택) ---
    # interpret=True로 실행했을 때만 채워진다. Finding을 바꾸지 않는 부가 정보다.
    interpretation: FindingInterpretation | None


def new_state(
    *,
    investigation_id: str,
    event_source: EventSource,
    dataset: str | None = None,
    host: str | None = None,
    service: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    source_types: Iterable[str] | None = None,
    scenario_definition: ScenarioDefinition | None = None,
    investigation_focus: InvestigationFocus | None = None,
) -> InvestigationState:
    """초기 State를 만든다. 모든 필드를 명시적으로 채운다(TypedDict 누락 방지)."""
    return InvestigationState(
        investigation_id=investigation_id,
        event_source=event_source,
        dataset=dataset,
        host=host,
        service=service,
        start_time=start_time,
        end_time=end_time,
        source_types=tuple(source_types) if source_types is not None else None,
        available_source_types=frozenset(),
        routed_agents=(),
        application_result=None,
        server_result=None,
        network_result=None,
        authentication_result=None,
        security_result=None,
        agent_findings=[],
        findings=[],
        errors={},
        scenario_definition=scenario_definition,
        investigation_focus=investigation_focus,
        scenario_projection=None,
        correlation_result=None,
        incident_selection=None,
        security_guidance=None,
        incident_report=None,
        interpretation=None,
    )


def scope_kwargs(state: InvestigationState) -> dict[str, Any]:
    """Agent.run()에 그대로 넘길 범위 지정 인자를 뽑는다."""
    return {
        "dataset": state["dataset"],
        "host": state["host"],
        "service": state["service"],
        "start_time": state["start_time"],
        "end_time": state["end_time"],
        "source_types": state["source_types"],
    }
