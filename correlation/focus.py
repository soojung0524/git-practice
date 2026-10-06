"""Investigation Focus - CorrelationResult에서 이번 조사 대상 incident를 고른다.

하나의 scenario Window 안에는 서로 무관한 incident가 함께 존재할 수 있다. 실측 예:
GAIA의 dbservice1 network anomaly를 기준으로 만든 20분 Window 안에, 그와 무관한
webservice2의 service_latency_spike 2건이 별도 multi-Finding incident로 존재했다.

따라서 "Window 안의 모든 incident"를 조사 대상으로 볼 수 없다. 조사 대상은 분석자가
anchor Finding으로 명시한다 - 랜덤 선택이나 LLM 판단을 쓰지 않는다.

incident 크기나 severity로 우선순위를 주지 않는다. anchor가 single-Finding incident에
있으면 그 single-Finding incident가 선택된다.

이 모듈은 CorrelationResult와 InvestigationFocus만 알면 동작한다(orchestration을 모른다).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

from src.models import Finding

from .models import CorrelationResult


@dataclass(frozen=True)
class InvestigationFocus:
    """이번 조사의 대상을 지정하는 anchor Finding 집합.

    anchor_finding_ids는 생성 시 정렬된 canonical tuple로 정규화된다. 따라서 같은 anchor
    집합이면 입력 순서와 무관하게 동일한 InvestigationFocus가 된다(== 비교와 해시가
    순서에 영향받지 않는다).

    빈 tuple과 중복은 설정 실수이므로 생성 시점에 ValueError로 거부한다. anchor가
    correlation 결과에 없는 경우는 Window 선택의 정상적인 결과일 수 있어 오류로 보지
    않는다(select_incidents의 unmatched_anchor_finding_ids 참고).
    """

    anchor_finding_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        anchors = tuple(self.anchor_finding_ids)
        if not anchors:
            raise ValueError(
                "anchor_finding_ids가 비어 있다. 조사 대상을 명시해야 한다"
            )
        if len(set(anchors)) != len(anchors):
            duplicates = sorted({a for a in anchors if anchors.count(a) > 1})
            raise ValueError(f"anchor_finding_ids에 중복이 있다: {duplicates}")
        # frozen dataclass지만 __post_init__에서는 object.__setattr__로 정규화할 수 있다.
        object.__setattr__(self, "anchor_finding_ids", tuple(sorted(anchors)))


def focus_on(findings: Iterable[Finding]) -> InvestigationFocus:
    """Finding 객체에서 InvestigationFocus를 만든다.

    실제 finding_id는
    "gaia:find_metric_anomaly:dbservice1_docker_network_in_packets:2021-07-31T19:10:27+00:00"
    처럼 길어서 손으로 적기 어렵다. Finding을 그대로 넘길 수 있게 한다.
    """
    return InvestigationFocus(anchor_finding_ids=tuple(f.finding_id for f in findings))


@dataclass(frozen=True)
class IncidentSelectionResult:
    """선택 결과. CorrelatedIncident를 복사하지 않고 ID만 참조한다.

    실제 incident 객체는 CorrelationResult.incident_by_id()로 찾는다.
    """

    scenario_id: str
    focused_incident_ids: tuple[str, ...]
    # correlation 결과에 없는 anchor. 오류가 아니다 - scenario Window 밖이어서
    # projection에서 제외됐거나, dataset Window가 없어 skip된 경우가 있다.
    unmatched_anchor_finding_ids: tuple[str, ...]
    # correlation이 만든 전체 incident 수(선택 전 후보 수).
    candidate_incident_count: int
    # anchor_finding_id -> 그 anchor가 속한 incident_id (추적용)
    anchor_to_incident: dict[str, str] = field(default_factory=dict)
    notes: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not self.focused_incident_ids

    @property
    def has_unmatched_anchors(self) -> bool:
        return bool(self.unmatched_anchor_finding_ids)


class InconsistentCorrelationError(AssertionError):
    """같은 finding_id가 둘 이상의 incident에 들어 있다.

    incident는 grouping edge의 connected component이므로 한 Finding은 정확히 하나의
    incident에만 속해야 한다. 이 불변식이 깨졌다면 correlation 쪽 버그이므로, 조용히
    덮어쓰지 않고 programming error로 즉시 실패시킨다(AssertionError를 상속해 기존
    orchestration error policy에서도 숨겨지지 않고 다시 raise된다).
    """


def _build_finding_index(result: CorrelationResult) -> dict[str, str]:
    """finding_id -> incident_id 역인덱스.

    중복이 있으면 InconsistentCorrelationError를 낸다.
    """
    index: dict[str, str] = {}
    for incident in result.incidents:
        for finding_id in incident.finding_ids:
            previous = index.get(finding_id)
            if previous is not None and previous != incident.incident_id:
                raise InconsistentCorrelationError(
                    f"finding {finding_id!r}가 두 incident에 동시에 속한다: "
                    f"{previous!r}, {incident.incident_id!r}"
                )
            index[finding_id] = incident.incident_id
    return index


def select_incidents(
    result: CorrelationResult, focus: InvestigationFocus
) -> IncidentSelectionResult:
    """anchor Finding이 속한 incident만 선택한다.

    - anchor 여러 개가 같은 incident에 있으면 그 incident는 한 번만 선택된다.
    - anchor가 서로 다른 incident에 있으면 여러 incident가 선택된다.
    - anchor가 correlation 결과에 없으면 unmatched_anchor_finding_ids에 기록하고 계속한다.
    - incident 크기나 severity로 우선순위를 주지 않는다.

    anchor_finding_ids가 이미 정렬돼 있고 결과도 정렬하므로, 같은 입력이면 항상 같은
    결과가 나온다.
    """
    index = _build_finding_index(result)

    focused: set[str] = set()
    unmatched: list[str] = []
    anchor_to_incident: dict[str, str] = {}

    for anchor in focus.anchor_finding_ids:
        incident_id = index.get(anchor)
        if incident_id is None:
            unmatched.append(anchor)
            continue
        focused.add(incident_id)
        anchor_to_incident[anchor] = incident_id

    notes: list[str] = []
    if unmatched:
        notes.append(
            f"correlation 결과에 없는 anchor {len(unmatched)}건. scenario Window 밖이어서 "
            "projection에서 제외됐는지, dataset Window가 없어 skip됐는지 확인할 것."
        )
    if unmatched and not focused:
        notes.append(
            "anchor가 하나도 매칭되지 않아 선택된 incident가 없다. "
            "scenario Window가 조사 대상 Finding을 포함하는지 확인할 것."
        )
    if len(focused) < result.incidents.__len__() and focused:
        notes.append(
            f"후보 incident {len(result.incidents)}건 중 anchor가 속한 {len(focused)}건만 "
            "선택했다. 나머지는 같은 Window 안에 있지만 조사 대상이 아니다."
        )

    return IncidentSelectionResult(
        scenario_id=result.scenario_id,
        focused_incident_ids=tuple(sorted(focused)),
        unmatched_anchor_finding_ids=tuple(unmatched),
        candidate_incident_count=len(result.incidents),
        anchor_to_incident=dict(sorted(anchor_to_incident.items())),
        notes=tuple(notes),
    )
