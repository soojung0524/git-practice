"""detector가 실제로 관측한 범위(Evaluation Coverage)를 정의한다.

recall의 분모는 "이 detector가 탐지할 기회가 있었던 Ground Truth incident 수"여야 한다.
관측하지도 않은 기간·host·metric의 incident를 분모에 넣으면 recall이 실제보다 낮게
나오고, 그 숫자를 근거로 threshold를 조정하면 잘못된 방향으로 튜닝된다.

Coverage는 세 축으로 제한한다(모두 실제 입력 이벤트에서 측정한 값이며, 추측하지 않는다).
  1. 기간   - detector에 들어간 이벤트의 실제 timestamp 최소~최대
  2. host   - 실제 이벤트에 존재한 host 이름
  3. service - GAIA metric처럼 detector가 지원하는 metric만 통과시킨 뒤 남은 대상 이름
              (지원하지 않는 metric은 애초에 이벤트 자체가 필터링되므로, 지원 metric
               제약이 자동으로 coverage에 반영된다)

축을 알 수 없으면 None으로 두고 "제약 없음"으로 취급한다 - 모르는 것을 근거로
incident를 분모에서 빼지 않는다.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime

from src.models import NormalizedEvent

from .ground_truth import GroundTruthIncident


@dataclass(frozen=True)
class EvaluationCoverage:
    """detector가 실제로 관측한 범위."""

    dataset: str
    start_time: datetime
    end_time: datetime
    # None이면 "이 축으로는 제한하지 않음". 빈 집합은 "관측한 대상이 하나도 없음"이라는
    # 뜻이므로 None과 구분해서 다룬다.
    hosts: frozenset[str] | None = None
    services: frozenset[str] | None = None
    # anomaly_type별로 범위가 다를 때 쓰는 중첩 coverage. GAIA가 실제 예다.
    # dbservice1은 지원 metric 중 network 계열만 관측되므로 dbservice1의 cpu_anomalies는
    # 볼 수 있는 CPU metric이 없어 탐지 기회가 없었고, memory metric이 관측된 기간도
    # 전체 관측 기간과 다르다. 기간과 service를 함께 좁혀야 정확하다.
    # 키가 있으면 그 anomaly_type은 해당 중첩 coverage로만 판정한다(위임).
    # 키가 없으면 이 coverage의 축을 그대로 쓴다.
    by_anomaly_type: dict[str, EvaluationCoverage] | None = None
    # coverage를 무엇으로부터 계산했는지 사람이 확인할 수 있게 남긴다.
    event_count: int = 0
    note: str = ""

    def covers(self, incident: GroundTruthIncident) -> bool:
        """이 incident를 detector가 탐지할 기회가 있었는지 판단한다.

        기간은 "겹치면 범위 안"으로 본다(완전히 포함될 것을 요구하지 않는다). 일부라도
        관측했다면 탐지 기회가 있었다고 보는 쪽이 detector에게 불리한(=보수적인) 판정이다.

        host/service는 incident 쪽에 값이 있고 coverage 축이 정의돼 있는데 그 안에 없을
        때만 범위 밖으로 판정한다. incident 쪽이 None이면 비교할 근거가 없으므로 배제하지
        않는다.
        """
        if incident.dataset != self.dataset:
            return False
        if self.by_anomaly_type is not None:
            nested = self.by_anomaly_type.get(incident.anomaly_type)
            if nested is not None:
                return nested.covers(incident)
        if incident.end_time < self.start_time or incident.start_time > self.end_time:
            return False
        if self.hosts is not None and incident.host is not None and incident.host not in self.hosts:
            return False
        if (
            self.services is not None
            and incident.service is not None
            and incident.service not in self.services
        ):
            return False
        return True

    def duration_seconds(self) -> float:
        return (self.end_time - self.start_time).total_seconds()


def build_coverage_from_events(
    events: Iterable[NormalizedEvent],
    *,
    dataset: str,
    predicate: Callable[[NormalizedEvent], bool] | None = None,
    host_fn: Callable[[NormalizedEvent], str | None] | None = None,
    service_fn: Callable[[NormalizedEvent], str | None] | None = None,
    note: str = "",
) -> EvaluationCoverage | None:
    """detector에 들어가는 이벤트 스트림을 그대로 훑어 coverage를 측정한다.

    predicate는 detector 자신의 입력 필터와 같은 조건을 주면 된다(예: find_metric_anomaly는
    SUPPORTED_METRICS에 있는 metric만 본다). 그래야 "실제 지원하는 metric" 제약이 coverage에
    반영된다.

    host_fn/service_fn을 주지 않으면 그 축은 None(제약 없음)이 된다. GAIA metric처럼
    이벤트의 host가 사실 service 이름인 경우 service_fn으로 넘긴다 - Finding이 쓰는 축과
    같은 축으로 맞춰야 비교가 성립한다.

    이벤트를 list로 모으지 않고 한 번만 순회한다(GAIA는 1천만 건 이상이다).
    """
    start: datetime | None = None
    end: datetime | None = None
    hosts: set[str] | None = set() if host_fn is not None else None
    services: set[str] | None = set() if service_fn is not None else None
    count = 0

    for event in events:
        if event.dataset != dataset:
            continue
        if predicate is not None and not predicate(event):
            continue
        if event.timestamp is None:
            continue
        count += 1
        if start is None or event.timestamp < start:
            start = event.timestamp
        if end is None or event.timestamp > end:
            end = event.timestamp
        if hosts is not None:
            value = host_fn(event)  # type: ignore[misc]
            if value:
                hosts.add(value)
        if services is not None:
            value = service_fn(event)  # type: ignore[misc]
            if value:
                services.add(value)

    if start is None or end is None:
        return None

    return EvaluationCoverage(
        dataset=dataset,
        start_time=start,
        end_time=end,
        hosts=frozenset(hosts) if hosts is not None else None,
        services=frozenset(services) if services is not None else None,
        event_count=count,
        note=note,
    )


# GAIA run/의 주입 유형 -> 그 유형을 관측할 수 있는 metric의 resource 종류.
# find_metric_anomaly의 _MetricSpec.resource_kind와 같은 어휘를 쓴다.
GAIA_ANOMALY_TYPE_RESOURCE_KINDS: dict[str, str] = {
    "cpu_anomalies": "cpu",
    "memory_anomalies": "memory",
}


def build_gaia_metric_coverage(
    events: Iterable[NormalizedEvent],
) -> EvaluationCoverage | None:
    """find_metric_anomaly의 관측 범위를 measured value로 만든다.

    detector가 실제로 보는 metric(SUPPORTED_METRICS)만 통과시키고, 그 metric의
    resource 종류까지 반영해 anomaly_type별 service 집합을 따로 만든다. 그래서
    "CPU metric이 관측되지 않은 service의 cpu_anomalies"는 분모에서 빠진다.

    이 함수는 detector의 SUPPORTED_METRICS 테이블을 읽기만 한다 - Ground Truth가
    detector 쪽으로 흘러가지 않는다(의존 방향은 evaluation -> skills 한쪽뿐이다).
    """
    from src.skills.gaia_metric_anomaly import SUPPORTED_METRICS

    resource_kind_of = {name: spec.resource_kind for name, spec in SUPPORTED_METRICS.items()}
    # resource 종류별로 (service 집합, 기간)을 따로 모은다. 같은 metric 묶음 안에서도
    # 종류마다 관측된 service와 기간이 다르기 때문이다.
    per_kind: dict[str, dict] = {}
    overall_services: set[str] = set()
    overall_start: datetime | None = None
    overall_end: datetime | None = None
    total = 0

    for event in events:
        if event.dataset != "gaia" or event.timestamp is None:
            continue
        kind = resource_kind_of.get(event.extra.get("metric_name", ""))
        if kind is None:
            continue
        total += 1
        overall_services.add(event.host)
        if overall_start is None or event.timestamp < overall_start:
            overall_start = event.timestamp
        if overall_end is None or event.timestamp > overall_end:
            overall_end = event.timestamp
        slot = per_kind.setdefault(
            kind, {"services": set(), "start": event.timestamp, "end": event.timestamp, "n": 0}
        )
        slot["services"].add(event.host)
        slot["n"] += 1
        if event.timestamp < slot["start"]:
            slot["start"] = event.timestamp
        if event.timestamp > slot["end"]:
            slot["end"] = event.timestamp

    if overall_start is None or overall_end is None:
        return None

    by_anomaly_type: dict[str, EvaluationCoverage] = {}
    for anomaly_type, kind in GAIA_ANOMALY_TYPE_RESOURCE_KINDS.items():
        slot = per_kind.get(kind)
        if slot is None:
            # 이 resource 종류의 metric을 하나도 관측하지 못했다. service 집합을 빈 집합으로
            # 둬서 이 유형의 incident는 전부 범위 밖이 되게 한다(GAIA incident는 항상
            # service가 있다).
            by_anomaly_type[anomaly_type] = EvaluationCoverage(
                dataset="gaia",
                start_time=overall_start,
                end_time=overall_end,
                services=frozenset(),
                note=f"{kind} 계열 지원 metric이 관측되지 않았다",
            )
            continue
        by_anomaly_type[anomaly_type] = EvaluationCoverage(
            dataset="gaia",
            start_time=slot["start"],
            end_time=slot["end"],
            services=frozenset(slot["services"]),
            event_count=slot["n"],
            note=f"{kind} 계열 지원 metric이 실제 관측된 service와 기간",
        )

    return EvaluationCoverage(
        dataset="gaia",
        start_time=overall_start,
        end_time=overall_end,
        services=frozenset(overall_services),
        by_anomaly_type=by_anomaly_type,
        event_count=total,
        note="find_metric_anomaly 입력 = SUPPORTED_METRICS의 metric만. "
        "anomaly_type별 범위는 by_anomaly_type에 resource 종류 단위로 따로 측정한다.",
    )


def filter_incidents_by_coverage(
    incidents: Iterable[GroundTruthIncident], coverage: EvaluationCoverage | None
) -> tuple[list[GroundTruthIncident], list[GroundTruthIncident]]:
    """(범위 안, 범위 밖) incident로 나눈다.

    coverage가 None이면(관측 이벤트가 없어 측정 자체가 불가능) 제한하지 않고 전부 범위
    안으로 둔다 - coverage를 측정하지 못한 것을 근거로 분모를 줄이지 않는다.
    """
    if coverage is None:
        return list(incidents), []
    inside: list[GroundTruthIncident] = []
    outside: list[GroundTruthIncident] = []
    for incident in incidents:
        (inside if coverage.covers(incident) else outside).append(incident)
    return inside, outside
