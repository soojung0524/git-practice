"""Agent Skill wrapper들이 공통으로 쓰는 입력 범위 지정 유틸리티.

이 모듈은 탐지를 하지 않는다. 하는 일은 두 가지뿐이다.
  1. 호출자가 지정한 분석 입력 범위(dataset/host/service/기간/source_type)로 이벤트를 걸러낸다.
  2. 그 결과를 source_type별로 나눠 담아, 각 detector가 자기 입력만 받게 한다.

threshold 계산, anomaly 판정, severity 재판정, Finding 변경은 일절 하지 않는다.

주의: 이것은 "결과 필터"가 아니라 "분석 입력 범위 지정"이다. 범위를 좁히면 그 범위의
이벤트만 detector에 들어가고, baseline(percentile)도 그 범위에서 다시 계산된다.
각 SKILLS.md 제약사항에 같은 내용을 명시해 두었다.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from src.models import NormalizedEvent


def partition_events(
    events: Iterable[NormalizedEvent],
    *,
    keep_source_types: Iterable[str],
    dataset: str | None = None,
    host: str | None = None,
    service: str | None = None,
    start_time: datetime | None = None,
    end_time: datetime | None = None,
    source_types: Iterable[str] | None = None,
) -> dict[str, list[NormalizedEvent]]:
    """이벤트를 한 번만 순회해 범위 조건을 적용하고 source_type별로 나눠 담는다.

    keep_source_types
        이 Skill이 실제로 쓰는 source_type. 여기에 없는 source_type의 이벤트는 애초에
        담지 않는다(Skill이 쓰지 않는 이벤트를 메모리에 들고 있지 않기 위해서다).
    source_types
        호출자가 더 좁히고 싶을 때 주는 부분집합. keep_source_types와 교집합만 남는다.
        교집합이 비면 그 detector는 호출되지 않는다(가짜 결과를 만들지 않는다).
    dataset
        NormalizedEvent.dataset이 이 값인 이벤트만 남긴다. Finding.dataset을 새로
        지정하는 용도가 아니다 - Finding의 provenance는 기존 detector가 정한 값을
        그대로 쓴다.
    host
        NormalizedEvent.host와 비교한다.
    service
        GAIA 이벤트는 loader가 CSV의 service/service_name 컬럼을 host에 담기 때문에
        service 이름이 NormalizedEvent.host에 들어 있다. 그래서 host와 같은 필드를
        비교한다. russellmitchell 이벤트에는 service 개념이 없으므로(host는 장비 이름)
        russellmitchell 분석에 service를 지정하면 아무 이벤트도 남지 않는다.
    start_time / end_time
        경계 포함(inclusive)으로 비교한다. 둘 중 하나라도 지정되면 timestamp가 없는
        이벤트(파싱 단계에서 시각을 얻지 못한 gaia_log unstructured 행 등)는 범위 안에
        있다고 확인할 수 없으므로 제외한다. 기간을 지정하지 않으면 그대로 통과시켜
        detector가 판단하게 둔다.

    반환값은 선택된 source_type마다 키가 반드시 있는 dict다(해당 이벤트가 없으면 빈
    리스트). 호출자가 키 존재 여부를 따로 확인하지 않아도 되게 한 것이다.
    """
    selected = set(keep_source_types)
    if source_types is not None:
        selected &= set(source_types)

    buckets: dict[str, list[NormalizedEvent]] = {name: [] for name in selected}
    if not selected:
        return buckets

    require_timestamp = start_time is not None or end_time is not None

    for event in events:
        if event.source_type not in selected:
            continue
        if dataset is not None and event.dataset != dataset:
            continue
        if host is not None and event.host != host:
            continue
        if service is not None and event.host != service:
            continue
        if require_timestamp:
            if event.timestamp is None:
                continue
            if start_time is not None and event.timestamp < start_time:
                continue
            if end_time is not None and event.timestamp > end_time:
                continue
        buckets[event.source_type].append(event)

    return buckets
