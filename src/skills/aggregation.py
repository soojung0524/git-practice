"""Analysis Skill들이 공통으로 쓰는 시간창 집계 / baseline / evidence 선택 함수.

이 모듈은 "무엇이 이상인가"를 모른다. group_key로 나누고, 집계값(count/value)을
구하고, baseline과 ratio를 계산하고, 대표 evidence를 고르는 계산만 담당한다.
그 결과를 Finding의 category/finding_type/severity로 해석하는 것은 각 detector
(find_*)의 책임이다 — Finding의 "의미"는 이 모듈이 아니라 detector가 정한다.

NormalizedEvent 스트림은 여러 파일을 이어 붙인 것이라 시간순으로 정렬되어 있다는
보장이 없다(src/models/event_store.py의 stream_to_dated_files 설명 참고). 그래서
아래 함수들은 입력 순서를 가정하지 않고, 전체를 한 번만 순회하며 (group_key, ...)
별로 필요한 최소 정보만 dict에 쌓는다. 원본 NormalizedEvent나 raw 텍스트, extra
전체를 복사해 들고 있지 않는다.

메모리 사용량 특성은 함수마다 다르다.
  - count_by_window: 창별 개수/합(value_sum)은 O(1)이라 (group, window) 조합 수에만
    비례한다. evidence 후보(samples)는 기본적으로 매칭된 이벤트 수에 비례해 늘어나지만,
    collect_evidence_for로 "실제 evidence로 쓰일 이벤트"만 고르면 그만큼 줄어든다.
  - collect_values_by_group: baseline(percentile)을 정확히 계산해야 해서 숫자 값
    자체는 매칭된 이벤트 수만큼 보관하지만(GroupValues.values, array.array로 압축),
    EvidenceReference가 필요한 객체(evidence_candidates)는 값이 큰 상위
    DEFAULT_MAX_CANDIDATES_PER_GROUP개로만 제한한다 — 자세한 설명은 GroupValues와
    collect_values_by_group의 docstring 참고.
"""

from __future__ import annotations

import array
import heapq
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from src.models import EvidenceReference, NormalizedEvent

# Finding 하나에 담을 대표 evidence 최대 개수. 전체 매칭 건수는 metrics["evidence_count"]에
# 별도로 남기므로, 여기서는 사람이 근거를 확인하는 데 필요한 만큼만 제한적으로 남긴다.
DEFAULT_MAX_EVIDENCE = 5


def evidence_from_event(event: NormalizedEvent) -> EvidenceReference:
    return EvidenceReference(
        source_type=event.source_type,
        source_file=event.source_path,
        line_number=event.line_number,
        timestamp=event.timestamp,
        event_id=event.event_id,
    )


@dataclass
class ValueSample:
    """group 안에서 관측된 값 하나. 대표 evidence 선택과 baseline 계산의 최소 단위."""

    value: float
    timestamp: datetime
    evidence: EvidenceReference


@dataclass
class WindowCount:
    group_key: Any
    window_start: datetime
    window_end: datetime
    count: int = 0
    # value_fn이 돌려준 값의 합. count_by_window를 호출하는 detector가 "이 창의
    # value_fn 평균/비율이 얼마인가"를 구할 때, samples 전체를 다시 순회하지 않고
    # value_sum / count로 바로 구할 수 있게 한다(아래 collect_evidence_for 참고).
    value_sum: float = 0.0
    samples: list[ValueSample] = field(default_factory=list)


def percentile(values: Sequence[float], p: float) -> float:
    """values의 p분위수(0<=p<=1)를 반환한다. 정렬되어 있지 않아도 된다.

    이전 단계(실제 데이터 분포 분석)에서 쓴 것과 같은 방식(순위 기반, 보간 없음)이라
    baseline 값이 그때 리포트한 실측 수치와 그대로 대응된다.
    """
    if not values:
        raise ValueError("percentile of empty sequence")
    ordered = sorted(values)
    idx = min(int(len(ordered) * p), len(ordered) - 1)
    return ordered[idx]


def count_by_window(
    events: Iterable[NormalizedEvent],
    *,
    window_seconds: int,
    group_key: Callable[[NormalizedEvent], Any],
    predicate: Callable[[NormalizedEvent], bool] | None = None,
    value_fn: Callable[[NormalizedEvent], float] | None = None,
    collect_evidence_for: Callable[[NormalizedEvent], bool] | None = None,
) -> dict[tuple[Any, datetime], WindowCount]:
    """이벤트를 (group_key(event), 고정 길이 시간창) 별로 센다.

    timestamp가 없는 이벤트는 시간창을 정할 수 없으므로 건너뛴다(버리는 것이 아니라
    이 집계의 대상이 아닐 뿐이다).

    value_fn을 주면 각 이벤트마다 부가 수치(예: 4xx/5xx면 1.0, 아니면 0.0)를 함께
    기록한다. 이 값 자체는 count_by_window가 해석하지 않는다 — 그 값들의 합/평균을
    어떻게 쓸지는(예: 에러 비율) 호출하는 detector가 결정한다. 창별 합은
    WindowCount.value_sum에 항상 쌓이므로, "그 값이 특별한 이벤트(예: ERROR)만
    evidence로 남기고 싶다"는 경우에도 count/value_sum 자체는 매칭된 이벤트 전체를
    정확히 반영한다.

    collect_evidence_for로 "이 이벤트를 evidence 후보로 남길지"를 따로 정할 수 있다.
    predicate로 이미 걸러진 이벤트 중에서도, 실제로 evidence에 쓰일 가능성이 있는
    이벤트(예: level이 ERROR인 것)만 골라 samples에 담고 싶을 때 쓴다 — 그렇지 않으면
    (기본값 None) 매칭된 이벤트 전부를 samples에 담는다. GAIA 분당 로그처럼 창 하나에
    수백 건이 섞여 있는데 그중 극히 일부만 evidence로 쓰이는 경우, 이 옵션으로 저장량을
    크게 줄일 수 있다(예: 로그 1건당 몇백 바이트인 EvidenceReference를 전부가 아니라
    실제로 쓰이는 것만 만든다).
    """
    buckets: dict[tuple[Any, datetime], WindowCount] = {}

    for event in events:
        if predicate is not None and not predicate(event):
            continue
        if event.timestamp is None:
            continue

        key = group_key(event)
        # 이벤트의 timestamp는 파서 단계에서 항상 tzinfo=utc로 통일되어 있다는 것이
        # 프로젝트 전체의 전제다(각 parser 모듈 docstring 참고).
        epoch = event.timestamp.astimezone(timezone.utc).timestamp()
        window_index = int(epoch // window_seconds)
        window_start = datetime.fromtimestamp(window_index * window_seconds, tz=timezone.utc)
        window_end = datetime.fromtimestamp((window_index + 1) * window_seconds, tz=timezone.utc)

        bucket_key = (key, window_start)
        bucket = buckets.get(bucket_key)
        if bucket is None:
            bucket = WindowCount(group_key=key, window_start=window_start, window_end=window_end)
            buckets[bucket_key] = bucket

        value = value_fn(event) if value_fn is not None else 0.0
        bucket.count += 1
        bucket.value_sum += value
        if collect_evidence_for is None or collect_evidence_for(event):
            bucket.samples.append(
                ValueSample(value=value, timestamp=event.timestamp, evidence=evidence_from_event(event))
            )

    return buckets


def compute_count_baseline(
    window_counts: Sequence[int],
    *,
    total_windows: int,
    percentile_value: float = 0.99,
    min_observations: int = 30,
) -> float | None:
    """count_by_window 결과 중 "이벤트가 1건이라도 있었던 창"의 count 목록과,
    관측 기간 전체 창 수(0건짜리 창 포함)를 받아 baseline을 계산한다.

    0건 창을 빼고 percentile을 구하면 트래픽이 뜸한 시간대의 0~1건짜리 정상 상태가
    반영되지 않아 baseline이 실제보다 높게 잡힌다. total_windows에서 관측된 창 수를
    뺀 만큼을 "논리적으로 0인 창"으로 percentile 계산에 포함하되, 그 0들을 실제
    리스트로 만들지는 않는다(메모리 낭비 방지).

    total_windows가 min_observations 미만이면(관측 기간이 너무 짧으면) baseline을
    신뢰할 수 없다는 뜻으로 None을 돌려준다 — 이 경우 호출자는 탐지를 건너뛰어야 한다.
    """
    n_observed = len(window_counts)
    n_zero = total_windows - n_observed
    if n_zero < 0:
        raise ValueError("total_windows must be >= len(window_counts)")
    if total_windows < min_observations:
        return None

    ordered = sorted(window_counts)
    idx = min(int(total_windows * percentile_value), total_windows - 1)
    if idx < n_zero:
        return 0.0
    return float(ordered[idx - n_zero])


# baseline(percentile)이 "이 group의 상위 몇 % 안에 드는가"로 정의되는 이상, flagged될
# 샘플은 항상 그 group에서 값이 큰 쪽에 있을 수밖에 없다. 그래서 evidence 후보를
# group당 이 개수만큼(값이 큰 순으로)만 들고 있어도, 실제 flagged 개수가 이 한도를
# 넘지 않는 한 최종 결과(어떤 episode가 만들어지는지, evidence가 무엇인지)는 전체를
# 들고 있을 때와 완전히 같다. 실측(GAIA trace 약 290만 건, find_latency_anomaly)에서
# 전체 flagged 샘플이 두 group 합쳐 7,248건이었던 것에 견줘 넉넉한 한도를 잡았다.
DEFAULT_MAX_CANDIDATES_PER_GROUP = 50_000


@dataclass
class GroupValues:
    """group_key 하나에 대해 collect_values_by_group이 모은 결과.

    values: 그 group에서 관측된 수치값 전체(percentile을 정확히 계산하기 위함).
        ValueSample 객체가 아니라 array.array('d', ...)로 담아, 값 하나당 Python
        float 객체(약 24바이트) + 리스트 슬롯 대신 8바이트 C double로 압축 저장한다.
    evidence_candidates: 값이 큰 순으로 최대 DEFAULT_MAX_CANDIDATES_PER_GROUP개까지만
        담은 ValueSample(evidence 포함) 목록. baseline 대비 ratio로 "이상"을 정의하는
        detector는 이 목록에서만 flagged 샘플을 찾으면 된다(위 설명 참고).
    """

    values: array.array
    evidence_candidates: list[ValueSample] = field(default_factory=list)


def collect_values_by_group(
    events: Iterable[NormalizedEvent],
    *,
    group_key: Callable[[NormalizedEvent], Any],
    value_fn: Callable[[NormalizedEvent], float | None],
    predicate: Callable[[NormalizedEvent], bool] | None = None,
    max_candidates_per_group: int = DEFAULT_MAX_CANDIDATES_PER_GROUP,
) -> dict[Any, GroupValues]:
    """group_key별로 (percentile 계산용 값 전체, evidence 후보)를 모은다.

    한 번만 순회하며, group별로:
      1. 숫자 값 자체는 빠짐없이 전부 압축 저장한다(baseline이 실제 분포 그대로
         정확해야 하므로 표본을 버리거나 근사하지 않는다).
      2. NormalizedEvent 전체나 raw 텍스트, EvidenceReference는 값이 큰 상위
         max_candidates_per_group개에 대해서만 만든다(최소 힙으로 유지) — 어차피
         evidence로 쓰일 가능성이 있는 샘플은 그 group에서 값이 큰 쪽뿐이기 때문에,
         나머지 대다수(예: GAIA trace에서 baseline 근처의 정상 span 수백만 건)는
         ValueSample/EvidenceReference 객체를 아예 만들지 않는다.

    이 두 가지를 합쳐, "그룹당 수백만 건" 규모에서도 detector가 들고 있어야 하는
    메모리가 원본 이벤트 수에 거의 비례하지 않게 만든다.
    """
    groups: dict[Any, GroupValues] = {}
    heaps: dict[Any, list[tuple[float, int, ValueSample]]] = {}
    seq_counters: dict[Any, int] = {}

    for event in events:
        if predicate is not None and not predicate(event):
            continue
        if event.timestamp is None:
            continue
        value = value_fn(event)
        if value is None:
            continue

        key = group_key(event)
        group = groups.get(key)
        if group is None:
            group = GroupValues(values=array.array("d"))
            groups[key] = group
            heaps[key] = []
            seq_counters[key] = 0

        group.values.append(value)

        heap = heaps[key]
        # heapq 튜플 비교가 ValueSample까지 내려가 비교하려 들지 않도록(비교 불가능한
        # 객체라 에러가 난다), (value, seq, sample) 순으로 두고 seq를 tie-break로 쓴다.
        seq_counters[key] += 1
        seq = seq_counters[key]

        if len(heap) < max_candidates_per_group:
            sample = ValueSample(value=value, timestamp=event.timestamp, evidence=evidence_from_event(event))
            heapq.heappush(heap, (value, seq, sample))
        elif value > heap[0][0]:
            sample = ValueSample(value=value, timestamp=event.timestamp, evidence=evidence_from_event(event))
            heapq.heapreplace(heap, (value, seq, sample))
        # value <= heap[0][0]이면 상위 K개에 들 수 없는 값이라 ValueSample조차 만들지
        # 않는다 — 대다수(baseline 근처 정상값)가 여기 해당한다.

    for key, heap in heaps.items():
        groups[key].evidence_candidates = [item[2] for item in heap]

    return groups


def cluster_by_time_gap(samples: Sequence[ValueSample], *, max_gap_seconds: float) -> list[list[ValueSample]]:
    """시간순 정렬 후, 연속된 두 샘플 사이 간격이 max_gap_seconds를 넘으면 새 구간(episode)으로
    끊는다.

    수치 이상 탐지(metric/latency)에서 "이상 시점 하나당 Finding 하나"가 되지 않도록,
    가까운 시간에 몰린 이상 샘플들을 하나의 지속 구간으로 묶기 위한 함수다.
    """
    if not samples:
        return []
    ordered = sorted(samples, key=lambda s: (s.timestamp, s.evidence.event_id))
    episodes: list[list[ValueSample]] = [[ordered[0]]]
    for prev, curr in zip(ordered, ordered[1:]):
        gap = (curr.timestamp - prev.timestamp).total_seconds()
        if gap <= max_gap_seconds:
            episodes[-1].append(curr)
        else:
            episodes.append([curr])
    return episodes


def select_representative_evidence(
    samples: Sequence[ValueSample], *, max_count: int = DEFAULT_MAX_EVIDENCE
) -> list[EvidenceReference]:
    """samples 중 대표 evidence를 최대 max_count개, 결정적으로 고른다.

    선택 기준: 값이 가장 큰(peak) 샘플, 가장 이른 샘플, 가장 늦은 샘플을 우선 포함하고
    남는 자리를 시간순으로 채운다. 동점은 (timestamp, event_id) 순으로 깨서 같은
    입력이면 항상 같은 결과가 나오게 한다(재실행해도 같은 Finding.evidence가 나와야
    한다는 요구사항).
    """
    if not samples:
        return []
    ordered = sorted(samples, key=lambda s: (s.timestamp, s.evidence.event_id))
    peak = max(ordered, key=lambda s: (s.value, s.timestamp, s.evidence.event_id))

    picked: list[ValueSample] = []
    seen_ids: set[str] = set()
    for candidate in (ordered[0], peak, ordered[-1]):
        if candidate.evidence.event_id not in seen_ids:
            picked.append(candidate)
            seen_ids.add(candidate.evidence.event_id)

    for candidate in ordered:
        if len(picked) >= max_count:
            break
        if candidate.evidence.event_id not in seen_ids:
            picked.append(candidate)
            seen_ids.add(candidate.evidence.event_id)

    picked.sort(key=lambda s: (s.timestamp, s.evidence.event_id))
    return [s.evidence for s in picked[:max_count]]
