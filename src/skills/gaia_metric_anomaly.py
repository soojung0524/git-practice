"""GAIA MicroSS metric(gaia_metric) 이벤트에서 리소스 사용량 이상을 찾는 Analysis Skill.

GAIA의 metric_name은 2,215개 이상 관측되어(gaia_metric.py 참고) 전부를 일괄 처리할 수
없다. 게다가 metric마다 값의 성격이 다르다:
  - gauge: 매 시점의 순간 측정값(예: CPU 사용률, 메모리 점유량) — baseline 대비 편차로
    이상을 판단할 수 있다.
  - cumulative counter: 계속 누적되는 값(예: diskio service_time) — 원시값을 그대로
    baseline과 비교하면 "정상적으로 시간이 지나 값이 커진 것"과 "실제 이상"을 구분할 수
    없다. rate/delta로 변환해야 하는데, 이번 1차 구현 범위에는 포함하지 않는다.
  - constant/no-signal: 표본 전체가 0이라 애초에 비교할 분포가 없다.

그래서 이번 1차 구현은 실제로 값을 뽑아 분포를 확인한 9개 metric_name 중, 이름과
실측 분포 양쪽으로 gauge라고 판단할 수 있는 것만 명시적으로 지원한다. 나머지는
SUPPORTED_METRICS에 넣지 않고 아래 EXCLUDED_METRICS에 사유를 남긴다(추측해서
포함하지 않는다).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from src.models import Finding, NormalizedEvent, make_finding_id
from src.skills.aggregation import (
    DEFAULT_MAX_EVIDENCE,
    cluster_by_time_gap,
    collect_values_by_group,
    percentile,
    select_representative_evidence,
)

DETECTOR = "find_metric_anomaly"


@dataclass(frozen=True)
class _MetricSpec:
    category: str  # Finding.category
    resource_kind: str  # finding_type 접미사에 쓰는 리소스 종류(cpu/memory/network/disk)
    # True면 0~1(또는 0~100%) 사이의 절대적인 상한이 있는 지표라, severity를 절대값
    # 기준으로도 판단할 수 있다(예: 사용률 95% 이상은 baseline과 무관하게 위험하다는
    # 판단이 가능). False면 용량 기준(총 메모리, NIC 대역폭 등)을 데이터에서 알 수 없어
    # 절대값으로 severity를 매길 근거가 없다.
    has_utilization_ceiling: bool


# 실제 표본(9개 metric_name, 총 397,346건)에서 확인한 값 범위를 근거로 선정했다.
SUPPORTED_METRICS: dict[str, _MetricSpec] = {
    # p50=0.53 p90=0.77 p99=0.78 max=1.0 — 0~1 사이 CPU 사용률 gauge.
    "system_cpu_total_norm_pct": _MetricSpec("resource", "cpu", True),
    # p50=0 p90=0.0098 p99=0.00996 max=0.0286 — 73.9%가 0이지만 나머지 구간에 변동이
    # 있어 constant는 아니다. 0~1 사이 CPU 사용률 gauge.
    "docker_cpu_user_pct": _MetricSpec("resource", "cpu", True),
    # p50=9.11e8 p90=1.32e9 p99=1.92e9 max=2.46e9(bytes) — 점유 메모리 gauge. 총 메모리
    # 용량을 알 수 없어 절대 상한 기준(has_utilization_ceiling)은 두지 않는다.
    "docker_memory_stats_active_anon": _MetricSpec("resource", "memory", False),
    # p50=13.8 p90=17.6 p99=20.7 max=578.4(packets) — 수신 패킷 수. 누적이라면 기간이
    # 지날수록 계속 커져야 하는데 0~578 범위에 갇혀 있어(수 주 관측) 매 수집 주기(30초)
    # 동안의 수신량으로 보고 gauge로 취급한다.
    "docker_network_in_packets": _MetricSpec("network", "network", False),
    # p50=0.0412 p90=0.052 p99=0.0539 max=0.0541 — 디스크 사용률(비율) gauge.
    "system_filesystem_used_pct": _MetricSpec("resource", "disk", True),
}

# 실제 데이터로 값을 확인했지만 이번 1차 구현에서는 지원하지 않는 metric.
# (코드에서 쓰이지 않는 문서용 dict — 보류 사유를 코드 옆에 남겨 둔다.)
EXCLUDED_METRICS: dict[str, str] = {
    "docker_cpu_core_5_norm_pct": "constant/no-signal: 표본 74,715건 중 100%가 0.",
    "system_network_summary_icmp_InAddrMasks": "constant/no-signal: 표본 13,465건 중 100%가 0.",
    "docker_diskio_summary_service_time": (
        "cumulative counter로 추정. 값이 3.78e10~4.72e10 범위에서 거의 항상 최댓값 "
        "근처에 머물러(상대표준편차 약 8.6%) 계속 누적되는 diskstats류 카운터의 "
        "전형적인 모양이다. rate/delta 변환이 필요해 이번 구현 범위 밖으로 둔다(후속 작업)."
    ),
    "0.0.0.2_system_process_memory_share": (
        "의미 불명확. 이름만으로 gauge(점유율)인지 다른 의미인지 확정할 수 없고, "
        "표본의 43.2%가 정확히 0이면서 나머지는 0~6.05e7까지 넓게 퍼져 있어 데이터로도 "
        "판단하기 어렵다. 추측해서 포함하지 않는다."
    ),
}

_MIN_SAMPLES = 30
_BASELINE_PERCENTILE = 0.99
_MIN_RATIO = 2.0
# GAIA metric 수집 주기가 약 30초라, 몇 개 표본이 비어도 같은 이상 구간으로 보기 위해
# 5분(300초)을 episode 간격으로 둔다.
_MAX_EPISODE_GAP_SECONDS = 300.0

_UTILIZATION_HIGH = 0.95
_UTILIZATION_MEDIUM = 0.80


def find_metric_anomaly(
    events: Iterable[NormalizedEvent], *, dataset: str = "gaia"
) -> list[Finding]:
    """(host, metric_name)별로 SUPPORTED_METRICS에 있는 metric만 골라, 그 자신의
    baseline(p99) 대비 뚜렷하게 튄 구간을 찾는다.

    baseline: 같은 (host, metric_name) 쌍의 관측값 전체에서 p99를 구한다. 별도의
    "정상 기간" 라벨이 없으므로 관측된 값 자체의 상위 분포를 기준으로 삼는다(Ground
    Truth 미사용).

    severity: 통계적 편차(ratio)만으로 severity를 정하지 않는다. system_cpu_total_norm_pct나
    system_filesystem_used_pct처럼 값 자체가 0~1 사이 사용률이라 절대적인 의미가 있는
    지표는 실제 관측된 최고값(예: 사용률 95% 이상)으로 severity를 매긴다. 반대로
    메모리 바이트 수나 패킷 수처럼 "얼마가 위험한 절대치인지" 데이터로 알 수 없는
    지표는, 통계적으로 아무리 크게 튀어도 low로 보수적으로 둔다.
    """
    predicate_metrics = SUPPORTED_METRICS

    groups = collect_values_by_group(
        events,
        group_key=lambda e: (e.host, e.extra.get("metric_name")),
        value_fn=lambda e: e.extra.get("value"),
        predicate=lambda e: e.source_type == "gaia_metric"
        and e.extra.get("metric_name") in predicate_metrics,
    )

    findings: list[Finding] = []
    for (host, metric_name), group in groups.items():
        if len(group.values) < _MIN_SAMPLES:
            continue
        spec = SUPPORTED_METRICS[metric_name]

        baseline = percentile(group.values, _BASELINE_PERCENTILE)
        if baseline <= 0:
            continue

        # flagged될 샘플은 이 group에서 값이 큰 쪽에 있을 수밖에 없으므로(baseline 대비
        # ratio로 정의되는 이상), evidence_candidates(값이 큰 상위 N개)만 확인하면
        # 전체를 다 봤을 때와 같은 결과가 나온다 — collect_values_by_group 문서 참고.
        flagged = [s for s in group.evidence_candidates if s.value / baseline >= _MIN_RATIO]
        if not flagged:
            continue

        for episode in cluster_by_time_gap(flagged, max_gap_seconds=_MAX_EPISODE_GAP_SECONDS):
            peak_sample = max(episode, key=lambda s: (s.value, s.timestamp, s.evidence.event_id))
            peak_value = peak_sample.value
            ratio = peak_value / baseline

            if spec.has_utilization_ceiling:
                if peak_value >= _UTILIZATION_HIGH:
                    severity = "high"
                elif peak_value >= _UTILIZATION_MEDIUM:
                    severity = "medium"
                else:
                    severity = "low"
            else:
                # 용량 기준을 알 수 없어 통계적 편차만으로는 severity를 올리지 않는다.
                severity = "low"

            start_time = min(s.timestamp for s in episode)
            end_time = max(s.timestamp for s in episode)
            finding_type = f"{spec.resource_kind}_usage_anomaly"

            findings.append(
                Finding(
                    finding_id=make_finding_id(
                        detector=DETECTOR,
                        dataset=dataset,
                        group_key=f"{host}:{metric_name}",
                        start_time=start_time,
                    ),
                    dataset=dataset,
                    category=spec.category,
                    finding_type=finding_type,
                    start_time=start_time,
                    end_time=end_time,
                    host=None,
                    service=host,
                    severity=severity,
                    summary=(
                        f"{host}의 {metric_name} 값이 {start_time.isoformat()}부터 "
                        f"baseline p99({baseline:.4g})의 {ratio:.1f}배인 {peak_value:.4g}까지 관측됨"
                    ),
                    metrics={
                        "metric_name": metric_name,
                        "peak_value": peak_value,
                        "baseline_p99": baseline,
                        "ratio": ratio,
                        "sample_count": len(episode),
                        "evidence_count": len(episode),
                    },
                    evidence=select_representative_evidence(episode, max_count=DEFAULT_MAX_EVIDENCE),
                    entities={"service": [host]},
                    detector=DETECTOR,
                )
            )

    findings.sort(key=lambda f: (f.start_time, f.finding_id))
    return findings
