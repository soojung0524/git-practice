"""GAIA MicroSS trace(gaia_trace) 이벤트에서 지연(latency) 이상을 찾는 Analysis Skill.

실제 데이터(dbservice1 1,437,954 span, webservice2 1,457,274 span)로 확인한 duration
분포:
    dbservice1: p50=0.16s p90=0.39s p99=1.36s p999=6.84s max=8598.74s
    webservice2: p50=0.85s p90=1.27s p99=2.48s p999=11.51s max=62.36s

호출을 시작하는 서비스(webservice*)든 호출을 받는 서비스(dbservice1 등)든 자기 자신의
duration 분포를 갖고 있어, root span으로 제한하지 않고 host(=service)별 전체 span을
그대로 baseline 대상으로 삼는다(parent_id로 호출 그래프를 구성하는 것은 이 단계의
범위가 아니다).
"""

from __future__ import annotations

from collections.abc import Iterable

from src.models import Finding, NormalizedEvent, make_finding_id
from src.skills.aggregation import (
    DEFAULT_MAX_EVIDENCE,
    cluster_by_time_gap,
    collect_values_by_group,
    percentile,
    select_representative_evidence,
)

DETECTOR = "find_latency_anomaly"

_MIN_SAMPLES = 100
_BASELINE_PERCENTILE = 0.99
_MIN_RATIO = 2.0
# trace span은 요청마다 발생해 촘촘하므로, 지속되는 지연 구간을 하나로 묶기 위한 간격을
# 짧게(60초) 둔다.
_MAX_EPISODE_GAP_SECONDS = 60.0

# 절대 지속시간(초) 기준. 통계적으로 몇 배 튀었는지와 무관하게, 응답이 실제로 몇 초/몇십초
# 걸렸는지는 그 자체로 사용자 체감 지연의 심각도를 나타낸다고 보수적으로 판단한다.
_HIGH_DURATION_SECONDS = 30.0
_MEDIUM_DURATION_SECONDS = 5.0


def find_latency_anomaly(
    events: Iterable[NormalizedEvent], *, dataset: str = "gaia"
) -> list[Finding]:
    """서비스(host)별 trace span duration이 그 서비스 자신의 baseline(p99)보다
    뚜렷하게 긴 구간을 찾는다.

    baseline: 서비스별로 관측된 duration_seconds 전체의 p99. 다른 서비스나 Ground
    Truth(run/)는 baseline에 쓰지 않는다.

    severity: ratio(baseline 대비 몇 배인지)는 탐지 트리거로만 쓰고, severity는 실제
    관측된 절대 지속시간(초)으로 정한다. 같은 2배라도 "0.3초 -> 0.6초"와
    "1초 -> 30초"는 체감 심각도가 다르기 때문이다. 이 detector 혼자서는 그 지연이
    실제 장애로 이어졌는지 알 수 없으므로 critical은 매기지 않는다.
    """
    groups = collect_values_by_group(
        events,
        group_key=lambda e: e.host,
        value_fn=lambda e: e.extra.get("duration_seconds"),
        predicate=lambda e: e.source_type == "gaia_trace",
    )

    findings: list[Finding] = []
    for host, group in groups.items():
        if len(group.values) < _MIN_SAMPLES:
            continue

        baseline = percentile(group.values, _BASELINE_PERCENTILE)
        if baseline <= 0:
            continue

        # flagged될 샘플은 이 group에서 값(duration)이 큰 쪽에 있을 수밖에 없으므로,
        # evidence_candidates(값이 큰 상위 N개)만 확인해도 전체를 다 봤을 때와 같은
        # 결과가 나온다 — collect_values_by_group 문서 참고.
        flagged = [s for s in group.evidence_candidates if s.value / baseline >= _MIN_RATIO]
        if not flagged:
            continue

        for episode in cluster_by_time_gap(flagged, max_gap_seconds=_MAX_EPISODE_GAP_SECONDS):
            peak_sample = max(episode, key=lambda s: (s.value, s.timestamp, s.evidence.event_id))
            peak_duration = peak_sample.value
            ratio = peak_duration / baseline

            if peak_duration >= _HIGH_DURATION_SECONDS:
                severity = "high"
            elif peak_duration >= _MEDIUM_DURATION_SECONDS:
                severity = "medium"
            else:
                severity = "low"

            start_time = min(s.timestamp for s in episode)
            end_time = max(s.timestamp for s in episode)

            findings.append(
                Finding(
                    finding_id=make_finding_id(
                        detector=DETECTOR, dataset=dataset, group_key=host, start_time=start_time
                    ),
                    dataset=dataset,
                    category="performance",
                    finding_type="service_latency_spike",
                    start_time=start_time,
                    end_time=end_time,
                    host=None,
                    service=host,
                    severity=severity,
                    summary=(
                        f"{host}에서 {start_time.isoformat()}부터 응답 시간이 "
                        f"baseline p99({baseline:.3f}초)의 {ratio:.1f}배인 {peak_duration:.3f}초까지 관측됨"
                    ),
                    metrics={
                        "duration_seconds_peak": peak_duration,
                        "baseline_p99_seconds": baseline,
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
