"""GAIA MicroSS business 로그(gaia_log) 이벤트에서 ERROR 비율 급증을 찾는 Analysis Skill.

실제 데이터(webservice1, 7,285,291건 중 구조화된 gaia_log_entry)로 확인한 특성:
    level 분포: INFO 98.12%, ERROR 1.88%(137,065건)
    분당 ERROR 건수: 29,915분 중 28,433분(95%)에 1건 이상 존재. mean=4.8 median=3.0
        p90=8 p99=41

russellmitchell의 apache 5xx(전체 기간 단 1건)와 달리, GAIA는 에러가 "거의 없다가
가끔 튀는" 게 아니라 항상 어느 정도 존재하는 ambient baseline이다. 그래서 "에러가
있다/없다"가 아니라 분당 로그 중 ERROR가 차지하는 비율이 그 서비스 자신의 평소
수준(p99)보다 뚜렷하게 높은 구간을 찾는다. 원시 건수가 아니라 비율을 쓰는 이유는
분당 전체 로그량 자체가 변하면 ERROR 건수도 같이 늘어날 수 있어, 건수만 보면 "트래픽
증가"와 "에러 비율 증가"를 구분할 수 없기 때문이다.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from src.models import Finding, NormalizedEvent, make_finding_id
from src.skills.aggregation import (
    DEFAULT_MAX_EVIDENCE,
    WindowCount,
    count_by_window,
    percentile,
    select_representative_evidence,
)

DETECTOR = "find_log_error_spike"

_WINDOW_SECONDS = 60
# 이 서비스(host)에서 최소 이만큼의 분(창)이 관측되어야 error rate baseline을 신뢰한다.
_MIN_WINDOWS = 100
_BASELINE_PERCENTILE = 0.99
_MIN_RATIO = 2.0

# 절대 에러 비율 기준. 같은 ratio라도 "1% -> 3%"와 "10% -> 60%"는 체감 심각도가
# 다르므로, severity는 baseline 대비 배율이 아니라 그 구간에서 실제로 관측된 에러
# 비율(절대값)로 정한다.
_HIGH_ERROR_RATE = 0.5
_MEDIUM_ERROR_RATE = 0.2


def _is_error(event: NormalizedEvent) -> float:
    return 1.0 if event.extra.get("level") == "ERROR" else 0.0


def find_log_error_spike(
    events: Iterable[NormalizedEvent], *, dataset: str = "gaia"
) -> list[Finding]:
    """서비스(host)별 분당 ERROR 로그 비율이 그 서비스 자신의 baseline(p99)보다
    뚜렷하게 높은 구간을 찾는다.

    baseline: 서비스별로 관측된 모든 분(창)의 error_rate(그 분의 ERROR 건수/전체 로그
    건수) 분포에서 p99. 다른 서비스나 Ground Truth는 쓰지 않는다. level이 없는
    gaia_log_unstructured 이벤트는 애초에 대상에서 제외한다(비교할 level 정보가 없다).

    severity: 위 baseline ratio는 탐지 트리거로만 쓰고, severity는 그 구간에서 실제
    관측된 에러 비율(절대값)로 정한다. 이 detector 혼자서는 서비스 영향 범위를 알 수
    없으므로 critical은 매기지 않는다.
    """
    buckets = count_by_window(
        events,
        window_seconds=_WINDOW_SECONDS,
        group_key=lambda e: e.host,
        predicate=lambda e: e.source_type == "gaia_log" and e.event_type == "gaia_log_entry",
        value_fn=_is_error,
        # 창 하나에 보통 수백 건의 로그가 섞여 있지만(대부분 INFO), evidence로 실제
        # 쓰이는 건 ERROR 로그뿐이다. INFO 로그의 EvidenceReference까지 전부 들고
        # 있으면(실측: gaia_log 약 715만 건) 메모리와 시간을 크게 낭비하므로, ERROR인
        # 이벤트만 evidence 후보로 남긴다. count/value_sum(=error 건수)은 이 필터와
        # 무관하게 매칭된 이벤트 전체를 정확히 반영한다.
        collect_evidence_for=lambda e: e.extra.get("level") == "ERROR",
    )

    by_host: dict[str, list[WindowCount]] = defaultdict(list)
    for bucket in buckets.values():
        by_host[bucket.group_key].append(bucket)

    findings: list[Finding] = []
    for host, host_buckets in by_host.items():
        if len(host_buckets) < _MIN_WINDOWS:
            continue
        host_buckets.sort(key=lambda b: b.window_start)

        error_rates = [b.value_sum / b.count for b in host_buckets if b.count > 0]
        baseline = percentile(error_rates, _BASELINE_PERCENTILE)
        if baseline <= 0:
            continue

        flagged = [b for b in host_buckets if b.count > 0 and (b.value_sum / b.count) / baseline >= _MIN_RATIO]
        if not flagged:
            continue

        episodes: list[list[WindowCount]] = []
        for bucket in flagged:
            if episodes and (bucket.window_start - episodes[-1][-1].window_start).total_seconds() <= _WINDOW_SECONDS:
                episodes[-1].append(bucket)
            else:
                episodes.append([bucket])

        for episode in episodes:
            total_log_count = sum(b.count for b in episode)
            total_error_count = sum(b.value_sum for b in episode)
            peak_rate = max(b.value_sum / b.count for b in episode)
            ratio = peak_rate / baseline

            if peak_rate >= _HIGH_ERROR_RATE:
                severity = "high"
            elif peak_rate >= _MEDIUM_ERROR_RATE:
                severity = "medium"
            else:
                severity = "low"

            start_time = episode[0].window_start
            end_time = episode[-1].window_end
            # collect_evidence_for가 이미 ERROR 이벤트만 골라 담았으므로 b.samples
            # 전체가 곧 error evidence 후보다.
            error_samples = [s for b in episode for s in b.samples]

            findings.append(
                Finding(
                    finding_id=make_finding_id(
                        detector=DETECTOR, dataset=dataset, group_key=host, start_time=start_time
                    ),
                    dataset=dataset,
                    category="error",
                    finding_type="log_error_rate_spike",
                    start_time=start_time,
                    end_time=end_time,
                    host=None,
                    service=host,
                    severity=severity,
                    summary=(
                        f"{host}에서 {start_time.isoformat()}부터 ERROR 로그 비율이 "
                        f"baseline p99({baseline:.1%})의 {ratio:.1f}배인 {peak_rate:.1%}까지 관측됨 "
                        f"(ERROR {int(total_error_count)}건 / 전체 로그 {total_log_count}건)"
                    ),
                    metrics={
                        "window_seconds": _WINDOW_SECONDS,
                        "error_count": int(total_error_count),
                        "total_log_count": total_log_count,
                        "error_rate_peak": peak_rate,
                        "baseline_p99_error_rate": baseline,
                        "ratio": ratio,
                        "window_count_in_episode": len(episode),
                        "evidence_count": len(error_samples),
                    },
                    evidence=select_representative_evidence(error_samples, max_count=DEFAULT_MAX_EVIDENCE),
                    entities={"service": [host]},
                    detector=DETECTOR,
                )
            )

    findings.sort(key=lambda f: (f.start_time, f.finding_id))
    return findings
