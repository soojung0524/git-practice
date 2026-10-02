"""russellmitchell apache_access 이벤트에서 트래픽 이상을 찾는 Analysis Skill.

실제 데이터 분포(전체 680,166건, apache_access 103,337건)로 확인한 근거:
  - 분당 요청 수: p50=8, p90=38, p95=89, p99=247, 최대 4,723건(p99의 19배, 2022-01-24
    03:57~03:58 두 개 창에 집중). -> find_request_spike
  - IP별로 보면 172.19.131.174 하나만 distinct path 8,787개(2위 834개의 10배 이상),
    404 비율 21.0%(다른 IP는 0~0.5%)인 뚜렷한 이상치가 있었다. -> find_scan_pattern
  - 5xx 상태코드는 전체 기간 단 1건뿐이라, "5xx 비율 급증" 같은 탐지는 이 데이터셋에서
    통계적으로 근거가 없다고 판단해 이번 1차 구현에서는 만들지 않았다.

Ground Truth(labels/)는 이 파일 어디에서도 읽지 않는다. threshold는 이벤트 스트림
자체의 통계(percentile, population median)로만 정한다.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable

from src.models import Finding, NormalizedEvent, make_finding_id
from src.skills.aggregation import (
    DEFAULT_MAX_EVIDENCE,
    WindowCount,
    compute_count_baseline,
    evidence_from_event,
    percentile,
    select_representative_evidence,
)
from src.skills.aggregation import ValueSample, count_by_window

DETECTOR_REQUEST_SPIKE = "find_request_spike"
DETECTOR_SCAN_PATTERN = "find_scan_pattern"

# --- find_request_spike ----------------------------------------------------

_REQUEST_WINDOW_SECONDS = 60
# 최소 30분 이상 관측된 host에 대해서만 baseline을 신뢰한다(관측 기간이 너무 짧으면
# p99 자체가 의미 없다).
_REQUEST_MIN_WINDOWS = 30
_REQUEST_BASELINE_PERCENTILE = 0.99
# 이 배수 미만이면 Finding을 만들지 않는다. ratio는 "탐지 트리거"일 뿐 severity를
# 결정하지 않는다 — severity는 아래에서 별도로, 그 창의 4xx/5xx 비율로 정한다.
_REQUEST_MIN_RATIO = 2.0


def _is_error_status(event: NormalizedEvent) -> float:
    status = event.extra.get("status")
    return 1.0 if isinstance(status, int) and status >= 400 else 0.0


def find_request_spike(
    events: Iterable[NormalizedEvent], *, dataset: str = "russellmitchell"
) -> list[Finding]:
    """host별 분당 요청 수가 그 host 자신의 baseline(p99)보다 뚜렷하게 많은 구간을 찾는다.

    baseline: host별로 관측된 전체 기간(첫 요청 창 ~ 마지막 요청 창)을 60초 창으로
    나눈 뒤, 요청이 0건이었던 창까지 포함해 p99를 계산한다(compute_count_baseline).
    같은 host의 실측 트래픽 패턴만 기준으로 삼고, 다른 host나 Ground Truth는 쓰지 않는다.

    severity: 통계적으로 몇 배 튀었는지(ratio)만으로 severity를 매기지 않는다. 요청량
    급증 자체는 정상적인 트래픽 증가일 수도 있기 때문이다. 대신 그 급증 구간에 실제로
    같이 있었던 4xx/5xx 응답의 비율로 정한다 — 요청은 몰렸는데 정상 응답(2xx/3xx)이
    대부분이면 low, 실패 응답이 섞여 있으면 medium/high로 올린다. 이 detector 혼자서는
    "심각한 침해"까지 단정할 근거가 없으므로 critical은 매기지 않는다(보수적으로 high가
    상한).
    """
    buckets = count_by_window(
        events,
        window_seconds=_REQUEST_WINDOW_SECONDS,
        group_key=lambda e: e.host,
        predicate=lambda e: e.source_type == "apache_access",
        value_fn=_is_error_status,
    )

    by_host: dict[str, list[WindowCount]] = defaultdict(list)
    for bucket in buckets.values():
        by_host[bucket.group_key].append(bucket)

    findings: list[Finding] = []
    for host, host_buckets in by_host.items():
        host_buckets.sort(key=lambda b: b.window_start)
        window_starts = [b.window_start for b in host_buckets]
        span_seconds = (window_starts[-1] - window_starts[0]).total_seconds()
        total_windows = int(span_seconds // _REQUEST_WINDOW_SECONDS) + 1

        baseline = compute_count_baseline(
            [b.count for b in host_buckets],
            total_windows=total_windows,
            percentile_value=_REQUEST_BASELINE_PERCENTILE,
            min_observations=_REQUEST_MIN_WINDOWS,
        )
        if not baseline:  # None(관측 부족) 또는 0.0(정말 baseline이 0인 host)
            continue

        flagged = [b for b in host_buckets if b.count / baseline >= _REQUEST_MIN_RATIO]
        if not flagged:
            continue

        # 연속된(창 간격이 window_seconds인) flagged 창은 하나의 급증 구간(episode)으로 묶는다.
        episodes: list[list[WindowCount]] = []
        for bucket in flagged:
            if episodes and (bucket.window_start - episodes[-1][-1].window_start).total_seconds() <= _REQUEST_WINDOW_SECONDS:
                episodes[-1].append(bucket)
            else:
                episodes.append([bucket])

        for episode in episodes:
            all_samples: list[ValueSample] = [s for b in episode for s in b.samples]
            total_count = sum(b.count for b in episode)
            peak_bucket = max(episode, key=lambda b: b.count)
            peak_ratio = peak_bucket.count / baseline
            error_fraction = sum(b.value_sum for b in episode) / total_count if total_count else 0.0

            if error_fraction >= 0.5:
                severity = "high"
            elif error_fraction >= 0.2:
                severity = "medium"
            else:
                severity = "low"

            start_time = episode[0].window_start
            end_time = episode[-1].window_end

            findings.append(
                Finding(
                    finding_id=make_finding_id(
                        detector=DETECTOR_REQUEST_SPIKE, dataset=dataset, group_key=host, start_time=start_time
                    ),
                    dataset=dataset,
                    category="availability",
                    finding_type="request_spike",
                    start_time=start_time,
                    end_time=end_time,
                    host=host,
                    service="apache2",
                    severity=severity,
                    summary=(
                        f"{host}에서 {start_time.isoformat()}부터 {len(episode)}개 창에 걸쳐 "
                        f"요청 {total_count}건 발생(피크 {peak_bucket.count}건/{_REQUEST_WINDOW_SECONDS}초, "
                        f"baseline p99={baseline:.0f}건의 {peak_ratio:.1f}배), "
                        f"4xx/5xx 비율 {error_fraction:.1%}"
                    ),
                    metrics={
                        "window_seconds": _REQUEST_WINDOW_SECONDS,
                        "request_count": total_count,
                        "peak_window_count": peak_bucket.count,
                        "baseline_p99": baseline,
                        "ratio": peak_ratio,
                        "window_count_in_episode": len(episode),
                        "error_status_fraction": error_fraction,
                        "evidence_count": len(all_samples),
                    },
                    evidence=select_representative_evidence(all_samples, max_count=DEFAULT_MAX_EVIDENCE),
                    entities={"host": [host]},
                    detector=DETECTOR_REQUEST_SPIKE,
                )
            )

    findings.sort(key=lambda f: (f.start_time, f.finding_id))
    return findings


# --- find_scan_pattern -------------------------------------------------------

# 요청이 너무 적은 IP는(1~2건) distinct path/404 비율이 우연히 커 보일 수 있어 제외한다.
_SCAN_MIN_REQUESTS = 10
# population median(비교 대상 IP 집합의 중앙값)을 신뢰하려면 최소 이만큼의 서로 다른
# IP가 있어야 한다.
_SCAN_MIN_IPS = 3
_SCAN_MIN_DISTINCT_PATH_RATIO = 3.0
_SCAN_HIGH_DISTINCT_PATH_RATIO = 10.0
_SCAN_MIN_ERROR_RATE_RATIO = 3.0


def find_scan_pattern(
    events: Iterable[NormalizedEvent], *, dataset: str = "russellmitchell"
) -> list[Finding]:
    """apache_access 요청을 src_ip별로 모아, 같은 관측 기간 다른 IP들과 비교해 경로
    다양성(distinct path)과 404 비율이 뚜렷하게 높은 IP를 찾는다(정찰/스캐닝 시그니처).

    시간창이 아니라 관측 전체 기간에 대한 IP별 집계다 — 실제 스캐닝 IP(172.19.131.174)의
    요청은 짧은 시간에 몰려 있지 않고 기간 전체에 퍼져 있었기 때문에, 분당 요청 수 급증
    (find_request_spike)으로는 잡히지 않고 "경로가 유난히 다양하고 404가 많다"는 형태로만
    드러났다.

    baseline: IP가 8개 안팎으로 적어 percentile 대신 population median(비교 대상 IP들의
    중앙값)을 기준으로 삼는다.

    severity: distinct path 비율만으로는 "정상적으로 다양한 페이지를 도는 크롤러/사용자"와
    구분할 수 없으므로, distinct path 비율과 404 비율 두 신호가 함께 높을 때만 severity를
    올린다. 이 detector 혼자서는 실제 침해 여부를 확인할 수 없으므로 상한은 high다.
    """
    per_ip: dict[str, dict] = {}
    for event in events:
        if event.source_type != "apache_access" or event.src_ip is None:
            continue
        entry = per_ip.setdefault(
            event.src_ip, {"total": 0, "error_count": 0, "paths": set(), "samples": []}
        )
        entry["total"] += 1
        status = event.extra.get("status")
        is_404 = isinstance(status, int) and status == 404
        if is_404:
            entry["error_count"] += 1
        path = event.extra.get("path")
        if path:
            entry["paths"].add(path)
        if event.timestamp is not None:
            entry["samples"].append(
                ValueSample(
                    value=1.0 if is_404 else 0.0,
                    timestamp=event.timestamp,
                    evidence=evidence_from_event(event),
                )
            )

    eligible = {ip: e for ip, e in per_ip.items() if e["total"] >= _SCAN_MIN_REQUESTS}
    if len(eligible) < _SCAN_MIN_IPS:
        return []

    distinct_counts = [len(e["paths"]) for e in eligible.values()]
    error_rates = [e["error_count"] / e["total"] for e in eligible.values()]
    median_distinct = percentile(distinct_counts, 0.5)
    median_error_rate = percentile(error_rates, 0.5)

    findings: list[Finding] = []
    for ip, entry in eligible.items():
        distinct = len(entry["paths"])
        error_rate = entry["error_count"] / entry["total"]

        if median_distinct > 0:
            distinct_ratio = distinct / median_distinct
        else:
            distinct_ratio = float("inf") if distinct > 0 else 0.0
        if median_error_rate > 0:
            error_ratio = error_rate / median_error_rate
        else:
            error_ratio = float("inf") if error_rate > 0 else 0.0

        if distinct_ratio < _SCAN_MIN_DISTINCT_PATH_RATIO:
            continue

        if distinct_ratio >= _SCAN_HIGH_DISTINCT_PATH_RATIO and error_ratio >= _SCAN_MIN_ERROR_RATE_RATIO:
            severity = "high"
        elif error_ratio >= _SCAN_MIN_ERROR_RATE_RATIO:
            severity = "medium"
        else:
            severity = "low"

        samples = entry["samples"]
        if not samples:
            continue
        timestamps = [s.timestamp for s in samples]
        start_time = min(timestamps)
        end_time = max(timestamps)
        error_samples = [s for s in samples if s.value == 1.0] or samples

        findings.append(
            Finding(
                finding_id=make_finding_id(
                    detector=DETECTOR_SCAN_PATTERN, dataset=dataset, group_key=ip, start_time=start_time
                ),
                dataset=dataset,
                category="security",
                finding_type="repeated_source_ip_scan",
                start_time=start_time,
                end_time=end_time,
                host=None,
                service="apache2",
                severity=severity,
                summary=(
                    f"{ip}가 관측 기간 동안 서로 다른 경로 {distinct}개에 요청"
                    f"(비교 대상 IP median의 {distinct_ratio:.1f}배), "
                    f"404 비율 {error_rate:.1%}(median의 {error_ratio:.1f}배)"
                ),
                metrics={
                    "total_requests": entry["total"],
                    "distinct_paths": distinct,
                    "median_distinct_paths": median_distinct,
                    "distinct_path_ratio": distinct_ratio,
                    "error_404_count": entry["error_count"],
                    "error_404_rate": error_rate,
                    "median_error_404_rate": median_error_rate,
                    "error_404_ratio": error_ratio,
                    "evidence_count": entry["total"],
                },
                evidence=select_representative_evidence(error_samples, max_count=DEFAULT_MAX_EVIDENCE),
                entities={"ip": [ip]},
                detector=DETECTOR_SCAN_PATTERN,
            )
        )

    findings.sort(key=lambda f: (f.start_time, f.finding_id))
    return findings
