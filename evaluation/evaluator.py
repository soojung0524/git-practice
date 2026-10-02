"""Finding과 GroundTruthIncident를 비교해 detector별 탐지 성능을 계산한다.

Finding
    ↓
Evaluator   (이 모듈)
    ↑
Ground Truth

이 모듈은 Analysis Skill이나 Parser를 전혀 모른다 - Finding과 GroundTruthIncident만
입력으로 받는다. Ground Truth를 threshold 조정이나 Finding 생성에 쓰지 않는다는
원칙은 이 모듈 경계 자체로 지킨다(이 모듈을 거치지 않고는 Ground Truth가 탐지
파이프라인에 들어갈 방법이 없다).

=== detector ↔ Ground Truth 유형 매핑 (의미 기준) ===

매핑 기준은 "같은 로그 파일에 붙어 있는 라벨인가"가 **아니라** "detector가 탐지하는
현상과 라벨이 가리키는 행위가 같은 것인가"다. 같은 access.log에 붙어 있다는 이유로
라벨을 몰아서 매핑하면, detector가 원래 탐지 대상으로 삼지 않은 행위까지 recall 분모에
들어가 성능이 실제보다 나쁘게 나온다.

그래서 apache access.log 라벨 8종의 실제 성질을 먼저 측정했다(라벨별 요청 수 /
서로 다른 경로 수 / 출발 IP 수).

  라벨              요청수  distinct path  성질
  dirb              4462    4462           경로 전수 조사, 전부 404 - 전형적 스캐닝
  wpscan            3186    3078           WordPress 스캐너 - 스캐닝 + 대량 요청
  foothold          7691    7542           공격 전 구간을 덮는 우산(캠페인) 라벨
  attacker_http     7687    7542           공격자 HTTP 트래픽 전체를 덮는 행위자 라벨
  webshell_cmd      32      1              웹셸 명령 실행 - 경로 1개, 스캐닝도 급증도 아님
  service_scan      12      4              서비스 배너 확인 - 요청량이 너무 적다
  escalate          4       1              웹셸로 권한 상승 - 경로 1개
  webshell_upload   3       2              파일 업로드 - 요청 3건

이 측정에 근거한 매핑:
  - find_scan_pattern(반복 출발 IP + 다수 distinct path + 높은 404율)의 의미와 정확히
    일치하는 라벨은 dirb, wpscan 둘이다. webshell_cmd/escalate는 경로가 1개뿐이고
    service_scan은 경로 4개·요청 12건이라 "스캐닝"의 정의에 맞지 않는다 -
    detector가 놓쳐도 그건 오탐이 아니라 애초에 탐지 대상이 아니다.
  - find_request_spike(단위 시간 요청 수 급증)의 의미와 일치하는 라벨도 dirb, wpscan
    둘이다. 나머지는 요청이 3~32건이라 어떤 합리적 threshold로도 "급증"이 될 수 없다.
  - foothold, attacker_http는 특정 행위가 아니라 캠페인/행위자 단위 우산 라벨이다
    (dirb·wpscan·webshell을 모두 포함하는 상위 집합). 어떤 단일 detector의 탐지 의미와도
    1:1로 대응하지 않으므로 detector 매핑에서 제외하고, UMBRELLA_GROUND_TRUTH_TYPES에
    따로 기록만 한다. dirb/wpscan incident가 이 캠페인의 부분집합이라 실질 평가 대상이
    사라지는 것은 아니다.
  - dnsteal 계열(DNS exfiltration), escalate 계열(auth.log/audit.log 권한 상승),
    attacker_vpn, network_scan/dns_scan(dnsmasq)에 대응하는 detector는 아직 구현되지
    않았다. 매핑을 지어내지 않는다.
  - crack_passwords는 CPU 모니터링 로그(파서 없음)에만 있어 GroundTruthIncident 자체가
    만들어지지 않는다(russellmitchell_ground_truth.py 참고).

GAIA:
  - cpu_usage_anomaly ↔ cpu_anomalies, memory_usage_anomaly ↔ memory_anomalies는
    "CPU/메모리를 과도하게 쓰는 프로그램을 주입했다"는 같은 대상을 가리키므로 의미가
    일치한다.
  - network_usage_anomaly에 대응하는 주입 유형은 run/에 없다 - 매핑하지 않는다.
  - service_latency_spike, log_error_rate_spike에 직접 대응하는 주입 유형도 없다.
    CPU 과부하가 간접적으로 지연을 유발했을 가능성은 있지만 인과를 이 데이터만으로
    확인할 수 없어 매핑하지 않는다(추측 금지).

=== 평가 모드 (temporal / entity) ===

detector가 만드는 Finding의 시간 granularity가 incident-level 시간 매칭에 쓸 수 있는지는
detector마다 다르다. find_scan_pattern은 관측 전체 기간을 한 덩어리로 집계해 IP당 Finding
하나를 만들기 때문에, 그 Finding의 시간 구간은 coverage 전체와 거의 같다. 이런 Finding으로
시간 겹침을 따지면 무조건 통과하므로 시간 기준 판별력이 0이고, precision/recall이 1.0으로
나와도 그것은 "시간적으로 정확히 탐지했다"는 뜻이 아니다.

그래서 detector별로 DETECTOR_EVALUATION_MODE를 선언한다.
  - "temporal": 시간 겹침으로 매칭한다(episode/window 단위 Finding).
  - "entity"  : 시간 겹침만으로는 판별력이 없으므로 entity(출발 IP 등) 일치를 **필수**
                조건으로 추가하고, 결과를 시간 정확도 지표로 쓰지 않는다
                (DetectorEvaluation.official_temporal_metrics=False).
"entity" 모드의 수치는 "이 IP가 실제 공격자 IP였는가"를 보는 것이지 "언제 탐지했는가"를
보는 것이 아니다. 근거를 코드에 하드코딩만 해두지 않고, 실제 Finding 시간 폭이 coverage의
몇 %인지 측정해 max_finding_span_ratio로 함께 보고한다.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from src.models import Finding

from .coverage import EvaluationCoverage, filter_incidents_by_coverage
from .ground_truth import GroundTruthIncident

# 특정 행위가 아니라 캠페인/행위자 전체를 덮는 우산 라벨. 어떤 detector의 탐지 의미와도
# 1:1 대응하지 않아 매핑에서 제외하지만, 실제 데이터에 존재한다는 사실은 남겨 둔다.
UMBRELLA_GROUND_TRUTH_TYPES: frozenset[str] = frozenset({"foothold", "attacker_http"})

# 대량 자동화 스캐닝 도구가 만든 라벨. 실측 결과 dirb는 4462요청/4462 distinct path,
# wpscan은 3186요청/3078 distinct path로, "스캐닝"과 "요청량 급증" 양쪽 의미에 모두 맞는다.
_AUTOMATED_SCANNER_TYPES: frozenset[str] = frozenset({"dirb", "wpscan"})

# finding_type -> 그 finding과 비교 가능한 GroundTruthIncident.anomaly_type 집합.
# 키가 없는 finding_type은 "이번 평가 대상이 아님"을 뜻한다(추측해서 채우지 않는다).
FINDING_TYPE_GROUND_TRUTH_TYPES: dict[str, frozenset[str]] = {
    "request_spike": _AUTOMATED_SCANNER_TYPES,
    "repeated_source_ip_scan": _AUTOMATED_SCANNER_TYPES,
    "cpu_usage_anomaly": frozenset({"cpu_anomalies"}),
    "memory_usage_anomaly": frozenset({"memory_anomalies"}),
    # 아래는 의도적으로 키를 두지 않는다: network_usage_anomaly, service_latency_spike,
    # log_error_rate_spike - 대응되는 Ground Truth 유형이 확인되지 않았다.
}

# detector -> 평가 모드. 모듈 docstring의 "평가 모드" 절 참고.
DETECTOR_EVALUATION_MODE: dict[str, str] = {
    "find_request_spike": "temporal",  # 60초 window 기반 episode
    "find_scan_pattern": "entity",  # 관측 전체 기간 집계 -> 시간 판별력 없음
    "find_metric_anomaly": "temporal",
    "find_latency_anomaly": "temporal",
    "find_log_error_spike": "temporal",
}

# detector -> 그 detector가 만들 수 있는 finding_type들의 GT 유형 합집합.
# finding이 0건이어도(예: 이번 실행에서 한 건도 안 잡힘) recall 분모(총 incident 수)를
# 정확히 계산하려면 detector가 "원래 평가 대상으로 삼는" GT 유형을 finding과 무관하게
# 미리 알아야 한다 - 그래서 finding_type 매핑과 별개로 고정 테이블을 둔다.
DETECTOR_GROUND_TRUTH_TYPES: dict[str, frozenset[str]] = {
    "find_request_spike": FINDING_TYPE_GROUND_TRUTH_TYPES["request_spike"],
    "find_scan_pattern": FINDING_TYPE_GROUND_TRUTH_TYPES["repeated_source_ip_scan"],
    "find_metric_anomaly": FINDING_TYPE_GROUND_TRUTH_TYPES["cpu_usage_anomaly"]
    | FINDING_TYPE_GROUND_TRUTH_TYPES["memory_usage_anomaly"],
    "find_latency_anomaly": frozenset(),
    "find_log_error_spike": frozenset(),
}


def _overlap_seconds(a_start: datetime, a_end: datetime, b_start: datetime, b_end: datetime) -> float:
    latest_start = max(a_start, b_start)
    earliest_end = min(a_end, b_end)
    return max(0.0, (earliest_end - latest_start).total_seconds())


def _intervals_intersect(
    a_start: datetime, a_end: datetime, b_start: datetime, b_end: datetime
) -> bool:
    """두 시간 구간이 겹치는지 판단한다.

    기본은 "겹치는 길이 > 0초"지만, 한쪽이 길이 0인 순간(start == end)일 때는 그 기준을
    쓸 수 없다. 실제 데이터에 두 종류 모두 존재한다.
      - Ground Truth: labels/ 의 라벨이 한 시각에만 붙은 incident(dirb, wpscan,
        network_scan, webshell_upload 등 실측에서 지속시간 0초)
      - Finding: metric/latency episode가 표본 1건으로 끝난 경우(sample_count=1)
    이 경우 "그 순간이 상대 구간 안에 들어오면 겹친 것"으로 본다. 양쪽 모두 길이가
    0보다 크면 단순히 맞닿은 구간(한쪽 끝 == 다른 쪽 시작)은 겹치지 않은 것으로 남긴다.
    """
    latest_start = max(a_start, b_start)
    earliest_end = min(a_end, b_end)
    if earliest_end < latest_start:
        return False
    if (earliest_end - latest_start).total_seconds() > 0:
        return True
    # 겹치는 길이가 정확히 0 - 한쪽이 순간(길이 0)일 때만 겹친 것으로 인정한다.
    return a_start == a_end or b_start == b_end


def _entities_overlap(a: dict[str, list[str]], b: dict[str, list[str]]) -> bool:
    for key in a.keys() & b.keys():
        if set(a[key]) & set(b[key]):
            return True
    return False


@dataclass(frozen=True)
class Match:
    """Finding 하나와 GroundTruthIncident 하나가 매치 조건을 만족했다는 기록."""

    finding_id: str
    incident_id: str
    overlap_seconds: float
    # incident 지속시간 대비 overlap 비율. incident가 순간적(지속시간 0)이면 정의할 수
    # 없어 None으로 둔다(0으로 눙쳐서 마치 안 겹친 것처럼 보이게 하지 않는다).
    overlap_ratio: float | None
    # finding 시작 시각 - incident 시작 시각(초). 양수면 늦게 탐지, 음수면 incident
    # 공식 시작보다 먼저 Finding이 만들어졌다는 뜻(예: episode 병합 창 경계 때문일 수 있음).
    detection_delay_seconds: float
    entities_overlap: bool


def _try_match(
    finding: Finding, incident: GroundTruthIncident, *, mode: str = "temporal"
) -> Match | None:
    """아래 조건을 모두 만족해야 match로 본다 (하나라도 어긋나면 None).

    1. dataset이 같아야 한다.
    2. finding.finding_type에 매핑된 GT 유형에 incident.anomaly_type이 포함돼야 한다.
    3. 시간 구간이 실제로 겹쳐야 한다(완전히 같은 시각일 필요는 없다). 판정 방식은
       _intervals_intersect 참고 - 한쪽이 길이 0인 순간이면 "그 순간이 상대 구간 안"
       이어야 하고, 양쪽 모두 길이가 있으면 겹치는 길이가 0보다 커야 한다.
    4. host/service는 "양쪽 다 값이 있는데 다르면" 탈락시킨다. 한쪽이 None이면(예:
       GAIA Finding은 host가 없다) 그 축은 비교하지 않는다.
    5. mode="entity"이면 entity(ip 등) 일치를 **추가 필수 조건**으로 요구한다. 시간
       판별력이 없는 전체 기간 Finding을 시간만으로 판정하지 않기 위한 조건이다.

    mode="temporal"에서는 entity overlap을 참고 정보로만 기록한다 - GAIA incident는 애초에
    entity가 없고, russellmitchell도 detector에 따라 없을 수 있어 필수 조건으로 두면 정당한
    match를 놓치게 된다.
    """
    if finding.dataset != incident.dataset:
        return None

    allowed_types = FINDING_TYPE_GROUND_TRUTH_TYPES.get(finding.finding_type)
    if not allowed_types or incident.anomaly_type not in allowed_types:
        return None

    if finding.host and incident.host and finding.host != incident.host:
        return None
    if finding.service and incident.service and finding.service != incident.service:
        return None

    if not _intervals_intersect(
        finding.start_time, finding.end_time, incident.start_time, incident.end_time
    ):
        return None
    overlap = _overlap_seconds(
        finding.start_time, finding.end_time, incident.start_time, incident.end_time
    )

    ent_overlap = _entities_overlap(finding.entities, incident.entities)
    if mode == "entity" and not ent_overlap:
        return None

    duration = (incident.end_time - incident.start_time).total_seconds()
    overlap_ratio = (overlap / duration) if duration > 0 else None
    delay = (finding.start_time - incident.start_time).total_seconds()

    return Match(
        finding_id=finding.finding_id,
        incident_id=incident.incident_id,
        overlap_seconds=overlap,
        overlap_ratio=overlap_ratio,
        detection_delay_seconds=delay,
        entities_overlap=ent_overlap,
    )


@dataclass
class DetectorEvaluation:
    detector: str
    ground_truth_types: frozenset[str]
    # "temporal" | "entity" - DETECTOR_EVALUATION_MODE 참고.
    evaluation_mode: str = "temporal"
    # False면 이 detector의 precision/recall/f1을 "시간 정확도를 반영한 공식 성능"으로
    # 인용해서는 안 된다(전체 기간 Finding이라 시간 판별력이 없음).
    official_temporal_metrics: bool = True

    total_incidents: int = 0
    detected_incidents: int = 0
    missed_incidents: int = 0
    missed_incident_ids: list[str] = field(default_factory=list)

    total_findings: int = 0
    true_positive_findings: int = 0
    false_positive_findings: int = 0
    false_positive_finding_ids: list[str] = field(default_factory=list)

    # 분모가 0이면(비교할 incident/finding 자체가 없으면) None - 0으로 대신하지 않는다.
    precision: float | None = None
    recall: float | None = None
    f1: float | None = None

    # coverage로 분모에서 제외된 incident. 제외했다는 사실과 개수를 반드시 남긴다.
    coverage: EvaluationCoverage | None = None
    out_of_coverage_incidents: int = 0
    out_of_coverage_by_type: dict[str, int] = field(default_factory=dict)

    # Finding 시간 폭 / coverage 시간 폭의 최대값. 1.0에 가까우면 그 Finding은 관측
    # 전체 기간을 덮고 있어 시간 겹침 조건이 사실상 무조건 통과한다는 뜻이다.
    max_finding_span_ratio: float | None = None

    matches: list[Match] = field(default_factory=list)
    caveats: list[str] = field(default_factory=list)


def evaluate_detector(
    findings: Iterable[Finding],
    incidents: Iterable[GroundTruthIncident],
    *,
    detector: str,
    coverage: EvaluationCoverage | None = None,
) -> DetectorEvaluation:
    """한 detector를 그에 매핑된 Ground Truth 유형만 대상으로 독립적으로 평가한다.

    계산 방식(명시):
      - 먼저 coverage로 분모를 제한한다. detector가 실제로 관측한 기간/host/service 밖의
        incident는 "탐지 기회가 없었다"고 보고 recall 분모에서 뺀다(제외 개수는
        out_of_coverage_incidents에 남긴다). coverage=None이면 제한하지 않는다.
      - Recall은 incident 단위: (매칭된 finding이 하나라도 있는 incident 수) / (coverage
        안의 관련 incident 수). "관련 incident"는 DETECTOR_GROUND_TRUTH_TYPES에 있는
        anomaly_type을 가진, 같은 dataset의 incident다.
      - Precision은 finding 단위: (매칭된 incident가 하나라도 있는 finding 수) /
        (전체 관련 finding 수). "관련 finding"은 이 detector가 만든 finding 중
        FINDING_TYPE_GROUND_TRUTH_TYPES에 매핑이 있는 finding_type만이다 - 매핑이
        없는 finding_type(예: network_usage_anomaly)은 판단할 Ground Truth가 없으므로
        평가에서 제외하며, false positive로 세지 않는다.
      - F1은 precision/recall의 조화평균(2PR/(P+R)). **둘 다 정의돼 있고 둘 다 0이면
        F1은 0.0이다**(정의되지 않은 것이 아니라 성능이 0인 것이다). precision이나
        recall 중 하나라도 None(분모 0)이면 F1도 None이다.
      - 하나의 incident를 여러 finding이 맞혀도 detected_incidents는 1로만 센다.
        하나의 finding이 여러 incident와 겹쳐도 true_positive_findings는 1로만 센다
        (다대다 관계를 "양쪽 다 최소 1개 매치"로 집계).
    """
    ground_truth_types = DETECTOR_GROUND_TRUTH_TYPES.get(detector, frozenset())
    mode = DETECTOR_EVALUATION_MODE.get(detector, "temporal")

    typed_incidents = [
        incident for incident in incidents if incident.anomaly_type in ground_truth_types
    ]
    relevant_incidents, excluded_incidents = filter_incidents_by_coverage(typed_incidents, coverage)
    out_of_coverage_by_type: dict[str, int] = {}
    for incident in excluded_incidents:
        out_of_coverage_by_type[incident.anomaly_type] = (
            out_of_coverage_by_type.get(incident.anomaly_type, 0) + 1
        )

    relevant_findings = [
        finding
        for finding in findings
        if finding.detector == detector and finding.finding_type in FINDING_TYPE_GROUND_TRUTH_TYPES
    ]

    matches: list[Match] = []
    matched_incident_ids: set[str] = set()
    matched_finding_ids: set[str] = set()

    for finding in relevant_findings:
        for incident in relevant_incidents:
            match = _try_match(finding, incident, mode=mode)
            if match is None:
                continue
            matches.append(match)
            matched_incident_ids.add(incident.incident_id)
            matched_finding_ids.add(finding.finding_id)

    max_span_ratio: float | None = None
    if coverage is not None and coverage.duration_seconds() > 0 and relevant_findings:
        max_span_ratio = max(
            (f.end_time - f.start_time).total_seconds() / coverage.duration_seconds()
            for f in relevant_findings
        )

    caveats: list[str] = []
    if mode == "entity":
        caveats.append(
            "전체 기간 집계 Finding이라 시간 겹침에 판별력이 없다. entity(IP) 일치를 필수 "
            "조건으로 요구해 평가했고, 이 수치는 시간 정확도를 나타내지 않는다."
        )
    if max_span_ratio is not None and max_span_ratio >= 0.5:
        caveats.append(
            f"Finding 시간 폭이 관측 기간의 최대 {max_span_ratio:.1%}에 달한다 - "
            "시간 겹침 조건이 사실상 무조건 통과한다."
        )
    if excluded_incidents:
        caveats.append(
            f"coverage(관측 기간/host/service) 밖이라 분모에서 제외한 incident {len(excluded_incidents)}건: "
            f"{out_of_coverage_by_type}"
        )

    total_incidents = len(relevant_incidents)
    detected_incidents = len(matched_incident_ids)
    missed_incidents = total_incidents - detected_incidents
    missed_incident_ids = sorted(
        {i.incident_id for i in relevant_incidents} - matched_incident_ids
    )

    total_findings = len(relevant_findings)
    true_positive_findings = len(matched_finding_ids)
    false_positive_findings = total_findings - true_positive_findings
    false_positive_finding_ids = sorted(
        {f.finding_id for f in relevant_findings} - matched_finding_ids
    )

    precision = (true_positive_findings / total_findings) if total_findings else None
    recall = (detected_incidents / total_incidents) if total_incidents else None
    f1: float | None = None
    if precision is not None and recall is not None:
        # precision과 recall이 모두 정의돼 있는데 합이 0이면, F1은 정의 불가가 아니라
        # 0.0이다(전부 틀렸다는 뜻). 이 경우를 None으로 돌려주면 "평가 불가"와
        # "성능 0"이 구분되지 않는다.
        f1 = 0.0 if (precision + recall) == 0 else 2 * precision * recall / (precision + recall)

    return DetectorEvaluation(
        detector=detector,
        ground_truth_types=ground_truth_types,
        evaluation_mode=mode,
        official_temporal_metrics=(mode == "temporal"),
        coverage=coverage,
        out_of_coverage_incidents=len(excluded_incidents),
        out_of_coverage_by_type=out_of_coverage_by_type,
        max_finding_span_ratio=max_span_ratio,
        caveats=caveats,
        total_incidents=total_incidents,
        detected_incidents=detected_incidents,
        missed_incidents=missed_incidents,
        missed_incident_ids=missed_incident_ids,
        total_findings=total_findings,
        true_positive_findings=true_positive_findings,
        false_positive_findings=false_positive_findings,
        false_positive_finding_ids=false_positive_finding_ids,
        precision=precision,
        recall=recall,
        f1=f1,
        matches=matches,
    )


def evaluate_all(
    findings: Iterable[Finding],
    incidents: Iterable[GroundTruthIncident],
    *,
    coverages: dict[str, EvaluationCoverage | None] | None = None,
) -> dict[str, DetectorEvaluation]:
    """DETECTOR_GROUND_TRUTH_TYPES에 등록된 모든 detector를 각각 독립적으로 평가한다.

    coverages는 detector 이름 -> 그 detector의 관측 범위. 주지 않으면 그 detector는
    범위 제한 없이 평가된다(분모를 줄이지 않는 쪽이 보수적이다).
    """
    findings = list(findings)
    incidents = list(incidents)
    coverages = coverages or {}
    return {
        detector: evaluate_detector(
            findings, incidents, detector=detector, coverage=coverages.get(detector)
        )
        for detector in DETECTOR_GROUND_TRUTH_TYPES
    }
