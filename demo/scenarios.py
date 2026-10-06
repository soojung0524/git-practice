"""시연용 demo pack의 scenario 설정.

여기에는 **설정만** 둔다. 분석 로직은 전부 기존 scenario / correlation / report 계층이
가지고 있고, demo generator(scripts/build_demo_replay.py)가 그것을 호출한다.

각 scenario는 "실제로 존재하는 Finding"을 anchor로 지정한다. anchor_finding_id는
저장된 Finding cache를 조사해서 확인한 실제 ID이며, 추측해서 적은 값이 아니다.
generator가 생성 시점에 그 ID가 cache에 있는지, 최종 보고서의 incident와 맞는지
검증하고 어긋나면 생성을 거부한다.

title도 관측된 사실만 쓴다. Root Cause나 공격 유형을 넣지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass

# 모든 scenario가 같은 분석 Window 정책을 쓴다(scripts/build_incident_report.py와 동일).
# demo 결과를 보기 좋게 만들려고 Window를 넓히지 않는다.
WINDOW_MINUTES = 20
LEAD_MINUTES = 10


@dataclass(frozen=True)
class StepSpec:
    """step 하나의 presentation metadata. 실제 분석 시간이 아니다."""

    order: int
    phase: str
    phase_label: str
    file: str
    recommended_delay_ms: int


# --- phase 이름 -------------------------------------------------------------
PHASE_COLLECTING = "collecting"
PHASE_FINDING_DETECTED = "finding_detected"
PHASE_CORRELATING = "correlating"
PHASE_FOCUS_SELECTED = "focus_selected"
PHASE_RAG_ANALYZING = "rag_analyzing"
PHASE_RAG_COMPLETED = "rag_completed"
PHASE_ANALYZING = "analyzing"
PHASE_ANALYSIS_COMPLETED = "analysis_completed"
PHASE_REPORT_READY = "report_ready"

_COMMON_HEAD = (
    StepSpec(0, PHASE_COLLECTING, "데이터 수집 중", "step_00_collecting.json", 2500),
    StepSpec(1, PHASE_FINDING_DETECTED, "이상 징후 탐지", "step_01_finding_detected.json", 2500),
    StepSpec(2, PHASE_CORRELATING, "상관분석", "step_02_correlation.json", 3000),
    StepSpec(3, PHASE_FOCUS_SELECTED, "조사 대상 선정", "step_03_focus_selected.json", 3000),
)

_RAG_MIDDLE = (
    StepSpec(4, PHASE_RAG_ANALYZING, "보안 가이던스 조회 중", "step_04_rag_analyzing.json", 3500),
    StepSpec(5, PHASE_RAG_COMPLETED, "보안 가이던스 완료", "step_05_rag_completed.json", 3500),
)

# RAG를 쓰지 않는 scenario. "보안 가이던스 완료"처럼 보이게 하지 않는다.
_ANALYSIS_MIDDLE = (
    StepSpec(4, PHASE_ANALYZING, "요약 분석 중", "step_04_analysis.json", 3500),
    StepSpec(5, PHASE_ANALYSIS_COMPLETED, "요약 분석 완료", "step_05_analysis_completed.json", 3500),
)

_COMMON_TAIL = (
    StepSpec(6, PHASE_REPORT_READY, "보고서 생성 완료", "step_06_report_ready.json", 0),
)


def make_steps(*, uses_rag: bool) -> tuple[StepSpec, ...]:
    middle = _RAG_MIDDLE if uses_rag else _ANALYSIS_MIDDLE
    return _COMMON_HEAD + middle + _COMMON_TAIL


@dataclass(frozen=True)
class DemoScenario:
    scenario_key: str
    title: str
    findings_path: str
    report_path: str
    out_dir: str
    scenario_id: str
    anchor_finding_id: str
    uses_rag: bool
    # RAG를 호출하지 않은 scenario에서 그 이유를 화면에 그대로 보여주기 위한 문구.
    guidance_not_requested_reason: str | None = None
    window_minutes: int = WINDOW_MINUTES
    lead_minutes: int = LEAD_MINUTES

    @property
    def steps(self) -> tuple[StepSpec, ...]:
        return make_steps(uses_rag=self.uses_rag)


_PERFORMANCE_NO_RAG = (
    "이 incident는 통계 탐지기가 관측한 성능 이상이며 보안 사고로 판단된 바가 없다. "
    "AWS Security Incident Response User Guide는 보안 사고 대응 문서이므로, 성능 이상을 "
    "보안 사고처럼 설명하지 않기 위해 Security Guidance를 요청하지 않았다."
)

_RESOURCE_NO_RAG = (
    "이 incident는 통계 탐지기가 관측한 자원 사용량 이상이며 보안 사고로 판단된 바가 없다. "
    "AWS Security Incident Response User Guide는 보안 사고 대응 문서이므로, 단순 자원 이상을 "
    "보안 사고로 확대하지 않기 위해 Security Guidance를 요청하지 않았다."
)


SCENARIOS: tuple[DemoScenario, ...] = (
    # 기존 scenario. 값과 산출물을 바꾸지 않는다.
    DemoScenario(
        scenario_key="gaia_network_incident",
        title="dbservice1 network_usage_anomaly 조사",
        findings_path="output/findings/gaia.pkl",
        report_path="output/reports/gaia-final_report_e4977bb394b7.json",
        out_dir="output/demo/gaia_network_incident",
        scenario_id="report-window",
        anchor_finding_id=(
            "gaia:find_metric_anomaly:dbservice1_docker_network_in_packets:"
            "2021-07-31T19:10:27+00:00"
        ),
        uses_rag=True,
    ),
    # A. 서비스 응답 지연.
    #
    # "응답 지연 및 오류"가 아니라 "응답 지연"이다. log_error_rate_spike는 전체 GAIA
    # cache에 1건뿐이고(webservice1, 2021-07-01 09:57) 그 전후 60분 안에 다른 Finding이
    # 하나도 없다. 두 사건을 한 화면에 묶으려면 3주짜리 Window가 필요하므로 묶지 않았다.
    DemoScenario(
        scenario_key="gaia_service_degradation",
        title="dbservice1 서비스 응답 지연 이상 조사",
        findings_path="output/findings/gaia.pkl",
        report_path="output/reports/gaia-latency_report_a9cfdbe9eb23.json",
        out_dir="output/demo/gaia_service_degradation",
        scenario_id="latency-window",
        anchor_finding_id=(
            "gaia:find_latency_anomaly:dbservice1:2021-07-19T23:12:12.933626+00:00"
        ),
        uses_rag=False,
        guidance_not_requested_reason=_PERFORMANCE_NO_RAG,
    ),
    # B. 서버 자원 이상.
    #
    # cache에 있는 resource Finding은 cpu_usage_anomaly 3건(모두 redis)뿐이다.
    # memory / disk / process crash Finding은 존재하지 않으므로 넣지 않았다.
    DemoScenario(
        scenario_key="gaia_server_resource_anomaly",
        title="redis CPU 사용량 이상 조사",
        findings_path="output/findings/gaia.pkl",
        report_path="output/reports/gaia-cpu_report_622bc058e015.json",
        out_dir="output/demo/gaia_server_resource_anomaly",
        scenario_id="resource-window",
        anchor_finding_id=(
            "gaia:find_metric_anomaly:redis_docker_cpu_user_pct:2021-07-20T09:34:55+00:00"
        ),
        uses_rag=False,
        guidance_not_requested_reason=_RESOURCE_NO_RAG,
    ),
    # C. 웹 요청 급증 / 스캔 패턴.
    #
    # anchor는 4xx/5xx 비율 99.3%, baseline의 234배인 intranet_server request_spike다.
    # 같은 Window 안에 repeated_source_ip_scan이 있지만 두 Finding은 evidence도 entity도
    # 공유하지 않아 correlation이 묶지 않는다 - 억지로 합치지 않고 별도 후보로 남긴다.
    DemoScenario(
        scenario_key="russellmitchell_web_scan",
        title="intranet_server 웹 요청 급증 조사",
        findings_path="output/findings/russellmitchell.pkl",
        report_path="output/reports/rm-webscan_report_0eaf2a67fa3c.json",
        out_dir="output/demo/russellmitchell_web_scan",
        scenario_id="webscan-window",
        anchor_finding_id=(
            "russellmitchell:find_request_spike:intranet_server:2022-01-24T03:57:00+00:00"
        ),
        uses_rag=True,
    ),
)

SCENARIOS_BY_KEY = {scenario.scenario_key: scenario for scenario in SCENARIOS}


def get_scenario(scenario_key: str) -> DemoScenario:
    try:
        return SCENARIOS_BY_KEY[scenario_key]
    except KeyError:
        known = ", ".join(sorted(SCENARIOS_BY_KEY))
        raise KeyError(f"알 수 없는 scenario_key: {scenario_key!r} (사용 가능: {known})") from None
