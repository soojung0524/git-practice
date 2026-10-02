"""두 데이터셋의 서로 다른 Ground Truth 형식을 공통으로 다루기 위한 최소 모델.

russellmitchell(labels/의 줄 단위 공격 라벨)과 GAIA(run/의 anomaly injection 기록)는
원본 형식이 완전히 다르지만, Finding과 비교하려면 결국 "언제부터 언제까지, 어느
host/service에서, 무슨 유형의 이상이 있었는가"라는 같은 모양의 정보가 필요하다.
GroundTruthIncident는 그 최소 교집합만 담는다 — 실제 데이터에서 확인되지 않는
필드(예: 공식 severity, incident 설명 텍스트)는 추가하지 않는다.

이 모델은 Evaluation 단계에서만 쓰인다. NormalizedEvent/Finding 모델은 건드리지
않고, Analysis Skill/Parser의 입력으로도 쓰이지 않는다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime


@dataclass(frozen=True)
class GroundTruthIncident:
    """두 데이터셋에 공통인 최소 Ground Truth 단위.

    Finding과 대응되도록 host/service를 분리해 둔다(russellmitchell은 host만,
    GAIA는 service만 채워진다 — Finding과 같은 관례).
    """

    dataset: str  # "russellmitchell" | "gaia"
    incident_id: str
    anomaly_type: str  # 원본 라벨/태그 문자열 그대로 보존한다(예: "dirb", "cpu_anomalies")
    start_time: datetime
    end_time: datetime
    host: str | None
    service: str | None
    # 실제로 원본에서 관측된 entity만 담는다(예: {"ip": [...], "user": [...]}).
    # 관측되지 않은 종류의 entity는 키 자체를 넣지 않는다 - Finding.entities와 같은 관례.
    entities: dict[str, list[str]] = field(default_factory=dict)
    # 이 incident를 구성한 원본 이벤트/행을 추적하기 위한 참조.
    # russellmitchell: NormalizedEvent.event_id("source_path:line_number")와 동일한 형식.
    # GAIA: "run/<file>:<csv 데이터 행 번호>" 형식(gaia_loader의 line_number 관례와 동일).
    evidence_event_ids: tuple[str, ...] = ()
