"""GAIA MicroSS의 run/ (anomaly injection 기록)을 GroundTruthIncident로 변환한다.

실제 확인한 run/run/run_table_*.csv 구조:
    datetime,service,message
    2021-07-01,dbservice1,"2021-07-01 11:54:27,616 | WARNING | 0.0.0.4 | 172.17.0.3 | dbservice1 |
        [memory_anomalies] trigger a high memory program, start at 2021-07-01 11:44:26.882752
        and lasts 600 seconds and use 1g memory"

business/*.csv 와 컬럼 구성은 같지만(datetime,service,message), 이 파일은 대부분
(전체 36,574행 중 35,067행, 약 96%) "[태그]" 표시가 없는 평범한 업무 시뮬레이션
로그다("wait for 11 seconds ... QR code expired" 등). run/ 전체를 Ground Truth로
쓰면 안 되고, 실제로 이상 주입을 구조적으로 기록한 줄만 골라야 한다.

"[태그]" 표시가 있는 줄은 실제로 4종류였다:
    memory_anomalies (1,367건), cpu_anomalies (81건),
    normal memory freed label (29건), Errno 111 (30건)

이 중 "start at <timestamp> and lasts <N> seconds" 구조를 가진 것은 memory_anomalies와
cpu_anomalies 두 종류뿐이며, 이 둘은 예외 없이(1,448건 전부) 그 구조를 따른다 — 그래서
시작 시각과 지속시간을 텍스트에서 직접, 안정적으로 뽑을 수 있다. "normal memory freed
label"은 시작/지속시간이 없는 별도 문장(예: "lasts ten minutes")이라 구조가 달라
제외했다. "Errno 111"은 실제 DB 연결 실패 에러 로그일 뿐 "이상 주입" 기록이 아니라서
(주입 시작/지속시간 정보가 없음) 제외했다. 이 두 유형을 GroundTruthIncident로 만들면
관측되지 않은 정보를 추측해서 채우는 셈이 되므로 하지 않는다.

주의: "lasts N seconds"의 N이 비정상적으로 큰 값(수백만 초)인 행이 실제로 존재한다
(예: cpu_anomalies 한 건이 1,631,517초 지속으로 기록됨). 이것이 데이터 자체의 특성인지
기록 오류인지는 이 데이터만으로 판단할 수 없어 임의로 자르거나 보정하지 않고 원본
값을 그대로 사용한다 - 평가 결과를 볼 때 참고할 caveat로 남긴다.
"""

from __future__ import annotations

import csv
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .ground_truth import GroundTruthIncident

_TAG_RE = re.compile(r"\[([^\]]+)\]")
_START_LASTS_RE = re.compile(
    r"start at (?P<start>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) and lasts (?P<duration>[\d.]+) seconds"
)

# 실제로 "start at ... lasts ... seconds" 구조를 100%(1,448/1,448) 만족하는 것을 확인한
# 두 태그만 지원한다. 다른 태그("Errno 111", "normal memory freed label")는 이 구조가
# 없어 추측해서 채우지 않는다 - 모듈 docstring 참고.
SUPPORTED_ANOMALY_TAGS = frozenset({"cpu_anomalies", "memory_anomalies"})


def load_gaia_ground_truth(gaia_root: str | Path) -> list[GroundTruthIncident]:
    """gaia_root/run/ 아래 run_table_*.csv를 읽어 GroundTruthIncident 목록을 만든다.

    gaia_root는 metric/trace/business와 같은 부모 디렉터리(일반 GAIA 파이프라인이
    쓰는 것과 동일한 루트)다. 실 배포본 압축을 풀면 run/run/run_table_*.csv 처럼
    한 단계 더 중첩되는 경우가 있어(gaia_loader.py가 다루는 metric/trace/business와
    달리 run/은 registry에 등록돼 있지 않아 이 중첩 구조를 그대로 두고 rglob으로
    찾는다), gaia_root/run 아래를 재귀적으로 탐색한다.
    """
    root = Path(gaia_root)
    run_root = root / "run"
    if not run_root.is_dir():
        return []

    incidents: list[GroundTruthIncident] = []

    for path in sorted(run_root.rglob("*.csv")):
        source_path = path.relative_to(root).as_posix()
        with path.open(encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for line_number, row in enumerate(reader, start=1):
                message = row.get("message") or ""
                tag_match = _TAG_RE.search(message)
                if tag_match is None:
                    continue
                anomaly_type = tag_match.group(1)
                if anomaly_type not in SUPPORTED_ANOMALY_TAGS:
                    continue
                struct_match = _START_LASTS_RE.search(message)
                if struct_match is None:
                    # 실측으로는 발생하지 않지만(1,448/1,448 매칭), 방어적으로 남긴다.
                    continue

                start_time = datetime.strptime(
                    struct_match["start"], "%Y-%m-%d %H:%M:%S.%f"
                ).replace(tzinfo=timezone.utc)
                duration_seconds = float(struct_match["duration"])
                end_time = start_time + timedelta(seconds=duration_seconds)
                service = row.get("service")

                incidents.append(
                    GroundTruthIncident(
                        dataset="gaia",
                        incident_id=f"gaia:{anomaly_type}:{service}:{start_time.isoformat()}",
                        anomaly_type=anomaly_type,
                        start_time=start_time,
                        end_time=end_time,
                        host=None,
                        service=service,
                        entities={},
                        evidence_event_ids=(f"{source_path}:{line_number}",),
                    )
                )

    return incidents
