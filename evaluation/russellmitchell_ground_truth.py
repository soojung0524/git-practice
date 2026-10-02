"""russellmitchell 데이터셋의 labels/ 를 GroundTruthIncident로 변환한다.

실제 확인한 labels/ 구조 (예: labels/intranet_server/logs/auth.log):
    {"line": 145, "labels": ["attacker_change_user", "escalate"],
     "rules": {"attacker_change_user": ["attacker.escalate.su.login"], ...}}

- labels/ 아래 디렉터리 구조는 gather/ 와 완전히 동일하다
  (labels/<host>/<원본과 같은 상대경로>). 파일 하나당 JSON Lines이며, 한 줄이
  원본 gather/ 파일의 특정 줄(1-based, "line" 필드)에 대한 라벨이다.
- 실제로 존재하는 labels/ 파일 8개를 전부 확인했다: dnsmasq.log, audit.log(2곳),
  apache2 access/error log, auth.log, openvpn.log, 그리고 CPU 모니터링 로그
  (monitoring/logs/logstash/intranet-server/2022-01-24-system.cpu.log).
  마지막 CPU 모니터링 로그는 이 프로젝트에 파서가 없는 형식이라(어떤 LOG_FILE_TYPES
  패턴에도 매칭되지 않음) 원본 이벤트(타임스탬프 등)를 재구성할 수 없다 — 그래서
  이 파일의 라벨("escalate", "crack_passwords")은 GroundTruthIncident로 만들지
  않고 건너뛴다. 존재하지 않는 정보를 추측해서 채우지 않는다는 원칙에 따른 것이다.
- 관측된 라벨(anomaly_type) 전체 목록(파일별 개수는 evaluator.py의 매핑 표 참고):
  dnsteal, attacker, dnsteal-received, dnsteal-dropped, foothold, service_scan,
  dns_scan, network_scan, webshell_cmd, webshell_upload, escalate, dirb, wpscan,
  traceroute, exfiltration-service, attacker_http, escalated_command,
  escalated_sudo_command, attacker_change_user, escalated_sudo_session,
  attacker_vpn, crack_passwords(→ 위 이유로 incident화 불가).

incident 구성 방법:
  labels 파일은 "줄" 단위 라벨이라 그 자체로는 시간 구간이 없다. 그래서 같은 파일 +
  같은 라벨을 가진 줄들을, 원본 이벤트의 timestamp를 파싱해 시간 간격이
  max_gap_seconds 이내면 하나의 incident로 묶는다(src/skills/aggregation.py의
  episode 병합과 같은 발상이며, 여기서는 evaluation 모듈을 skills에 의존시키지
  않기 위해 별도로 작게 구현했다). 이 간격 값은 실제 라벨 분포에서 역산한 것이
  아니라 명시적으로 고른 설계값이다 — 얼마나 걸었는지는 이 파일에 그대로 남긴다.
"""

from __future__ import annotations

import fnmatch
import json
from collections.abc import Iterator
from pathlib import Path

from src.models import NormalizedEvent, RawLogLine
from src.parser import LOG_FILE_TYPES, get_parser

from .ground_truth import GroundTruthIncident

# labels 파일들 사이에서 실제로 관측되는 최대 라벨 개수 차이가 커서(dnsteal 5만여 건 vs
# escalate 몇 건) 하나의 절대적으로 "옳은" 값은 없다. 5분을 기본값으로 둔다 — Analysis
# Skills 단계에서 GAIA metric episode 병합에 쓴 것과 같은 수준(300초)이라 두 단계의
# "지속되는 하나의 사건" 정의를 맞췄다.
DEFAULT_MAX_GAP_SECONDS = 300.0


def _infer_source_type(rel_path: Path) -> str | None:
    """<host>/logs/... 형태의 상대경로에서 source_type을 추론한다.

    LOG_FILE_TYPES의 glob 패턴은 <host>/logs/ 아래 상대경로 기준이므로, 그 앞부분
    (호스트명, "logs")을 제거한 나머지로 매칭한다. 매칭되는 패턴이 없으면(=이
    프로젝트에 파서가 없는 로그 형식) None을 돌려준다.
    """
    parts = rel_path.parts
    if len(parts) < 3 or parts[1] != "logs":
        return None
    within_logs = Path(*parts[2:]).as_posix()
    for pattern, source_type, _ in LOG_FILE_TYPES:
        if fnmatch.fnmatch(within_logs, pattern):
            return source_type
    return None


def _iter_label_rows(label_file: Path) -> Iterator[dict]:
    with label_file.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                yield json.loads(line)


def _cluster_events_by_gap(
    events: list[NormalizedEvent], max_gap_seconds: float
) -> list[list[NormalizedEvent]]:
    """timestamp 기준으로 정렬한 뒤, 간격이 max_gap_seconds를 넘으면 새 묶음으로 끊는다."""
    if not events:
        return []
    ordered = sorted(events, key=lambda e: e.timestamp)
    clusters: list[list[NormalizedEvent]] = [[ordered[0]]]
    for prev, curr in zip(ordered, ordered[1:]):
        gap = (curr.timestamp - prev.timestamp).total_seconds()
        if gap <= max_gap_seconds:
            clusters[-1].append(curr)
        else:
            clusters.append([curr])
    return clusters


def _build_incident(*, anomaly_type: str, host: str, cluster: list[NormalizedEvent]) -> GroundTruthIncident:
    start_time = cluster[0].timestamp
    end_time = cluster[-1].timestamp

    entities: dict[str, list[str]] = {}
    ips = sorted({e.src_ip for e in cluster if e.src_ip})
    users = sorted({e.user for e in cluster if e.user})
    if ips:
        entities["ip"] = ips
    if users:
        entities["user"] = users

    return GroundTruthIncident(
        dataset="russellmitchell",
        incident_id=f"russellmitchell:{anomaly_type}:{host}:{start_time.isoformat()}",
        anomaly_type=anomaly_type,
        start_time=start_time,
        end_time=end_time,
        host=host,
        service=None,
        entities=entities,
        evidence_event_ids=tuple(e.event_id for e in cluster),
    )


def load_russellmitchell_ground_truth(
    dataset_root: str | Path, *, max_gap_seconds: float = DEFAULT_MAX_GAP_SECONDS
) -> list[GroundTruthIncident]:
    """dataset_root/labels/ 전체를 읽어 GroundTruthIncident 목록을 만든다.

    각 labels 파일에 대해:
      1. 같은 상대경로의 gather/ 원본 파일을 찾는다.
      2. 라벨이 붙은 줄 번호의 원본 텍스트를, 실제 파이프라인과 동일한 parser로
         파싱해 timestamp/host/src_ip/user 등을 얻는다(라벨 파일 자체에는 이 정보가
         없다).
      3. (파일, 라벨) 별로 이벤트를 모아 시간 간격 기준으로 묶어 incident를 만든다.

    dataset_root/labels/ 가 없으면 빈 리스트를 돌려준다(GAIA 전용으로 이 함수를
    부르지 않도록 방어하는 정도이며, 존재해야 할 디렉터리가 없는 다른 상황을 조용히
    감추지는 않는다 - FileNotFoundError는 각 host 순회 중 발생하면 그대로 전파된다).
    """
    root = Path(dataset_root)
    labels_root = root / "labels"
    if not labels_root.is_dir():
        return []

    incidents: list[GroundTruthIncident] = []

    for label_file in sorted(labels_root.rglob("*")):
        if not label_file.is_file():
            continue
        rel_path = label_file.relative_to(labels_root)
        host = rel_path.parts[0]
        source_type = _infer_source_type(rel_path)
        if source_type is None:
            # 이 로그 형식은 이 프로젝트에 파서가 없다(예: CPU 모니터링 로그) - 원본
            # timestamp를 재구성할 수 없어 incident를 만들지 않고 건너뛴다.
            continue
        parse_fn = get_parser(source_type)
        if parse_fn is None:
            continue

        gather_rel_path = Path("gather") / rel_path
        gather_path = root / gather_rel_path
        if not gather_path.is_file():
            continue
        raw_lines = gather_path.read_text(encoding="utf-8", errors="replace").splitlines()
        source_path = gather_rel_path.as_posix()

        by_label: dict[str, list[NormalizedEvent]] = {}
        for row in _iter_label_rows(label_file):
            line_number = row["line"]
            if line_number < 1 or line_number > len(raw_lines):
                continue
            raw = RawLogLine(
                host=host,
                source_type=source_type,
                source_path=source_path,
                line_number=line_number,
                raw=raw_lines[line_number - 1],
            )
            event = parse_fn(raw)
            if event is None or event.timestamp is None:
                continue
            for label in row.get("labels", []):
                by_label.setdefault(label, []).append(event)

        for anomaly_type, events in by_label.items():
            for cluster in _cluster_events_by_gap(events, max_gap_seconds):
                incidents.append(_build_incident(anomaly_type=anomaly_type, host=host, cluster=cluster))

    return incidents
