"""GAIA MicroSS metric CSV(metric/*.csv) 파서.

실제 파일에서 확인한 형식 (예: metric/dbservice1_0.0.0.4_docker_cpu_core_5_norm_pct_2021-08-01_2021-08-31.csv):
    timestamp,value
    1627747200000,0
    1627747230000,0.0273

- timestamp: 13자리 밀리초 단위 유닉스 타임스탬프
- value: 정수 또는 실수 문자열 (관측된 값은 항상 존재했지만, 방어적으로 파싱 실패 시 None 처리한다)

GAIA는 지표 이름을 파일명에 담는다(README에 명시). 파일명은
    <service>_<ip>_<metric_name>_<start_date>_<end_date>.csv
형태이지만, service와 metric_name 모두 언더스코어를 포함할 수 있어(예: redisservice1,
system_network_summary_tcp_OutRsts) 위치만으로는 자를 수 없다. 대신 파일명에 항상
등장하는 IPv4 토큰을 기준으로 앞을 service, 뒤(날짜 구간 제외)를 metric_name으로
나눈다. 실제로 metric_name 은 2,215개 이상의 서로 다른 값이 존재해 더 세분화하지
않고 문자열 그대로 보존하며, 맨 앞 토큰(docker/system/redis/zookeeper)만
대략적인 카테고리로 남긴다.

일부 파일(system_0.0.0.2_0.0.0.2_system_process_memory_share_...)은 ip 토큰이
metric_name 안에도 다시 등장한다. 이런 경우도 추측해서 더 쪼개지 않고 metric_name에
그대로 남긴다.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from src.models import NormalizedEvent, RawLogLine, make_event_id

SOURCE_TYPE = "gaia_metric"

_IP_RE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_FILENAME_RE = re.compile(r"^(?P<prefix>.+)_(?P<start>\d{4}-\d{2}-\d{2})_(?P<end>\d{4}-\d{2}-\d{2})$")


def parse_filename(stem: str) -> dict[str, str] | None:
    """metric CSV 파일명(확장자 제외)에서 service/ip/metric_name/날짜범위를 뽑는다.

    관측된 형식에 맞지 않으면 None을 돌려준다(추측해서 만들어내지 않는다).
    """
    match = _FILENAME_RE.match(stem)
    if match is None:
        return None
    prefix = match["prefix"]
    ip_match = _IP_RE.search(prefix)
    if ip_match is None:
        return None
    service = prefix[: ip_match.start()].rstrip("_")
    metric_name = prefix[ip_match.end() :].lstrip("_")
    if not service or not metric_name:
        return None
    return {
        "service": service,
        "ip": ip_match.group(),
        "metric_name": metric_name,
        "metric_category": metric_name.split("_")[0],
        "start_date": match["start"],
        "end_date": match["end"],
    }


def parse(raw: RawLogLine) -> NormalizedEvent | None:
    parts = raw.raw.split(",")
    if len(parts) != 2:
        return None
    ts_text, value_text = parts

    try:
        timestamp = datetime.fromtimestamp(int(ts_text) / 1000, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None

    try:
        value: float | None = float(value_text)
    except ValueError:
        value = None

    filename_info = parse_filename(Path(raw.source_path).stem) or {}

    extra: dict = {
        "value": value,
        "value_raw": value_text,
        "ip": filename_info.get("ip"),
        "metric_name": filename_info.get("metric_name"),
        "metric_category": filename_info.get("metric_category"),
        "file_start_date": filename_info.get("start_date"),
        "file_end_date": filename_info.get("end_date"),
    }

    metric_name = filename_info.get("metric_name", "unknown_metric")

    return NormalizedEvent(
        event_id=make_event_id(raw),
        source_type=raw.source_type,
        host=raw.host,
        source_path=raw.source_path,
        line_number=raw.line_number,
        timestamp=timestamp,
        raw=raw.raw,
        dataset="gaia",
        event_type="gaia_metric_sample",
        message=f"{metric_name}={value_text}",
        extra=extra,
    )
