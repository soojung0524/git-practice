"""GAIA MicroSS trace CSV(trace/*.csv) 파서.

실제 필드(README와 실제 파일 모두 확인함):
    timestamp,host_ip,service_name,trace_id,span_id,parent_id,start_time,end_time,url,status_code,message

예:
    2021-07-01 14:58:03,0.0.0.3,webservice2,47b56e46e21a0530,d1db8a029b58d4ce,0,\
        2021-07-01 14:57:52.377571,2021-07-01 14:58:02.741081,\
        http://0.0.0.3:9381/web_login_service,500,request call function 1 webservice2.web_login_service

Loader가 각 행을 csv.DictReader로 읽어 JSON 문자열로 직렬화해 넘기므로(파일마다
컬럼 구성이 달라지는 business/*.csv와 로더 코드를 공유하기 위함), 이 파서는
raw.raw를 json.loads로 되돌려 원래 컬럼 이름으로 접근한다.

실제 데이터에서 관측한 특징:
- parent_id는 호출을 시작하는 최상위 서비스(webservice*)의 스팬에서는 항상 "0",
  호출을 받는 하위 서비스(dbservice1 등)의 스팬에서는 항상 0이 아닌 값이었다.
  즉 이 필드로 호출 그래프(부모-자식 관계)를 구성할 수 있다 — 다만 그 구성 자체는
  이 단계의 범위가 아니므로 값만 그대로 보존한다.
- status_code는 "200"과 "500"만 관측됐다(README는 200 외 값을 이상으로 설명하지만,
  이 파서는 정상/이상을 판단하지 않고 숫자 그대로 보존한다).
- start_time/end_time은 마이크로초 단위까지 있다. timestamp 컬럼은 초 단위로
  반올림된 별도 값이라 start_time과 정확히 일치하지 않는다. 더 정밀한 start_time을
  이벤트의 timestamp로 쓰고, 원래 timestamp 컬럼 값은 extra에 그대로 남긴다.
  end_time과의 차이(duration_seconds)도 원본에 있는 두 시각의 단순 뺄셈일 뿐이라
  extra에 같이 남긴다(지연 여부를 판단하지 않는다).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from src.models import NormalizedEvent, RawLogLine, make_event_id

SOURCE_TYPE = "gaia_trace"

_REQUIRED_FIELDS = ("start_time", "trace_id", "span_id")
_DATETIME_FORMATS = ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S")


def _parse_datetime(text: str | None) -> datetime | None:
    if not text:
        return None
    for fmt in _DATETIME_FORMATS:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def parse(raw: RawLogLine) -> NormalizedEvent | None:
    try:
        row = json.loads(raw.raw)
    except json.JSONDecodeError:
        return None

    if not isinstance(row, dict) or any(not row.get(field) for field in _REQUIRED_FIELDS):
        return None

    start_time = _parse_datetime(row.get("start_time"))
    end_time = _parse_datetime(row.get("end_time"))

    duration_seconds = None
    if start_time is not None and end_time is not None:
        duration_seconds = (end_time - start_time).total_seconds()

    status_code = None
    if row.get("status_code"):
        try:
            status_code = int(row["status_code"])
        except ValueError:
            status_code = None

    extra: dict = {
        "trace_id": row.get("trace_id"),
        "span_id": row.get("span_id"),
        "parent_id": row.get("parent_id"),
        "timestamp_field": row.get("timestamp"),
        "start_time": row.get("start_time"),
        "end_time": row.get("end_time"),
        "duration_seconds": duration_seconds,
        "url": row.get("url"),
        "status_code": status_code,
        "host_ip": row.get("host_ip"),
    }

    return NormalizedEvent(
        event_id=make_event_id(raw),
        source_type=raw.source_type,
        host=raw.host,
        source_path=raw.source_path,
        line_number=raw.line_number,
        timestamp=start_time,
        raw=raw.raw,
        dataset="gaia",
        event_type="gaia_trace_span",
        message=row.get("message") or "",
        extra=extra,
    )
