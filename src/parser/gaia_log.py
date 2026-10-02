"""GAIA MicroSS business(애플리케이션) 로그 CSV(business/*.csv) 파서.

실제 파일을 확인한 결과, CSV 자체의 컬럼 구성이 파일마다 다르다.
    business_table_webservice1_2021-07.csv  -> datetime,service,message            (3컬럼)
    business_table_2021-08.csv              -> id,datetime,service,message         (4컬럼)
Loader가 csv.DictReader로 읽어 컬럼 이름 그대로 JSON 직렬화해서 넘기므로, 이 파서는
컬럼 순서/개수와 무관하게 이름(datetime/service/message)으로만 접근한다.

message 컬럼 안에는 다시 파이프(|)로 구분된 애플리케이션 로그 한 줄이 들어있다.
    2021-08-01 00:00:01,302 | INFO | 0.0.0.2 | dbservice2 | permission_operate.py -> \
        permission_operation -> 35 | 7a379c0e7ccf9a58 | the list of all available services ...

파이프 필드는 항상 "정밀 타임스탬프 | 레벨 | ... | 자유 텍스트 메시지" 순이지만,
가운데(3번째 이후) 필드의 의미가 로그 문장마다 다르다는 것을 실제 데이터에서 확인했다.
예를 들어 어떤 줄은 4번째 필드가 컨테이너 IP고 5번째가 서비스명이지만, 다른 줄은
4번째 필드가 곧바로 서비스명이고 5번째가 "파일명 -> 함수명 -> 줄번호" 형태의
소스 코드 위치다. 실제로 확인된 것 이상으로 의미를 추측해 필드 이름을 붙이지
않기 위해, 가운데 필드는 이름을 붙이지 않고 순서 그대로 리스트(extra["fields"])에
보존한다.

이 형식에 맞지 않는 message(파이프 구분자가 거의 없는 등)는 버리지 않고
event_type="gaia_log_unstructured"로 원문을 그대로 보존한다. 그래야 원본 파일에
있던 내용이 정규화 단계에서 유실되지 않는다(apache_error 파서의 처리 방식과 동일).

타임존: 이 파일 자체에는 타임존 표기가 없다. metric(13자리 유닉스 타임스탬프라
정의상 UTC)이나 trace와 서로 다른 타임존이라고 볼 근거도 없어, 같은 테스트베드에서
같은 시계를 쓴다고 보고 UTC로 간주해 tzinfo를 붙인다. 이는 russellmitchell의
auditd epoch처럼 다른 필드와 대조해 검증한 사실이 아니라 가정이며, GAIA 세 파서가
서로 다른 시간대를 쓰면 이벤트 timestamp끼리 비교/정렬이 깨지기 때문에 최소한
파서 사이의 일관성은 맞췄다.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from src.models import NormalizedEvent, RawLogLine, make_event_id

SOURCE_TYPE = "gaia_log"

_EMBEDDED_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S,%f"

# 이 미만이면 "타임스탬프 | 레벨 | 메시지" 최소 구조조차 아니라고 본다.
_MIN_STRUCTURED_PARTS = 3


def _parse_embedded_timestamp(text: str) -> datetime | None:
    try:
        return datetime.strptime(text, _EMBEDDED_TIMESTAMP_FORMAT).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _unstructured_event(raw: RawLogLine, row: dict, message_field: str) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=make_event_id(raw),
        source_type=raw.source_type,
        host=raw.host,
        source_path=raw.source_path,
        line_number=raw.line_number,
        timestamp=None,
        raw=raw.raw,
        dataset="gaia",
        event_type="gaia_log_unstructured",
        message=message_field.strip(),
        extra={"csv_datetime": row.get("datetime")},
    )


def parse(raw: RawLogLine) -> NormalizedEvent | None:
    try:
        row = json.loads(raw.raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(row, dict):
        return None

    message_field = row.get("message") or ""
    parts = [p.strip() for p in message_field.split(" | ")]

    if len(parts) < _MIN_STRUCTURED_PARTS:
        return _unstructured_event(raw, row, message_field)

    timestamp = _parse_embedded_timestamp(parts[0])
    level = parts[1]
    middle_fields = parts[2:-1]
    message = parts[-1]

    extra: dict = {
        "level": level,
        "fields": middle_fields,
        "csv_datetime": row.get("datetime"),
        "embedded_timestamp_raw": parts[0],
    }

    return NormalizedEvent(
        event_id=make_event_id(raw),
        source_type=raw.source_type,
        host=raw.host,
        source_path=raw.source_path,
        line_number=raw.line_number,
        timestamp=timestamp,
        raw=raw.raw,
        dataset="gaia",
        event_type="gaia_log_entry",
        message=message,
        extra=extra,
    )
