"""Apache error.log 파서.

실제 관측된 라인 형식:
    [Mon Jan 24 03:57:26.696483 2022] [authz_core:error] [pid 25711] [client 172.19.131.174:36072] \
        AH01630: client denied by server configuration: /var/www/.../file
    [Mon Jan 24 06:25:03.954255 2022] [mpm_prefork:notice] [pid 449] AH00163: Apache/2.4.29 ...

`[client ip:port]` 구간은 클라이언트 요청과 무관한 서버 자체 메시지(기동/설정 등)에는 없다.
"AH#####:" 형태의 에러 코드도 모든 라인에 있는 것은 아니다.

error.log에는 Apache가 직접 쓴 위 형식 외에, Apache 아래에서 실행된 프로세스가 stderr로
내보낸 출력이 그대로 섞여 들어온다(예: samba의 "mkdir failed ...", wget 진행률 출력).
이런 라인은 구조가 없으므로 필드를 지어내지 않고 event_type="apache_error_unstructured"로
원문만 보존한다. 버리면 원본 파일에 남아 있는 내용이 정규화 단계에서 유실되기 때문이다.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from src.models import NormalizedEvent, RawLogLine, make_event_id

SOURCE_TYPE = "apache_error"

_LINE_RE = re.compile(
    r"^\[(?P<dow>\w{3}) (?P<mon>\w{3}) (?P<day>\d{1,2}) "
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})\.(?P<micro>\d+) (?P<year>\d{4})\] "
    r"\[(?P<module>[\w-]+):(?P<level>\w+)\] \[pid (?P<pid>\d+)\]"
    r"(?: \[client (?P<client_ip>[\d.]+):(?P<client_port>\d+)\])? (?P<msg>.*)$"
)

_ERROR_CODE_RE = re.compile(r"^(?P<code>AH\d+): (?P<detail>.*)$")


def _parse_timestamp(fields: dict) -> datetime | None:
    # Apache error.log 자체에는 타임존 표기가 없다. 같은 서버의 access.log(+0000)와
    # auditd epoch가 모두 UTC로 확인되어, error.log도 UTC로 간주해 tzinfo를 부여한다.
    try:
        return datetime.strptime(
            f"{fields['year']} {fields['mon']} {int(fields['day']):02d} "
            f"{fields['hour']}:{fields['minute']}:{fields['second']}.{fields['micro']}",
            "%Y %b %d %H:%M:%S.%f",
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _unstructured_event(raw: RawLogLine) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=make_event_id(raw),
        source_type=raw.source_type,
        host=raw.host,
        source_path=raw.source_path,
        line_number=raw.line_number,
        timestamp=None,
        raw=raw.raw,
        event_type="apache_error_unstructured",
        message=raw.raw,
    )


def parse(raw: RawLogLine) -> NormalizedEvent | None:
    match = _LINE_RE.match(raw.raw)
    if match is None:
        return _unstructured_event(raw)

    fields = match.groupdict()
    timestamp = _parse_timestamp(fields)
    msg = fields["msg"]

    error_code = None
    code_match = _ERROR_CODE_RE.match(msg)
    if code_match:
        error_code = code_match["code"]
        msg = code_match["detail"]

    extra: dict = {
        "module": fields["module"],
        "level": fields["level"],
        "error_code": error_code,
    }
    if fields["client_port"] is not None:
        extra["client_port"] = int(fields["client_port"])

    return NormalizedEvent(
        event_id=make_event_id(raw),
        source_type=raw.source_type,
        host=raw.host,
        source_path=raw.source_path,
        line_number=raw.line_number,
        timestamp=timestamp,
        raw=raw.raw,
        process="apache2",
        pid=int(fields["pid"]),
        user=None,
        src_ip=fields["client_ip"],
        dst_ip=None,
        event_type="http_error",
        message=msg,
        extra=extra,
    )
