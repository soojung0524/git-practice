"""Apache access.log 파서 (Combined / vhost_combined Log Format).

실제 관측된 라인 형식은 두 가지다.

Combined (`*-access.log*`, `proxy-access.log*`):
    10.143.2.91 - - [23/Jan/2022:06:36:13 +0000] "GET / HTTP/1.1" 200 6203 "-" "Mozilla/5.0 ..."

vhost_combined (`other_vhosts_access.log*`) — 앞에 `<vhost>:<port> ` 접두부가 붙는다:
    cloud.dmz.smith.russellmitchell.com:443 172.19.130.68 - - [24/Jan/2022:07:36:12 +0000] \
        "GET / HTTP/1.1" 302 4122 "-" "Mozilla/5.0 ..."

IP에는 콜론이 없으므로 두 형식은 접두부 유무로 구분된다.
"""

from __future__ import annotations

import re
from datetime import datetime

from src.models import NormalizedEvent, RawLogLine, make_event_id

SOURCE_TYPE = "apache_access"

_LINE_RE = re.compile(
    r'^(?:(?P<vhost>[\w.-]+):(?P<vhost_port>\d+) )?'
    r'(?P<ip>\S+) (?P<ident>\S+) (?P<authuser>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>[^"]*)" (?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"$'
)

_REQUEST_RE = re.compile(r"^(?P<method>\S+) (?P<path>\S+) (?P<protocol>\S+)$")


def _parse_timestamp(text: str) -> datetime | None:
    try:
        return datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def parse(raw: RawLogLine) -> NormalizedEvent | None:
    match = _LINE_RE.match(raw.raw)
    if match is None:
        return None

    fields = match.groupdict()
    timestamp = _parse_timestamp(fields["time"])

    extra: dict = {
        "ident": fields["ident"],
        "authuser": fields["authuser"],
        "status": int(fields["status"]),
        "size": int(fields["size"]) if fields["size"].isdigit() else None,
        "referrer": fields["referrer"],
        "user_agent": fields["user_agent"],
        "request": fields["request"],
    }

    request_match = _REQUEST_RE.match(fields["request"])
    if request_match:
        extra["method"] = request_match["method"]
        extra["path"] = request_match["path"]
        extra["protocol"] = request_match["protocol"]

    if fields["vhost"] is not None:
        extra["vhost"] = fields["vhost"]
        extra["vhost_port"] = int(fields["vhost_port"])

    user = fields["authuser"] if fields["authuser"] != "-" else None

    return NormalizedEvent(
        event_id=make_event_id(raw),
        source_type=raw.source_type,
        host=raw.host,
        source_path=raw.source_path,
        line_number=raw.line_number,
        timestamp=timestamp,
        raw=raw.raw,
        process="apache2",
        pid=None,
        user=user,
        src_ip=fields["ip"],
        dst_ip=None,
        event_type="http_request",
        message=fields["request"],
        extra=extra,
    )
