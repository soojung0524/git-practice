"""dnsmasq.log 파서.

실제 관측된 라인 형식 (연도, 타임존 정보 없음):
    Jan 21 00:00:09 dnsmasq[3468]: query[A] example.com from 10.143.0.103
    Jan 21 00:00:09 dnsmasq[3468]: forwarded example.com to 192.168.231.254
    Jan 21 00:00:09 dnsmasq[3468]: reply example.com is 195.128.194.168
    Jan 21 00:02:37 dnsmasq[3468]: cached db.local.clamav.net is <CNAME>
    Jan 21 05:55:17 dnsmasq[3468]: nameserver 127.0.0.1 refused to do a recursive query
    Jan 21 07:05:20 dnsmasq[3468]: failed to access /etc/dnsmasq.d/dnsmasq-resolv.conf: No such file or directory

호스트명 필드는 존재하지 않는다 (auth.log 등 다른 syslog 로그와 다른 점).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from src.models import NormalizedEvent, RawLogLine, make_event_id

SOURCE_TYPE = "dnsmasq"

# russellmitchell 데이터셋의 관측 기간(dataset.yaml: 2022-01-21 ~ 2022-01-25) 기준.
# syslog 형식 자체에는 연도가 없어 부득이하게 파서 호출 시 지정하도록 하고, 기본값만 제공한다.
_DEFAULT_YEAR = 2022

_HEADER_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) "
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) "
    r"dnsmasq\[(?P<pid>\d+)\]: (?P<msg>.*)$"
)

_QUERY_RE = re.compile(r"^query\[(?P<qtype>[A-Za-z]+)\] (?P<domain>\S+) from (?P<ip>\S+)$")
_FORWARDED_RE = re.compile(r"^forwarded (?P<domain>\S+) to (?P<ip>\S+)$")
_REPLY_RE = re.compile(r"^(?P<kind>reply|cached) (?P<domain>\S+) is (?P<answer>.+)$")
_NAMESERVER_RE = re.compile(r"^nameserver (?P<ip>\S+) (?P<detail>.+)$")


def _parse_timestamp(mon: str, day: str, hour: str, minute: str, second: str, year: int) -> datetime | None:
    try:
        return datetime.strptime(
            f"{year} {mon} {int(day):02d} {hour}:{minute}:{second}",
            "%Y %b %d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def parse(raw: RawLogLine, year: int = _DEFAULT_YEAR) -> NormalizedEvent | None:
    match = _HEADER_RE.match(raw.raw)
    if match is None:
        return None

    fields = match.groupdict()
    msg = fields["msg"]
    timestamp = _parse_timestamp(
        fields["mon"], fields["day"], fields["hour"], fields["minute"], fields["second"], year
    )

    event_type: str | None = "dns_other"
    src_ip: str | None = None
    dst_ip: str | None = None
    extra: dict = {}

    query_match = _QUERY_RE.match(msg)
    forwarded_match = _FORWARDED_RE.match(msg)
    reply_match = _REPLY_RE.match(msg)
    nameserver_match = _NAMESERVER_RE.match(msg)

    if query_match:
        event_type = "dns_query"
        src_ip = query_match["ip"]
        extra = {"domain": query_match["domain"], "query_type": query_match["qtype"]}
    elif forwarded_match:
        event_type = "dns_forwarded"
        dst_ip = forwarded_match["ip"]
        extra = {"domain": forwarded_match["domain"]}
    elif reply_match:
        event_type = "dns_reply" if reply_match["kind"] == "reply" else "dns_cached"
        extra = {"domain": reply_match["domain"], "answer": reply_match["answer"]}
    elif nameserver_match:
        event_type = "dns_nameserver"
        dst_ip = nameserver_match["ip"]
        extra = {"detail": nameserver_match["detail"]}

    return NormalizedEvent(
        event_id=make_event_id(raw),
        source_type=raw.source_type,
        host=raw.host,
        source_path=raw.source_path,
        line_number=raw.line_number,
        timestamp=timestamp,
        raw=raw.raw,
        process="dnsmasq",
        pid=int(fields["pid"]),
        user=None,
        src_ip=src_ip,
        dst_ip=dst_ip,
        event_type=event_type,
        message=msg,
        extra=extra,
    )
