"""Linux auditd audit.log 파서.

실제 관측된 라인 형식:
    type=USER_ACCT msg=audit(1642724221.475:149): pid=1716 uid=0 auid=4294967295 ses=4294967295 \
        msg='op=PAM:accounting acct="root" exe="/usr/sbin/cron" hostname=? addr=? terminal=cron res=success'
    type=SYSCALL msg=audit(1642746582.129:529): arch=c000003e syscall=1 success=yes exit=44953 \
        a0=6 a1=55688bbf9b10 a2=af99 a3=0 items=0 ppid=23661 pid=23662 auid=4294967295 uid=0 \
        comm="apparmor_parser" exe="/sbin/apparmor_parser" key=(null)

모든 라인이 `type=... msg=audit(epoch:seq): key=value ...` 형태의 flat key=value 나열이며,
일부 type(USER_ACCT, USER_LOGIN, SERVICE_START 등)은 `msg='...'` 안에 다시 key=value 목록을
중첩해서 담는다. 이 데이터셋에는 EXECVE 타입이 존재하지 않아 별도 처리하지 않았다.

msg=audit(epoch:seq)의 epoch는 UTC 기준 유닉스 타임스탬프이다
(같은 이벤트의 auth.log syslog 타임스탬프와 대조하여 확인함).
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from src.models import NormalizedEvent, RawLogLine, make_event_id

SOURCE_TYPE = "auditd"

_HEADER_RE = re.compile(
    r"^type=(?P<type>[A-Z_]+) msg=audit\((?P<epoch>\d+\.\d+):(?P<seq>\d+)\):\s*(?P<rest>.*)$"
)

_KV_RE = re.compile(r'(?P<key>[\w-]+)=(?:"(?P<dq>[^"]*)"|\'(?P<sq>[^\']*)\'|(?P<bare>\S*))')

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _tokenize(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for match in _KV_RE.finditer(text):
        if match.group("dq") is not None:
            value = match.group("dq")
        elif match.group("sq") is not None:
            value = match.group("sq")
        else:
            value = match.group("bare")
        fields[match.group("key")] = value
    return fields


def parse(raw: RawLogLine) -> NormalizedEvent | None:
    header_match = _HEADER_RE.match(raw.raw)
    if header_match is None:
        return None

    audit_type = header_match["type"]
    epoch = float(header_match["epoch"])
    seq = header_match["seq"]
    rest = header_match["rest"]

    timestamp = datetime.fromtimestamp(epoch, tz=timezone.utc)

    fields = _tokenize(rest)
    nested_fields: dict[str, str] = {}
    nested_msg = fields.get("msg")
    if nested_msg is not None:
        nested_fields = _tokenize(nested_msg)

    extra: dict = {"audit_type": audit_type, "audit_seq": seq}
    extra.update(fields)
    extra.update(nested_fields)

    pid = int(fields["pid"]) if fields.get("pid", "").isdigit() else None
    process = nested_fields.get("exe") or fields.get("exe") or fields.get("comm")
    user = nested_fields.get("acct")

    src_ip = None
    for ip_key in ("addr", "hostname"):
        candidate = nested_fields.get(ip_key)
        if candidate and _IP_RE.match(candidate):
            src_ip = candidate
            break

    message = nested_msg if nested_msg is not None else rest

    return NormalizedEvent(
        event_id=make_event_id(raw),
        source_type=raw.source_type,
        host=raw.host,
        source_path=raw.source_path,
        line_number=raw.line_number,
        timestamp=timestamp,
        raw=raw.raw,
        process=process,
        pid=pid,
        user=user,
        src_ip=src_ip,
        dst_ip=None,
        event_type=f"audit_{audit_type.lower()}",
        message=message,
        extra=extra,
    )
