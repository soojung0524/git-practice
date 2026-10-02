"""OpenVPN 서버 로그(openvpn.log) 파서.

실제 관측된 라인 형식 (연도 포함, 타임존 정보는 없음):
    2022-01-21 06:30:01 192.168.230.95:60795 [twhite] Peer Connection Initiated with [AF_INET]192.168.230.95:60795
    2022-01-21 00:09:11 jhall/192.168.230.165:46011 VERIFY OK: depth=1, C=AT, ST=Vienna, ...
    2022-01-21 00:09:11 jhall/192.168.230.165:46011 peer info: IV_VER=2.4.4
    2022-01-23 14:54:54 jhall/192.168.230.165:59814 TLS Error: TLS key negotiation failed to occur ...

클라이언트 식별 접두부는 세 가지 형태로 관측된다:
    "<user>/<ip>:<port> "    (인증이 끝나 사용자가 식별된 이후의 메시지)
    "<ip>:<port> [<user>] "  (Peer Connection Initiated 등, 사용자명이 확정되는 시점)
    "<ip>:<port> "           (인증 전 단계. TLS 초기 패킷, 인증서 검증 등)

정규식 대안 순서가 중요하다. 사용자명 없는 세 번째 형태를 먼저 두면
"[<user>]"가 메시지 본문으로 빨려 들어가므로 반드시 마지막에 둔다.

메시지 종류가 매우 다양하여(SENT CONTROL, MULTI_sva, Data/Control Channel 협상 로그 등),
연결 수명주기와 직접 관련된 일부만 event_type으로 분류하고 나머지는 vpn_other로 남긴다.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from src.models import NormalizedEvent, RawLogLine, make_event_id

SOURCE_TYPE = "openvpn"

_HEADER_RE = re.compile(
    r"^(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2}) "
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) "
    r"(?:"
    r"(?P<user_a>[\w.@-]+)/(?P<ip_a>[\d.]+):(?P<port_a>\d+)"
    r"|"
    r"(?P<ip_b>[\d.]+):(?P<port_b>\d+) \[(?P<user_b>[\w.@-]+)\]"
    r"|"
    r"(?P<ip_c>[\d.]+):(?P<port_c>\d+)"
    r") (?P<msg>.*)$"
)

_PATTERNS = (
    (re.compile(r"^Peer Connection Initiated with (?P<detail>.*)$"), "vpn_peer_connection_initiated"),
    (re.compile(r"^VERIFY OK: depth=(?P<depth>\d+), (?P<subject>.*)$"), "vpn_cert_verify_ok"),
    (re.compile(r"^VERIFY KU OK$"), "vpn_cert_verify_ku_ok"),
    (re.compile(r"^VERIFY EKU OK$"), "vpn_cert_verify_eku_ok"),
    (re.compile(r"^TLS Error: (?P<detail>.*)$"), "vpn_tls_error"),
    (re.compile(r"^TLS: soft reset (?P<detail>.*)$"), "vpn_tls_soft_reset"),
    (re.compile(r"^TLS: Initial packet (?P<detail>.*)$"), "vpn_tls_initial_packet"),
    (re.compile(r"^MULTI: Learn: (?P<pool_ip>\S+) -> (?P<learned_id>.*)$"), "vpn_multi_learn"),
    (re.compile(r"^\[[\w.@-]+\] Inactivity timeout (?P<detail>.*)$"), "vpn_inactivity_timeout"),
    (
        re.compile(r"^SIGUSR1\[soft,ping-restart\] received, client-instance (?P<detail>.*)$"),
        "vpn_client_restart_signal",
    ),
)


def _parse_timestamp(fields: dict) -> datetime | None:
    try:
        return datetime.strptime(
            f"{fields['year']}-{fields['month']}-{fields['day']} "
            f"{fields['hour']}:{fields['minute']}:{fields['second']}",
            "%Y-%m-%d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def parse(raw: RawLogLine) -> NormalizedEvent | None:
    match = _HEADER_RE.match(raw.raw)
    if match is None:
        return None

    fields = match.groupdict()
    timestamp = _parse_timestamp(fields)
    msg = fields["msg"]

    user = fields["user_a"] or fields["user_b"]
    src_ip = fields["ip_a"] or fields["ip_b"] or fields["ip_c"]
    port = fields["port_a"] or fields["port_b"] or fields["port_c"]

    event_type = "vpn_other"
    extra: dict = {"port": int(port)}

    for pattern, matched_event_type in _PATTERNS:
        pattern_match = pattern.match(msg)
        if pattern_match is None:
            continue
        event_type = matched_event_type
        extra.update(pattern_match.groupdict())
        break

    return NormalizedEvent(
        event_id=make_event_id(raw),
        source_type=raw.source_type,
        host=raw.host,
        source_path=raw.source_path,
        line_number=raw.line_number,
        timestamp=timestamp,
        raw=raw.raw,
        process="openvpn",
        pid=None,
        user=user,
        src_ip=src_ip,
        dst_ip=None,
        event_type=event_type,
        message=msg,
        extra=extra,
    )
