"""auth.log 파서 (표준 syslog 포맷, sshd/CRON/su/sudo/systemd-logind/systemd).

실제 관측된 라인 형식 (연도, 타임존 정보 없음):
    Jan 23 16:30:46 intranet-server sshd[25184]: Accepted publickey for jhall from 172.19.131.174 port 49828 ssh2: RSA SHA256:...
    Jan 24 03:56:47 intranet-server sshd[27751]: Did not receive identification string from 172.19.131.174 port 40876
    Jan 23 16:23:04 intranet-server sshd[15014]: pam_unix(sshd:session): session closed for user jhall
    Jan 23 06:39:01 intranet-server CRON[23064]: pam_unix(cron:session): session opened for user root by (uid=0)
    Jan 24 04:37:40 intranet-server su[27950]: Successful su for jhall by www-data
    Jan 24 04:37:40 intranet-server su[27950]: + /dev/pts/1 www-data:jhall
    Jan 23 16:30:47 intranet-server systemd-logind[957]: New session 271 of user jhall.
    Jan 23 16:23:04 intranet-server systemd-logind[957]: Removed session 111.
    Jan 24 04:37:58 intranet-server sudo:    jhall : TTY=pts/1 ; PWD=/var/... ; USER=root ; COMMAND=/bin/cat /etc/shadow
    Jan 23 16:30:47 intranet-server systemd: pam_unix(systemd-user:session): session opened for user jhall by (uid=0)
    Jan 20 12:54:24 davey-mail dovecot: pam_unix(dovecot:auth): authentication failure; logname= uid=0 euid=0 \
        tty=dovecot ruser=shane.watson rhost=192.168.231.56  user=shane.watson

관측되지 않은 메시지(sshd Failed password/Invalid user 등)는 이 데이터셋에 존재하지 않아 구현하지 않았다.

dovecot 인증 실패 패턴은 mail 계열 호스트(davey_mail/mail/morris_mail)의 auth.log에서
실제로 21건(사용자 6명) 확인했으며, 21건 모두 동일한 필드 구성(logname 비어있음,
uid=0, euid=0, tty=dovecot, ruser==user)이었다. rhost 뒤에 공백 두 칸을 두고 이어지는
부분에 "user=" 필드가 오는 표준 pam_unix 메시지 형식 그대로다. ruser가 비어 있는
경우는 이 데이터셋에서 관측되지 않아 별도로 다루지 않는다.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from src.models import NormalizedEvent, RawLogLine, make_event_id

SOURCE_TYPE = "syslog_auth"

# russellmitchell 데이터셋의 관측 기간(dataset.yaml: 2022-01-21 ~ 2022-01-25) 기준.
_DEFAULT_YEAR = 2022

_HEADER_RE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2}) +(?P<day>\d{1,2}) "
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2}) "
    r"(?P<syslog_host>\S+) (?P<process>[\w.-]+)(?:\[(?P<pid>\d+)\])?: (?P<msg>.*)$"
)

_PATTERNS = (
    (
        re.compile(
            r"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) "
            r"port (?P<port>\d+) ssh2(?::\s*(?P<detail>.*))?$"
        ),
        "ssh_accepted",
    ),
    (
        re.compile(r"^Did not receive identification string from (?P<ip>\S+) port (?P<port>\d+)$"),
        "ssh_no_identification_string",
    ),
    (
        re.compile(r"^Disconnected from user (?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+)$"),
        "ssh_disconnected",
    ),
    (
        re.compile(
            r"^Received disconnect from (?P<ip>\S+) port (?P<port>\d+):(?P<code>\d+): (?P<reason>.*)$"
        ),
        "ssh_received_disconnect",
    ),
    (
        re.compile(r"^Received signal (?P<signal>\d+); terminating\.$"),
        "ssh_daemon_signal",
    ),
    (
        re.compile(r"^Server listening on (?P<addr>\S+) port (?P<port>\d+)\.$"),
        "ssh_daemon_listening",
    ),
    (
        re.compile(
            r"^pam_unix\((?P<svc>[\w-]+):session\): session opened for user (?P<user>\S+) "
            r"by \(uid=(?P<by_uid>\d+)\)$"
        ),
        "pam_session_opened",
    ),
    (
        re.compile(r"^pam_unix\((?P<svc>[\w-]+):session\): session closed for user (?P<user>\S+)$"),
        "pam_session_closed",
    ),
    (
        re.compile(r"^Successful su for (?P<target_user>\S+) by (?P<by_user>\S+)$"),
        "su_success",
    ),
    (
        re.compile(r"^\+ (?P<tty>\S+) (?P<by_user>[\w.-]+):(?P<target_user>[\w.-]+)$"),
        "su_pty_alloc",
    ),
    (
        re.compile(r"^New session (?P<session_id>\S+) of user (?P<user>\S+)\.$"),
        "logind_new_session",
    ),
    (
        re.compile(r"^Removed session (?P<session_id>\S+)\.$"),
        "logind_removed_session",
    ),
    (
        re.compile(
            r"^\s*(?P<user>\S+) : TTY=(?P<tty>\S+) ; PWD=(?P<pwd>.*?) ; "
            r"USER=(?P<target_user>\S+) ; COMMAND=(?P<command>.*)$"
        ),
        "sudo_command",
    ),
    (
        re.compile(
            r"^pam_unix\(dovecot:auth\): authentication failure; "
            r"logname=(?P<logname>\S*) uid=(?P<uid>\S*) euid=(?P<euid>\S*) tty=(?P<tty>\S*) "
            r"ruser=(?P<ruser>\S*) rhost=(?P<ip>\S+)  user=(?P<user>\S+)$"
        ),
        "dovecot_auth_failure",
    ),
)


def _parse_timestamp(mon: str, day: str, hour: str, minute: str, second: str, year: int) -> datetime | None:
    try:
        return datetime.strptime(
            f"{year} {mon} {int(day):02d} {hour}:{minute}:{second}",
            "%Y %b %d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def parse(raw: RawLogLine, year: int = _DEFAULT_YEAR) -> NormalizedEvent | None:
    header_match = _HEADER_RE.match(raw.raw)
    if header_match is None:
        return None

    fields = header_match.groupdict()
    msg = fields["msg"]
    timestamp = _parse_timestamp(
        fields["mon"], fields["day"], fields["hour"], fields["minute"], fields["second"], year
    )

    event_type = "auth_other"
    user: str | None = None
    src_ip: str | None = None
    extra: dict = {"syslog_host": fields["syslog_host"]}

    for pattern, matched_event_type in _PATTERNS:
        match = pattern.match(msg)
        if match is None:
            continue
        event_type = matched_event_type
        groups = match.groupdict()
        user = groups.get("user")
        src_ip = groups.get("ip")
        extra.update({k: v for k, v in groups.items() if k not in ("user", "ip")})
        break

    return NormalizedEvent(
        event_id=make_event_id(raw),
        source_type=raw.source_type,
        host=raw.host,
        source_path=raw.source_path,
        line_number=raw.line_number,
        timestamp=timestamp,
        raw=raw.raw,
        process=fields["process"],
        pid=int(fields["pid"]) if fields["pid"] else None,
        user=user,
        src_ip=src_ip,
        dst_ip=None,
        event_type=event_type,
        message=msg,
        extra=extra,
    )
