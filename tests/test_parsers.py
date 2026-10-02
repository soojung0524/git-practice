from pathlib import Path

from src.models import RawLogLine, make_event_id
from src.parser import apache_access, apache_error, auditd, dnsmasq, openvpn, syslog_auth

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _load_lines(filename: str) -> list[str]:
    text = (FIXTURES_DIR / filename).read_text(encoding="utf-8")
    return [line for line in text.splitlines() if line]


def _raw(source_type: str, filename: str, line_number: int, raw: str) -> RawLogLine:
    return RawLogLine(
        host="test-host",
        source_type=source_type,
        source_path=f"gather/test-host/logs/{filename}",
        line_number=line_number,
        raw=raw,
    )


# ---------------------------------------------------------------------------
# event_id
# ---------------------------------------------------------------------------


def test_event_id_does_not_collide_across_rotated_files():
    """auth.log와 auth.log.1은 host/source_type이 같고 줄 번호도 1부터 다시 시작한다."""
    line = "Jan 23 06:39:01 intranet-server CRON[1]: pam_unix(cron:session): session closed for user root"
    current = RawLogLine(
        host="davey_mail",
        source_type="syslog_auth",
        source_path="gather/davey_mail/logs/auth.log",
        line_number=1,
        raw=line,
    )
    rotated = RawLogLine(
        host="davey_mail",
        source_type="syslog_auth",
        source_path="gather/davey_mail/logs/auth.log.1",
        line_number=1,
        raw=line,
    )

    assert make_event_id(current) != make_event_id(rotated)
    assert syslog_auth.parse(current).event_id != syslog_auth.parse(rotated).event_id


def test_event_id_matches_labels_join_key():
    """labels/ 의 정답 파일이 (상대 경로, 줄 번호)로 매겨져 있어 그대로 조인 키가 된다."""
    raw = _raw("syslog_auth", "auth.log", 145, "irrelevant")
    assert make_event_id(raw) == "gather/test-host/logs/auth.log:145"


# ---------------------------------------------------------------------------
# dnsmasq
# ---------------------------------------------------------------------------


def test_dnsmasq_query():
    lines = _load_lines("dnsmasq.log")
    event = dnsmasq.parse(_raw("dnsmasq", "dnsmasq.log", 1, lines[0]))
    assert event is not None
    assert event.event_type == "dns_query"
    assert event.process == "dnsmasq"
    assert event.pid == 3468
    assert event.src_ip == "10.143.0.103"
    assert event.extra["domain"] == "example.com"
    assert event.extra["query_type"] == "A"
    assert event.timestamp is not None
    assert event.timestamp.year == 2022 and event.timestamp.month == 1 and event.timestamp.day == 21


def test_dnsmasq_forwarded_and_reply():
    lines = _load_lines("dnsmasq.log")
    forwarded = dnsmasq.parse(_raw("dnsmasq", "dnsmasq.log", 2, lines[1]))
    reply = dnsmasq.parse(_raw("dnsmasq", "dnsmasq.log", 3, lines[2]))

    assert forwarded.event_type == "dns_forwarded"
    assert forwarded.dst_ip == "192.168.231.254"

    assert reply.event_type == "dns_reply"
    assert reply.extra["answer"] == "195.128.194.168"


def test_dnsmasq_cached_and_nameserver_and_fallback():
    lines = _load_lines("dnsmasq.log")
    cached = dnsmasq.parse(_raw("dnsmasq", "dnsmasq.log", 9, lines[8]))
    nameserver = dnsmasq.parse(_raw("dnsmasq", "dnsmasq.log", 10, lines[9]))
    fallback = dnsmasq.parse(_raw("dnsmasq", "dnsmasq.log", 11, lines[10]))

    assert cached.event_type == "dns_cached"
    assert cached.extra["answer"] == "<CNAME>"

    assert nameserver.event_type == "dns_nameserver"
    assert nameserver.dst_ip == "127.0.0.1"

    assert fallback.event_type == "dns_other"
    assert "failed to access" in fallback.message


def test_dnsmasq_rejects_unrelated_line():
    unrelated = _raw("dnsmasq", "dnsmasq.log", 1, "this is not a dnsmasq line")
    assert dnsmasq.parse(unrelated) is None


# ---------------------------------------------------------------------------
# syslog_auth
# ---------------------------------------------------------------------------


def test_auth_ssh_accepted_and_sessions():
    lines = _load_lines("auth.log")
    accepted = syslog_auth.parse(_raw("syslog_auth", "auth.log", 4, lines[3]))
    assert accepted.event_type == "ssh_accepted"
    assert accepted.user == "jhall"
    assert accepted.src_ip == "172.19.131.174"
    assert accepted.extra["port"] == "49828"
    assert accepted.process == "sshd"
    assert accepted.pid == 25184

    opened = syslog_auth.parse(_raw("syslog_auth", "auth.log", 1, lines[0]))
    assert opened.event_type == "pam_session_opened"
    assert opened.user == "root"
    assert opened.process == "CRON"


def test_auth_sudo_command_and_su():
    lines = _load_lines("auth.log")
    sudo_event = syslog_auth.parse(_raw("syslog_auth", "auth.log", 13, lines[12]))
    assert sudo_event.event_type == "sudo_command"
    assert sudo_event.user == "jhall"
    assert sudo_event.extra["target_user"] == "root"
    assert sudo_event.extra["command"] == "/bin/cat /etc/shadow"

    su_event = syslog_auth.parse(_raw("syslog_auth", "auth.log", 10, lines[9]))
    assert su_event.event_type == "su_success"
    assert su_event.extra["target_user"] == "jhall"
    assert su_event.extra["by_user"] == "www-data"


def test_auth_logind_sessions():
    lines = _load_lines("auth.log")
    new_session = syslog_auth.parse(_raw("syslog_auth", "auth.log", 8, lines[7]))
    assert new_session.event_type == "logind_new_session"
    assert new_session.user == "jhall"
    assert new_session.extra["session_id"] == "271"


def test_auth_dovecot_authentication_failure():
    lines = _load_lines("auth.log")
    event = syslog_auth.parse(_raw("syslog_auth", "auth.log", 16, lines[15]))
    assert event is not None
    assert event.event_type == "dovecot_auth_failure"
    assert event.user == "shane.watson"
    assert event.src_ip == "192.168.231.56"
    assert event.extra["ruser"] == "shane.watson"
    assert event.extra["tty"] == "dovecot"
    assert event.extra["logname"] == ""
    assert event.process == "dovecot"


def test_auth_unmatched_message_falls_back():
    raw = _raw(
        "syslog_auth",
        "auth.log",
        1,
        "Jan 23 06:39:01 intranet-server sshd[1]: something we never modeled happened",
    )
    event = syslog_auth.parse(raw)
    assert event is not None
    assert event.event_type == "auth_other"
    assert event.user is None


# ---------------------------------------------------------------------------
# auditd
# ---------------------------------------------------------------------------


def test_auditd_nested_msg_fields():
    lines = _load_lines("audit.log")
    event = auditd.parse(_raw("auditd", "audit.log", 1, lines[0]))
    assert event.event_type == "audit_user_acct"
    assert event.user == "root"
    assert event.process == "/usr/sbin/cron"
    assert event.pid == 1716
    assert event.extra["res"] == "success"
    assert event.timestamp is not None


def test_auditd_flat_syscall_and_avc():
    lines = _load_lines("audit.log")
    syscall_event = auditd.parse(_raw("auditd", "audit.log", 6, lines[5]))
    assert syscall_event.event_type == "audit_syscall"
    assert syscall_event.process == "/sbin/apparmor_parser"
    assert syscall_event.pid == 23662

    avc_event = auditd.parse(_raw("auditd", "audit.log", 7, lines[6]))
    assert avc_event.event_type == "audit_avc"
    assert avc_event.process == "apparmor_parser"
    assert avc_event.user is None


def test_auditd_login_extracts_ip():
    lines = _load_lines("audit.log")
    login_event = auditd.parse(_raw("auditd", "audit.log", 9, lines[8]))
    assert login_event.event_type == "audit_user_login"
    assert login_event.src_ip == "172.19.131.174"
    assert login_event.process == "/usr/sbin/sshd"


def test_auditd_rejects_unrelated_line():
    unrelated = _raw("auditd", "audit.log", 1, "this is not an audit line")
    assert auditd.parse(unrelated) is None


# ---------------------------------------------------------------------------
# apache_access
# ---------------------------------------------------------------------------


def test_apache_access_parses_combined_log_format():
    lines = _load_lines("access.log")
    event = apache_access.parse(_raw("apache_access", "access.log", 1, lines[0]))
    assert event.event_type == "http_request"
    assert event.src_ip == "10.143.2.91"
    assert event.extra["method"] == "GET"
    assert event.extra["path"] == "/"
    assert event.extra["status"] == 200
    assert event.extra["size"] == 6203
    assert event.user is None
    assert event.timestamp is not None
    assert event.timestamp.year == 2022


def test_apache_access_parses_vhost_combined_format():
    lines = _load_lines("access.log")
    event = apache_access.parse(_raw("apache_access", "other_vhosts_access.log", 3, lines[2]))
    assert event.event_type == "http_request"
    assert event.src_ip == "172.19.130.68"
    assert event.extra["vhost"] == "cloud.dmz.smith.russellmitchell.com"
    assert event.extra["vhost_port"] == 443
    assert event.extra["method"] == "GET"
    assert event.extra["status"] == 302


def test_apache_access_plain_combined_has_no_vhost_fields():
    lines = _load_lines("access.log")
    event = apache_access.parse(_raw("apache_access", "access.log", 1, lines[0]))
    assert "vhost" not in event.extra


def test_apache_access_rejects_unrelated_line():
    unrelated = _raw("apache_access", "access.log", 1, "this is not an access log line")
    assert apache_access.parse(unrelated) is None


# ---------------------------------------------------------------------------
# apache_error
# ---------------------------------------------------------------------------


def test_apache_error_with_client_and_code():
    lines = _load_lines("error.log")
    event = apache_error.parse(_raw("apache_error", "error.log", 1, lines[0]))
    assert event.event_type == "http_error"
    assert event.src_ip == "172.19.131.174"
    assert event.extra["client_port"] == 36072
    assert event.extra["error_code"] == "AH01630"
    assert event.extra["module"] == "authz_core"


def test_apache_error_without_client_or_code():
    lines = _load_lines("error.log")
    without_client = apache_error.parse(_raw("apache_error", "error.log", 2, lines[1]))
    assert without_client.extra["error_code"] is None

    server_message = apache_error.parse(_raw("apache_error", "error.log", 3, lines[2]))
    assert server_message.src_ip is None
    assert server_message.extra["error_code"] == "AH00163"


def test_apache_error_keeps_non_apache_output_as_unstructured():
    lines = _load_lines("error.log")

    samba_line = apache_error.parse(_raw("apache_error", "error.log", 4, lines[3]))
    assert samba_line.event_type == "apache_error_unstructured"
    assert samba_line.timestamp is None
    assert samba_line.message == lines[3]
    assert samba_line.extra == {}

    # 웹셸로 실행된 명령의 stderr도 error.log에 섞여 들어오므로 유실시키지 않는다.
    wget_line = apache_error.parse(_raw("apache_error", "error.log", 5, lines[4]))
    assert wget_line.event_type == "apache_error_unstructured"
    assert "wphashcrack" in wget_line.message
    assert wget_line.line_number == 5


# ---------------------------------------------------------------------------
# openvpn
# ---------------------------------------------------------------------------


def test_openvpn_peer_connection_initiated_form_b():
    lines = _load_lines("openvpn.log")
    event = openvpn.parse(_raw("openvpn", "openvpn.log", 1, lines[0]))
    assert event.event_type == "vpn_peer_connection_initiated"
    assert event.user == "twhite"
    assert event.src_ip == "192.168.230.95"
    assert event.extra["port"] == 60795


def test_openvpn_verify_ok_form_a():
    lines = _load_lines("openvpn.log")
    event = openvpn.parse(_raw("openvpn", "openvpn.log", 2, lines[1]))
    assert event.event_type == "vpn_cert_verify_ok"
    assert event.user == "jhall"
    assert event.src_ip == "192.168.230.165"
    assert event.extra["depth"] == "1"


def test_openvpn_multi_learn_and_tls_error():
    lines = _load_lines("openvpn.log")
    learn_event = openvpn.parse(_raw("openvpn", "openvpn.log", 6, lines[5]))
    assert learn_event.event_type == "vpn_multi_learn"
    assert learn_event.extra["pool_ip"] == "10.9.0.6"

    tls_error_event = openvpn.parse(_raw("openvpn", "openvpn.log", 9, lines[8]))
    assert tls_error_event.event_type == "vpn_tls_error"


def test_openvpn_unclassified_message_falls_back():
    lines = _load_lines("openvpn.log")
    event = openvpn.parse(_raw("openvpn", "openvpn.log", 5, lines[4]))
    assert event.event_type == "vpn_other"
    assert event.message == "peer info: IV_VER=2.4.4"


def test_openvpn_client_prefix_without_username_form_c():
    lines = _load_lines("openvpn.log")
    event = openvpn.parse(_raw("openvpn", "openvpn.log", 10, lines[9]))
    assert event is not None
    assert event.event_type == "vpn_tls_initial_packet"
    assert event.src_ip == "192.168.230.95"
    assert event.extra["port"] == 60795
    # 인증 전 단계라 사용자명이 로그에 없다. 지어내지 않는다.
    assert event.user is None


def test_openvpn_bracket_user_form_still_wins_over_form_c():
    """형태 C를 먼저 매칭하면 "[user]"가 메시지로 빨려 들어가므로 순서를 고정한다."""
    raw = _raw(
        "openvpn",
        "openvpn.log",
        1,
        "2022-01-21 06:30:01 192.168.230.95:60795 [twhite] Peer Connection Initiated with [AF_INET]192.168.230.95:60795",
    )
    event = openvpn.parse(raw)
    assert event.user == "twhite"
    assert event.event_type == "vpn_peer_connection_initiated"
