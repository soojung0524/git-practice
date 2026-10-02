import pytest

from src.loader import find_log_files, iter_raw_lines


def _make_dataset(tmp_path):
    host_logs = tmp_path / "gather" / "intranet_server" / "logs"
    (host_logs / "apache2").mkdir(parents=True)
    (host_logs / "audit").mkdir(parents=True)

    (host_logs / "auth.log").write_text(
        "Jan 23 06:39:01 intranet-server CRON[23064]: pam_unix(cron:session): session opened for user root by (uid=0)\n"
        "\n"  # 빈 줄은 건너뛰어야 한다
        "Jan 23 06:39:01 intranet-server CRON[23064]: pam_unix(cron:session): session closed for user root\n",
        encoding="utf-8",
    )
    (host_logs / "dnsmasq.log").write_text(
        "Jan 21 00:00:09 dnsmasq[3468]: query[A] example.com from 10.143.0.103\n",
        encoding="utf-8",
    )
    (host_logs / "audit" / "audit.log").write_text(
        "type=LOGIN msg=audit(1642723741.076:377): pid=10125 uid=0 res=1\n",
        encoding="utf-8",
    )
    (host_logs / "apache2" / "site-access.log").write_text(
        '10.143.2.91 - - [23/Jan/2022:06:36:13 +0000] "GET / HTTP/1.1" 200 6203 "-" "curl/7.0"\n',
        encoding="utf-8",
    )
    # 지원 대상이 아닌 파일은 발견되지 않아야 한다.
    (host_logs / "kern.log").write_text("some unrelated kernel log line\n", encoding="utf-8")

    return tmp_path


def test_find_log_files_only_returns_supported_patterns(tmp_path):
    dataset_root = _make_dataset(tmp_path)
    found = list(find_log_files(dataset_root))
    found_names = sorted(path.name for _, _, path in found)

    assert found_names == ["audit.log", "auth.log", "dnsmasq.log", "site-access.log"]
    assert all(host == "intranet_server" for host, _, _ in found)


def test_find_log_files_raises_when_gather_missing(tmp_path):
    with pytest.raises(FileNotFoundError):
        list(find_log_files(tmp_path / "does-not-exist"))


def test_iter_raw_lines_assigns_line_numbers_and_skips_blank_lines(tmp_path):
    dataset_root = _make_dataset(tmp_path)
    auth_lines = [
        line for line in iter_raw_lines(dataset_root) if line.source_path.endswith("auth.log")
    ]

    assert [line.line_number for line in auth_lines] == [1, 3]
    assert auth_lines[0].host == "intranet_server"
    assert auth_lines[0].source_type == "syslog_auth"
    assert auth_lines[0].source_path == "gather/intranet_server/logs/auth.log"


def test_iter_raw_lines_assigns_source_type_per_file(tmp_path):
    dataset_root = _make_dataset(tmp_path)
    source_types = {line.source_type for line in iter_raw_lines(dataset_root)}

    assert source_types == {"syslog_auth", "dnsmasq", "auditd", "apache_access"}
