from src.models import RawLogLine
from src.parser import apache_access, dnsmasq, gaia_log, gaia_metric, gaia_trace, get_parser, parse_lines


def test_get_parser_returns_expected_function_per_source_type():
    assert get_parser("dnsmasq") is dnsmasq.parse
    assert get_parser("apache_access") is apache_access.parse
    assert get_parser("unknown_source_type") is None


def test_get_parser_covers_gaia_source_types_alongside_russellmitchell():
    # 두 데이터셋이 같은 get_parser/parse_lines를 공유하는지 확인한다.
    assert get_parser("gaia_metric") is gaia_metric.parse
    assert get_parser("gaia_trace") is gaia_trace.parse
    assert get_parser("gaia_log") is gaia_log.parse


def test_parse_lines_skips_lines_without_registered_parser():
    raw_lines = [
        RawLogLine(
            host="h",
            source_type="unknown_source_type",
            source_path="gather/h/logs/whatever.log",
            line_number=1,
            raw="irrelevant content",
        ),
        RawLogLine(
            host="h",
            source_type="dnsmasq",
            source_path="gather/h/logs/dnsmasq.log",
            line_number=1,
            raw="Jan 21 00:00:09 dnsmasq[3468]: query[A] example.com from 10.143.0.103",
        ),
    ]

    events = list(parse_lines(raw_lines))

    assert len(events) == 1
    assert events[0].source_type == "dnsmasq"
    assert events[0].event_type == "dns_query"


def test_parse_lines_skips_lines_that_fail_to_match_format():
    raw_lines = [
        RawLogLine(
            host="h",
            source_type="dnsmasq",
            source_path="gather/h/logs/dnsmasq.log",
            line_number=1,
            raw="this does not look like a dnsmasq line",
        )
    ]

    assert list(parse_lines(raw_lines)) == []
