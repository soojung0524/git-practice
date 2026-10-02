import csv
import json
from pathlib import Path

from src.models import RawLogLine
from src.parser import gaia_log, gaia_metric, gaia_trace

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


def _metric_data_lines(filename: str) -> list[str]:
    text = (FIXTURES_DIR / filename).read_text(encoding="utf-8")
    return text.splitlines()[1:]  # 헤더 제외


def _csv_rows(filename: str) -> list[dict]:
    with (FIXTURES_DIR / filename).open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _raw(source_type: str, source_path: str, line_number: int, raw_text: str, host: str = "test-host") -> RawLogLine:
    return RawLogLine(
        host=host,
        source_type=source_type,
        source_path=source_path,
        line_number=line_number,
        raw=raw_text,
    )


# ---------------------------------------------------------------------------
# gaia_metric
# ---------------------------------------------------------------------------

_METRIC_PATH = "metric/dbservice1_0.0.0.4_docker_cpu_core_5_norm_pct_2021-08-01_2021-08-31.csv"


def test_gaia_metric_parses_int_value():
    lines = _metric_data_lines("gaia_metric.csv")
    raw = _raw("gaia_metric", _METRIC_PATH, 1, lines[0], host="dbservice1")
    event = gaia_metric.parse(raw)

    assert event is not None
    assert event.dataset == "gaia"
    assert event.event_type == "gaia_metric_sample"
    assert event.host == "dbservice1"
    assert event.extra["value"] == 0.0
    assert event.extra["ip"] == "0.0.0.4"
    assert event.extra["metric_name"] == "docker_cpu_core_5_norm_pct"
    assert event.extra["metric_category"] == "docker"
    assert event.timestamp is not None
    assert event.timestamp.year == 2021 and event.timestamp.month == 7


def test_gaia_metric_parses_float_value():
    lines = _metric_data_lines("gaia_metric.csv")
    raw = _raw("gaia_metric", _METRIC_PATH, 3, lines[2], host="dbservice1")  # 1627747260000,0.0273
    event = gaia_metric.parse(raw)

    assert event is not None
    assert event.extra["value"] == 0.0273


def test_gaia_metric_filename_parsing_splits_on_ip_token():
    info = gaia_metric.parse_filename(
        "dbservice1_0.0.0.4_docker_cpu_core_5_norm_pct_2021-08-01_2021-08-31"
    )
    assert info == {
        "service": "dbservice1",
        "ip": "0.0.0.4",
        "metric_name": "docker_cpu_core_5_norm_pct",
        "metric_category": "docker",
        "start_date": "2021-08-01",
        "end_date": "2021-08-31",
    }


def test_gaia_metric_filename_parsing_handles_repeated_ip_without_guessing():
    # 실제 관측된 파일명: system_0.0.0.2_0.0.0.2_system_process_memory_share_...
    # ip 토큰이 metric_name 안에도 다시 나오는 경우, 추측해서 더 쪼개지 않고 그대로 둔다.
    info = gaia_metric.parse_filename(
        "system_0.0.0.2_0.0.0.2_system_process_memory_share_2021-08-01_2021-08-31"
    )
    assert info is not None
    assert info["service"] == "system"
    assert info["ip"] == "0.0.0.2"
    assert info["metric_name"] == "0.0.0.2_system_process_memory_share"


def test_gaia_metric_filename_parsing_rejects_unexpected_shape():
    assert gaia_metric.parse_filename("not_a_recognized_shape") is None


def test_gaia_metric_rejects_row_without_exactly_two_columns():
    raw = _raw("gaia_metric", _METRIC_PATH, 1, "not,a,valid,metric,row")
    assert gaia_metric.parse(raw) is None


def test_gaia_metric_handles_non_numeric_value_without_crashing():
    raw = _raw("gaia_metric", _METRIC_PATH, 1, "1627747200000,not_a_number")
    event = gaia_metric.parse(raw)

    assert event is not None
    assert event.extra["value"] is None
    assert event.extra["value_raw"] == "not_a_number"


def test_gaia_metric_rejects_unparseable_timestamp():
    raw = _raw("gaia_metric", _METRIC_PATH, 1, "not_a_timestamp,1")
    assert gaia_metric.parse(raw) is None


# ---------------------------------------------------------------------------
# gaia_trace
# ---------------------------------------------------------------------------


def test_gaia_trace_root_span_has_zero_parent_id():
    rows = _csv_rows("gaia_trace.csv")
    row = rows[0]  # webservice2, parent_id=0, status 500
    raw = _raw(
        "gaia_trace",
        "trace/trace_table_webservice2_2021-07.csv",
        1,
        json.dumps(row, ensure_ascii=False),
        host=row["service_name"],
    )
    event = gaia_trace.parse(raw)

    assert event is not None
    assert event.dataset == "gaia"
    assert event.event_type == "gaia_trace_span"
    assert event.host == "webservice2"
    assert event.extra["parent_id"] == "0"
    assert event.extra["status_code"] == 500
    assert event.extra["trace_id"] == "47b56e46e21a0530"
    assert event.timestamp is not None
    assert event.extra["duration_seconds"] is not None
    assert event.extra["duration_seconds"] > 0


def test_gaia_trace_child_span_has_nonzero_parent_id():
    rows = _csv_rows("gaia_trace.csv")
    row = rows[2]  # dbservice1, parent_id != 0
    raw = _raw(
        "gaia_trace",
        "trace/trace_table_dbservice1_2021-07.csv",
        1,
        json.dumps(row, ensure_ascii=False),
        host=row["service_name"],
    )
    event = gaia_trace.parse(raw)

    assert event is not None
    assert event.host == "dbservice1"
    assert event.extra["parent_id"] == "8b3e4a4003c5119c"
    assert event.extra["status_code"] == 200


def test_gaia_trace_rejects_invalid_json():
    raw = _raw("gaia_trace", "trace/x.csv", 1, "this is not json")
    assert gaia_trace.parse(raw) is None


def test_gaia_trace_rejects_row_missing_required_fields():
    row = {"trace_id": "", "span_id": "x", "start_time": "2021-07-01 00:00:00"}
    raw = _raw("gaia_trace", "trace/x.csv", 1, json.dumps(row))
    assert gaia_trace.parse(raw) is None


# ---------------------------------------------------------------------------
# gaia_log
# ---------------------------------------------------------------------------


def test_gaia_log_structured_error_line_3col():
    rows = _csv_rows("gaia_log_3col.csv")
    row = rows[0]
    raw = _raw(
        "gaia_log",
        "business/business_table_webservice1_2021-07.csv",
        1,
        json.dumps(row, ensure_ascii=False),
        host=row["service"],
    )
    event = gaia_log.parse(raw)

    assert event is not None
    assert event.dataset == "gaia"
    assert event.event_type == "gaia_log_entry"
    assert event.host == "webservice1"
    assert event.extra["level"] == "ERROR"
    assert event.extra["fields"] == [
        "0.0.0.1",
        "webservice1",
        "retry_func.py -> wrapper -> 40",
        "22741016938865b0",
    ]
    assert "Try to get redisservice1" in event.message
    assert event.timestamp is not None
    assert (event.timestamp.month, event.timestamp.day) == (7, 1)


def test_gaia_log_info_line_has_different_middle_field_meaning():
    # 같은 파이프 자리(인덱스 1)가 ERROR 줄에서는 서비스명이지만, 이 INFO 줄에서는
    # 컨테이너 IP다. 그래서 의미를 추측해 이름 붙이지 않고 순서 그대로 보존했는지 확인한다.
    rows = _csv_rows("gaia_log_3col.csv")
    row = rows[-1]
    raw = _raw(
        "gaia_log",
        "business/business_table_webservice1_2021-07.csv",
        6,
        json.dumps(row, ensure_ascii=False),
        host=row["service"],
    )
    event = gaia_log.parse(raw)

    assert event is not None
    assert event.extra["level"] == "INFO"
    assert event.extra["fields"] == ["0.0.0.1", "172.17.0.3", "webservice1", "c124e30fb40651dc"]


def test_gaia_log_4col_variant_reads_by_column_name_not_position():
    rows = _csv_rows("gaia_log_4col.csv")
    row = rows[0]
    raw = _raw(
        "gaia_log",
        "business/business_table_2021-08.csv",
        1,
        json.dumps(row, ensure_ascii=False),
        host=row["service"],
    )
    event = gaia_log.parse(raw)

    assert event is not None
    assert event.host == "dbservice2"
    assert event.extra["level"] == "INFO"


def test_gaia_log_unstructured_fallback_preserves_raw_message():
    row = {"datetime": "2021-07-01", "service": "weird", "message": "no pipes here at all"}
    raw = _raw("gaia_log", "business/x.csv", 1, json.dumps(row))
    event = gaia_log.parse(raw)

    assert event is not None
    assert event.event_type == "gaia_log_unstructured"
    assert event.message == "no pipes here at all"
    assert event.timestamp is None


def test_gaia_log_rejects_invalid_json():
    raw = _raw("gaia_log", "business/x.csv", 1, "this is not json")
    assert gaia_log.parse(raw) is None
