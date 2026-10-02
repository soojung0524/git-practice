import json

import pytest

from src.loader import find_gaia_files, iter_raw_rows

_METRIC_NAME = "dbservice1_0.0.0.4_docker_cpu_core_5_norm_pct_2021-08-01_2021-08-31.csv"
_TRACE_NAME = "trace_table_webservice2_2021-07.csv"
_BUSINESS_NAME = "business_table_webservice1_2021-07.csv"


def _make_gaia_root(tmp_path):
    metric_dir = tmp_path / "metric"
    trace_dir = tmp_path / "trace"
    business_dir = tmp_path / "business"
    run_dir = tmp_path / "run" / "run"
    metric_dir.mkdir()
    trace_dir.mkdir()
    business_dir.mkdir()
    run_dir.mkdir(parents=True)

    (metric_dir / _METRIC_NAME).write_text(
        "timestamp,value\n1627747200000,0\n1627747230000,0.0273\n",
        encoding="utf-8",
    )
    (trace_dir / _TRACE_NAME).write_text(
        "timestamp,host_ip,service_name,trace_id,span_id,parent_id,start_time,end_time,url,status_code,message\n"
        "2021-07-01 14:58:03,0.0.0.3,webservice2,47b56e46e21a0530,d1db8a029b58d4ce,0,"
        "2021-07-01 14:57:52.377571,2021-07-01 14:58:02.741081,"
        "http://0.0.0.3:9381/web_login_service,500,request call function 1 webservice2.web_login_service\n",
        encoding="utf-8",
    )
    (business_dir / _BUSINESS_NAME).write_text(
        "datetime,service,message\n"
        '2021-07-01,webservice1,"2021-07-01 09:57:04,258 | ERROR | 0.0.0.1 | webservice1 | '
        'retry_func.py -> wrapper -> 40 | 22741016938865b0 | Try to get redisservice1 inst"\n',
        encoding="utf-8",
    )
    # ground truth(anomaly injection) -- Loader가 절대 읽어서는 안 된다 (작업 7).
    (run_dir / "run_table_2021-07.csv").write_text(
        "datetime,service,message\n"
        '2021-07-01,dbservice1,"2021-07-01 11:54:27,616 | WARNING | ip | svc | [memory_anomalies] trigger"\n',
        encoding="utf-8",
    )
    return tmp_path


def test_find_gaia_files_covers_metric_trace_business_only(tmp_path):
    gaia_root = _make_gaia_root(tmp_path)
    found = list(find_gaia_files(gaia_root))

    found_names = sorted(path.name for _, path in found)
    assert found_names == sorted([_METRIC_NAME, _TRACE_NAME, _BUSINESS_NAME])

    source_types = {source_type for source_type, _ in found}
    assert source_types == {"gaia_metric", "gaia_trace", "gaia_log"}


def test_find_gaia_files_excludes_run_ground_truth(tmp_path):
    gaia_root = _make_gaia_root(tmp_path)
    found_paths = [str(path) for _, path in find_gaia_files(gaia_root)]

    assert not any("run_table" in p for p in found_paths)
    assert not any("\\run\\" in p or "/run/" in p for p in found_paths)


def test_find_gaia_files_raises_when_root_missing(tmp_path):
    with pytest.raises(FileNotFoundError):
        list(find_gaia_files(tmp_path / "does-not-exist"))


def test_iter_raw_rows_metric_uses_filename_service_as_host(tmp_path):
    gaia_root = _make_gaia_root(tmp_path)
    metric_rows = [r for r in iter_raw_rows(gaia_root) if r.source_type == "gaia_metric"]

    assert [r.line_number for r in metric_rows] == [1, 2]
    assert all(r.host == "dbservice1" for r in metric_rows)
    assert metric_rows[0].raw == "1627747200000,0"
    assert metric_rows[0].source_path == f"metric/{_METRIC_NAME}"


def test_iter_raw_rows_trace_uses_row_service_name_as_host_and_json_raw(tmp_path):
    gaia_root = _make_gaia_root(tmp_path)
    trace_rows = [r for r in iter_raw_rows(gaia_root) if r.source_type == "gaia_trace"]

    assert len(trace_rows) == 1
    row = trace_rows[0]
    assert row.host == "webservice2"
    assert row.line_number == 1

    decoded = json.loads(row.raw)
    assert decoded["trace_id"] == "47b56e46e21a0530"
    assert decoded["status_code"] == "500"


def test_iter_raw_rows_business_uses_row_service_as_host_and_json_raw(tmp_path):
    gaia_root = _make_gaia_root(tmp_path)
    business_rows = [r for r in iter_raw_rows(gaia_root) if r.source_type == "gaia_log"]

    assert len(business_rows) == 1
    row = business_rows[0]
    assert row.host == "webservice1"

    decoded = json.loads(row.raw)
    assert "Try to get redisservice1 inst" in decoded["message"]


def test_iter_raw_rows_never_yields_ground_truth(tmp_path):
    gaia_root = _make_gaia_root(tmp_path)
    all_rows = list(iter_raw_rows(gaia_root))

    assert all("run_table" not in r.source_path for r in all_rows)
    assert all("memory_anomalies" not in r.raw for r in all_rows)
