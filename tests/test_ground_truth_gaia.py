import csv
from pathlib import Path

from evaluation import load_gaia_ground_truth

HEADER = ["datetime", "service", "message"]

ROWS = [
    (
        "2021-07-01",
        "dbservice1",
        "2021-07-01 11:54:27,616 | WARNING | 0.0.0.4 | 172.17.0.3 | dbservice1 | "
        "[memory_anomalies] trigger a high memory program, start at "
        "2021-07-01 11:44:26.882752 and lasts 600 seconds and use 1g memory",
    ),
    (
        "2021-07-26",
        "webservice2",
        "2021-07-26 03:31:34,276 | WARNING | 0.0.0.3 | 172.17.0.4 | webservice2 | "
        "[cpu_anomalies] trigger a parallel fast sorting program , start at "
        "2021-07-26 03:31:34.257418 and lasts 3.0 seconds",
    ),
    (
        "2021-07-01",
        "dbservice1",
        "2021-07-01 12:25:08,804 | WARNING | 0.0.0.4 | 172.17.0.3 | dbservice1 | "
        "[normal memory freed label] lasts ten minutes",
    ),
    (
        "2021-07-20",
        "dbservice1",
        "2021-07-20 03:10:06,148 | ERROR | 0.0.0.4 | 172.17.0.3 | dbservice1 | "
        "upload business logs failed: (pymysql.err.OperationalError) (2003, \"[Errno 111] Connection refused\")",
    ),
    (
        "2021-07-01",
        "mobservice1",
        "2021-07-01 15:03:43,991 | WARNING | 0.0.0.1 | 172.17.0.5 | mobservice1 | "
        "db0ed47426370ed5 | wait for 11 seconds to simulate QR code expiry",
    ),
]


def _write_run_table(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        writer.writerows(ROWS)


def test_load_extracts_only_structured_memory_and_cpu_anomalies(tmp_path):
    _write_run_table(tmp_path / "run" / "run_table_2021-07.csv")
    incidents = load_gaia_ground_truth(tmp_path)

    types = {i.anomaly_type for i in incidents}
    assert types == {"memory_anomalies", "cpu_anomalies"}
    assert len(incidents) == 2  # "normal memory freed", "Errno 111", 무태그 행은 제외된다


def test_start_and_duration_are_parsed_into_start_end_time(tmp_path):
    _write_run_table(tmp_path / "run" / "run_table_2021-07.csv")
    incidents = load_gaia_ground_truth(tmp_path)

    memory = next(i for i in incidents if i.anomaly_type == "memory_anomalies")
    assert memory.start_time.isoformat() == "2021-07-01T11:44:26.882752+00:00"
    assert (memory.end_time - memory.start_time).total_seconds() == 600.0
    assert memory.service == "dbservice1"
    assert memory.host is None
    assert memory.dataset == "gaia"

    cpu = next(i for i in incidents if i.anomaly_type == "cpu_anomalies")
    assert cpu.service == "webservice2"
    assert (cpu.end_time - cpu.start_time).total_seconds() == 3.0


def test_handles_nested_run_run_directory(tmp_path):
    # 실제 배포본은 run/run/run_table_*.csv 처럼 한 단계 더 중첩되기도 한다.
    _write_run_table(tmp_path / "run" / "run" / "run_table_2021-07.csv")
    incidents = load_gaia_ground_truth(tmp_path)
    assert len(incidents) == 2


def test_missing_run_directory_returns_empty_list(tmp_path):
    assert load_gaia_ground_truth(tmp_path) == []


def test_evidence_event_id_traceable_to_source_file_and_row(tmp_path):
    _write_run_table(tmp_path / "run" / "run_table_2021-07.csv")
    incidents = load_gaia_ground_truth(tmp_path)
    memory = next(i for i in incidents if i.anomaly_type == "memory_anomalies")
    assert memory.evidence_event_ids == ("run/run_table_2021-07.csv:1",)
