"""GAIA -> Loader -> Parser -> NormalizedEvent 전체 흐름을 실제 데이터 형식의
샘플로 검증한다 (작업 8: end-to-end 확인).

tests/fixtures/gaia_*.csv 에 있는, 실제 GAIA MicroSS 파일에서 그대로 발췌한 내용을
metric/trace/business 디렉터리 구조로 배치한 뒤 gaia_loader + parse_lines를
그대로 통과시킨다.
"""

from src.loader import iter_raw_rows
from src.parser import parse_lines
from src.skills import summarize_events

FIXTURES_DIR_NAME = "fixtures"


def _make_real_sample_gaia_root(tmp_path):
    import shutil
    from pathlib import Path

    fixtures = Path(__file__).resolve().parent / FIXTURES_DIR_NAME

    metric_dir = tmp_path / "metric"
    trace_dir = tmp_path / "trace"
    business_dir = tmp_path / "business"
    metric_dir.mkdir()
    trace_dir.mkdir()
    business_dir.mkdir()

    shutil.copy(
        fixtures / "gaia_metric.csv",
        metric_dir / "dbservice1_0.0.0.4_docker_cpu_core_5_norm_pct_2021-08-01_2021-08-31.csv",
    )
    shutil.copy(fixtures / "gaia_trace.csv", trace_dir / "trace_table_sample_2021-07.csv")
    shutil.copy(
        fixtures / "gaia_log_3col.csv",
        business_dir / "business_table_webservice1_2021-07.csv",
    )
    shutil.copy(fixtures / "gaia_log_4col.csv", business_dir / "business_table_2021-08.csv")

    return tmp_path


def test_gaia_end_to_end_produces_normalized_events_for_all_three_formats(tmp_path):
    gaia_root = _make_real_sample_gaia_root(tmp_path)

    events = list(parse_lines(iter_raw_rows(gaia_root)))

    assert len(events) > 0
    assert all(e.dataset == "gaia" for e in events)

    source_types = {e.source_type for e in events}
    assert source_types == {"gaia_metric", "gaia_trace", "gaia_log"}

    # 모든 이벤트가 원본 파일까지 추적 가능해야 한다 (작업 6).
    assert all(e.source_path and e.line_number >= 1 for e in events)
    assert all(e.raw for e in events)


def test_gaia_end_to_end_summary_matches_expected_counts(tmp_path):
    gaia_root = _make_real_sample_gaia_root(tmp_path)

    events = parse_lines(iter_raw_rows(gaia_root))
    summary = summarize_events(events)

    assert summary.by_source_type["gaia_metric"] == 5
    assert summary.by_source_type["gaia_trace"] == 4
    # 3컬럼 파일 6행 + 4컬럼 파일 2행
    assert summary.by_source_type["gaia_log"] == 8

    assert "webservice2" in summary.by_host
    assert "dbservice1" in summary.by_host
    assert "webservice1" in summary.by_host
    assert "dbservice2" in summary.by_host
