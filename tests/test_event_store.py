from datetime import datetime, timedelta, timezone
from itertools import islice

import pytest

from src.models import (
    UNDATED_KEY,
    NormalizedEvent,
    date_key,
    dated_path,
    load_events,
    save_events,
    save_events_by_date,
    stream_to_file,
)
from src.models.event_store import PICKLE_BATCH_SIZE


def _events() -> list[NormalizedEvent]:
    return [
        NormalizedEvent(
            event_id="gather/intranet_server/logs/auth.log:4",
            source_type="syslog_auth",
            host="intranet_server",
            source_path="gather/intranet_server/logs/auth.log",
            line_number=4,
            timestamp=datetime(2022, 1, 23, 16, 30, 46, tzinfo=timezone.utc),
            raw="Jan 23 16:30:46 intranet-server sshd[25184]: Accepted publickey for jhall ...",
            process="sshd",
            pid=25184,
            user="jhall",
            src_ip="172.19.131.174",
            event_type="ssh_accepted",
            message="Accepted publickey for jhall ...",
            extra={"port": "49828", "method": "publickey", "syslog_host": "intranet-server"},
        ),
        # timestamp가 없는 이벤트도 왕복해야 한다 (apache_error_unstructured 등)
        NormalizedEvent(
            event_id="gather/cloud_share/logs/apache2/error.log.2:3",
            source_type="apache_error",
            host="cloud_share",
            source_path="gather/cloud_share/logs/apache2/error.log.2",
            line_number=3,
            timestamp=None,
            raw="mkdir failed on directory /var/run/samba/msg.lock: Permission denied",
            event_type="apache_error_unstructured",
            message="mkdir failed on directory /var/run/samba/msg.lock: Permission denied",
        ),
    ]


@pytest.mark.parametrize("filename", ["events.pkl", "events.pickle", "events.jsonl"])
def test_save_and_load_roundtrip(tmp_path, filename):
    original = _events()
    path = tmp_path / filename

    written = save_events(original, path)
    assert written == len(original)
    assert path.exists()

    restored = list(load_events(path))
    assert restored == original


def test_roundtrip_preserves_timezone_aware_timestamp(tmp_path):
    path = tmp_path / "events.jsonl"
    save_events(_events(), path)

    restored = list(load_events(path))
    assert restored[0].timestamp == datetime(2022, 1, 23, 16, 30, 46, tzinfo=timezone.utc)
    assert restored[0].timestamp.tzinfo is not None
    assert restored[1].timestamp is None


def test_stream_to_file_passes_events_through(tmp_path):
    path = tmp_path / "events.pkl"

    # 저장과 집계를 한 번의 순회로 처리할 수 있어야 한다.
    passed_through = list(stream_to_file(_events(), path))

    assert [e.event_id for e in passed_through] == [e.event_id for e in _events()]
    assert list(load_events(path)) == _events()


def test_load_events_is_lazy(tmp_path):
    path = tmp_path / "events.pkl"
    save_events(_events(), path)

    first = next(load_events(path))
    assert first.event_id == "gather/intranet_server/logs/auth.log:4"


def _many_events(count: int):
    for i in range(count):
        yield NormalizedEvent(
            event_id=f"h:dnsmasq:{i}",
            source_type="dnsmasq",
            host="inet-firewall",
            source_path="gather/inet-firewall/logs/dnsmasq.log",
            line_number=i,
            timestamp=datetime(2022, 1, 21, tzinfo=timezone.utc),
            raw=f"line {i}",
            event_type="dns_query",
            message=f"line {i}",
        )


def test_pickle_batching_handles_partial_trailing_batch(tmp_path):
    """배치 크기의 배수가 아닌 건수도 하나도 빠짐없이 복원되어야 한다."""
    path = tmp_path / "events.pkl"
    count = PICKLE_BATCH_SIZE * 2 + 7

    assert save_events(_many_events(count), path) == count

    restored = list(load_events(path))
    assert len(restored) == count
    assert [e.line_number for e in restored] == list(range(count))


def _dated_event(day: int, hour: int = 0, event_id: str | None = None) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id or f"h:dnsmasq:{day}-{hour}",
        source_type="dnsmasq",
        host="inet-firewall",
        source_path="gather/inet-firewall/logs/dnsmasq.log",
        line_number=day * 100 + hour,
        timestamp=datetime(2022, 1, day, hour, tzinfo=timezone.utc),
        raw="raw",
        event_type="dns_query",
        message="msg",
    )


@pytest.mark.parametrize("suffix", [".pkl", ".jsonl"])
def test_save_by_date_splits_into_one_file_per_utc_date(tmp_path, suffix):
    events = [
        _dated_event(21, 0),
        _dated_event(21, 23),
        _dated_event(22, 12),
        _dated_event(24, 5),
    ]
    base = tmp_path / f"events{suffix}"

    assert save_events_by_date(events, base) == 4

    assert sorted(p.name for p in tmp_path.iterdir()) == [
        f"events_2022-01-21{suffix}",
        f"events_2022-01-22{suffix}",
        f"events_2022-01-24{suffix}",
    ]
    day21 = list(load_events(dated_path(base, "2022-01-21")))
    assert len(day21) == 2
    assert all(e.timestamp.day == 21 for e in day21)


def test_save_by_date_keeps_events_without_timestamp(tmp_path):
    """날짜를 알 수 없다고 버리면 원본에 있던 내용이 사라진다."""
    base = tmp_path / "events.pkl"
    undated = _events()[1]
    assert undated.timestamp is None

    save_events_by_date([_dated_event(21), undated], base)

    restored = list(load_events(dated_path(base, UNDATED_KEY)))
    assert restored == [undated]


def test_save_by_date_handles_unsorted_input(tmp_path):
    """이벤트는 호스트별 파일 순서로 들어오므로 날짜순으로 정렬되어 있지 않다."""
    base = tmp_path / "events.pkl"
    events = [_dated_event(24), _dated_event(21), _dated_event(24, 9), _dated_event(21, 9)]

    save_events_by_date(events, base)

    assert len(list(load_events(dated_path(base, "2022-01-21")))) == 2
    assert len(list(load_events(dated_path(base, "2022-01-24")))) == 2


def test_save_by_date_splits_across_pickle_batch_boundary(tmp_path):
    base = tmp_path / "events.pkl"
    per_day = PICKLE_BATCH_SIZE + 3
    events = [_dated_event(21, event_id=f"a{i}") for i in range(per_day)]
    events += [_dated_event(22, event_id=f"b{i}") for i in range(per_day)]

    save_events_by_date(events, base)

    assert len(list(load_events(dated_path(base, "2022-01-21")))) == per_day
    assert len(list(load_events(dated_path(base, "2022-01-22")))) == per_day


def test_date_key_uses_utc(tmp_path):
    # +09:00 22일 03시는 UTC로는 21일이다.
    event = _dated_event(21)
    event.timestamp = datetime(2022, 1, 22, 3, tzinfo=timezone(timedelta(hours=9)))
    assert date_key(event) == "2022-01-21"


def test_stream_to_file_flushes_when_consumer_stops_early(tmp_path):
    """소비자가 중간에 멈춰도 이미 넘어간 이벤트는 파일에 남아야 한다."""
    path = tmp_path / "events.pkl"
    taken = 5

    stream = stream_to_file(_many_events(PICKLE_BATCH_SIZE * 2), path)
    consumed = list(islice(stream, taken))
    stream.close()

    assert len(consumed) == taken
    assert len(list(load_events(path))) == taken
