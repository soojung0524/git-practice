from datetime import datetime, timezone

from src.models import NormalizedEvent
from src.skills import summarize_events


def _event(**overrides) -> NormalizedEvent:
    defaults = dict(
        event_id="h:t:1",
        source_type="dnsmasq",
        host="inet-firewall",
        source_path="gather/inet-firewall/logs/dnsmasq.log",
        line_number=1,
        timestamp=datetime(2022, 1, 21, 0, 0, 0, tzinfo=timezone.utc),
        raw="raw line",
        event_type="dns_query",
        user=None,
        message="msg",
    )
    defaults.update(overrides)
    return NormalizedEvent(**defaults)


def test_summarize_events_counts_by_dimension():
    events = [
        _event(host="inet-firewall", source_type="dnsmasq", event_type="dns_query", user=None),
        _event(host="intranet_server", source_type="syslog_auth", event_type="ssh_accepted", user="jhall"),
        _event(host="intranet_server", source_type="syslog_auth", event_type="ssh_accepted", user="jhall"),
    ]

    summary = summarize_events(events)

    assert summary.total_events == 3
    assert summary.by_source_type["dnsmasq"] == 1
    assert summary.by_source_type["syslog_auth"] == 2
    assert summary.by_host["intranet_server"] == 2
    assert summary.by_event_type["ssh_accepted"] == 2
    assert summary.by_user["jhall"] == 2


def test_summarize_events_tracks_time_range_and_ignores_missing_timestamp():
    events = [
        _event(timestamp=datetime(2022, 1, 21, 0, 0, 0, tzinfo=timezone.utc)),
        _event(timestamp=datetime(2022, 1, 25, 12, 0, 0, tzinfo=timezone.utc)),
        _event(timestamp=None),
    ]

    summary = summarize_events(events)

    assert summary.total_events == 3
    assert summary.earliest_timestamp == datetime(2022, 1, 21, 0, 0, 0, tzinfo=timezone.utc)
    assert summary.latest_timestamp == datetime(2022, 1, 25, 12, 0, 0, tzinfo=timezone.utc)


def test_summarize_events_with_no_events():
    summary = summarize_events([])

    assert summary.total_events == 0
    assert summary.earliest_timestamp is None
    assert summary.latest_timestamp is None
