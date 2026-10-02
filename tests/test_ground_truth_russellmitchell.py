import json
from pathlib import Path

from evaluation import load_russellmitchell_ground_truth

AUTH_LOG_LINES = [
    "Jan 24 04:37:40 intranet-server su[27950]: Successful su for jhall by www-data",
    "Jan 24 04:37:40 intranet-server su[27950]: + /dev/pts/1 www-data:jhall",
    "Jan 24 04:37:58 intranet-server sudo:    jhall : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=list",
    "Jan 24 06:00:00 intranet-server sudo:    jhall : TTY=pts/1 ; PWD=/var/www ; USER=root ; COMMAND=ls",
]


def _write_dataset(root: Path, *, labels: list[dict], auth_lines: list[str] = AUTH_LOG_LINES) -> Path:
    gather_auth = root / "gather" / "intranet_server" / "logs" / "auth.log"
    gather_auth.parent.mkdir(parents=True, exist_ok=True)
    gather_auth.write_text("\n".join(auth_lines) + "\n", encoding="utf-8")

    labels_auth = root / "labels" / "intranet_server" / "logs" / "auth.log"
    labels_auth.parent.mkdir(parents=True, exist_ok=True)
    labels_auth.write_text("\n".join(json.dumps(row) for row in labels) + "\n", encoding="utf-8")
    return root


def test_load_builds_incident_with_correct_time_range_and_host(tmp_path):
    root = _write_dataset(
        tmp_path,
        labels=[
            {"line": 1, "labels": ["attacker_change_user", "escalate"], "rules": {}},
            {"line": 3, "labels": ["escalate", "escalated_command"], "rules": {}},
        ],
    )
    incidents = load_russellmitchell_ground_truth(root, max_gap_seconds=300)
    escalate = [i for i in incidents if i.anomaly_type == "escalate"]
    assert len(escalate) == 1
    incident = escalate[0]
    assert incident.dataset == "russellmitchell"
    assert incident.host == "intranet_server"
    assert incident.service is None
    # line 1 (04:37:40) ~ line 3 (04:37:58), 간격이 짧아 하나로 묶여야 한다.
    assert incident.start_time.hour == 4 and incident.start_time.minute == 37
    assert incident.end_time.second == 58
    assert incident.entities.get("user") == ["jhall"]
    assert len(incident.evidence_event_ids) == 2


def test_time_gap_splits_into_separate_incidents(tmp_path):
    root = _write_dataset(
        tmp_path,
        labels=[
            {"line": 3, "labels": ["escalated_command"], "rules": {}},  # 04:37:58
            {"line": 4, "labels": ["escalated_command"], "rules": {}},  # 06:00:00, gap 큼
        ],
    )
    incidents = load_russellmitchell_ground_truth(root, max_gap_seconds=60)
    matching = [i for i in incidents if i.anomaly_type == "escalated_command"]
    assert len(matching) == 2


def test_time_gap_within_threshold_merges_into_one_incident(tmp_path):
    root = _write_dataset(
        tmp_path,
        labels=[
            {"line": 3, "labels": ["escalated_command"], "rules": {}},
            {"line": 4, "labels": ["escalated_command"], "rules": {}},
        ],
    )
    # line 3(04:37:58) ~ line 4(06:00:00): 간격 약 5,522초. 넉넉한 gap을 주면 하나로 묶인다.
    incidents = load_russellmitchell_ground_truth(root, max_gap_seconds=6000)
    matching = [i for i in incidents if i.anomaly_type == "escalated_command"]
    assert len(matching) == 1
    assert matching[0].start_time.second == 58


def test_unparseable_log_format_is_skipped_not_guessed(tmp_path):
    # 이 프로젝트에 파서가 없는 로그 형식(CPU 모니터링 로그)을 흉내낸다.
    cpu_gather = tmp_path / "gather" / "monitoring" / "logs" / "logstash" / "intranet-server" / "cpu.log"
    cpu_gather.parent.mkdir(parents=True, exist_ok=True)
    cpu_gather.write_text("some,unparseable,csv,line\n", encoding="utf-8")

    cpu_labels = tmp_path / "labels" / "monitoring" / "logs" / "logstash" / "intranet-server" / "cpu.log"
    cpu_labels.parent.mkdir(parents=True, exist_ok=True)
    cpu_labels.write_text(json.dumps({"line": 1, "labels": ["crack_passwords"], "rules": {}}) + "\n", encoding="utf-8")

    incidents = load_russellmitchell_ground_truth(tmp_path)
    assert incidents == []


def test_missing_labels_directory_returns_empty_list(tmp_path):
    (tmp_path / "gather").mkdir()
    assert load_russellmitchell_ground_truth(tmp_path) == []


def test_multiple_labels_on_same_line_produce_separate_incident_groups(tmp_path):
    root = _write_dataset(
        tmp_path,
        labels=[{"line": 1, "labels": ["attacker_change_user", "escalate"], "rules": {}}],
    )
    incidents = load_russellmitchell_ground_truth(root)
    types = {i.anomaly_type for i in incidents}
    assert types == {"attacker_change_user", "escalate"}
