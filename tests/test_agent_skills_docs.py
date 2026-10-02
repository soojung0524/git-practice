"""SKILLS.md와 wrapper 코드의 불일치를 막는 검증.

SKILLS.md에 실제로 존재하지 않는 detector를 적거나, wrapper가 문서에 없는 source_type을
읽는 상황을 테스트로 차단한다. 의존 방향(agent_skills -> src)도 함께 검사한다.
"""

import importlib
import re
from pathlib import Path

import pytest

import src.skills as src_skills
from src.parser.registry import GAIA_FILE_TYPES, LOG_FILE_TYPES

PROJECT_ROOT = Path(__file__).resolve().parent.parent
AGENT_SKILLS_ROOT = PROJECT_ROOT / "agent_skills"

# (Skill 디렉터리명, wrapper 모듈 경로)
SKILLS = [
    ("application_analysis", "run_application_analysis"),
    ("server_analysis", "run_server_analysis"),
    ("network_analysis", "run_network_analysis"),
    ("authentication_analysis", "run_authentication_analysis"),
    ("security_analysis", "run_security_analysis"),
]

REQUIRED_SECTIONS = [
    "## 1. Skill 이름",
    "## 2. 목적",
    "## 3. 언제 사용하는지",
    "## 4. 입력",
    "## 5. 출력",
    "## 6. 사용하는 기존 detector 함수",
    "## 7. 사용 가능한 source_type / event_type",
    "## 8. 제약사항",
    "## 9. 사용하면 안 되는 경우",
    "## 10. 실행 script",
]

# 아직 구현되지 않은 함수 이름. detector 목록 절에 등장하면 안 된다.
NOT_IMPLEMENTED_NAMES = [
    "find_login_failure",
    "find_bruteforce_pattern",
    "find_dns_anomaly",
    "find_vpn_anomaly",
    "find_privilege_event",
    "find_trace_failure",
    "find_http_error_spike",
]

REAL_SOURCE_TYPES = {source_type for _, source_type, _ in (*LOG_FILE_TYPES, *GAIA_FILE_TYPES)}


def _skills_md(skill_dir: str) -> str:
    return (AGENT_SKILLS_ROOT / skill_dir / "SKILLS.md").read_text(encoding="utf-8")


def _wrapper_module(skill_dir: str, module_name: str):
    return importlib.import_module(f"agent_skills.{skill_dir}.scripts.{module_name}")


def _section_body(text: str, heading: str) -> str:
    """해당 `## n.` 절의 본문만 잘라낸다(다음 `## ` 직전까지)."""
    start = text.index(heading) + len(heading)
    rest = text[start:]
    next_heading = re.search(r"\n## ", rest)
    return rest[: next_heading.start()] if next_heading else rest


def _backticked(text: str) -> set[str]:
    return set(re.findall(r"`([^`]+)`", text))


# ---------------------------------------------------------------------------
# 파일 구조
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("skill_dir,module_name", SKILLS)
def test_skill_package_has_skills_md_and_script(skill_dir, module_name):
    assert (AGENT_SKILLS_ROOT / skill_dir / "SKILLS.md").is_file()
    assert (AGENT_SKILLS_ROOT / skill_dir / "scripts" / f"{module_name}.py").is_file()


@pytest.mark.parametrize("skill_dir,module_name", SKILLS)
def test_skills_md_has_all_required_sections(skill_dir, module_name):
    text = _skills_md(skill_dir)
    for section in REQUIRED_SECTIONS:
        assert section in text, f"{skill_dir}/SKILLS.md에 '{section}' 절이 없다"


@pytest.mark.parametrize("skill_dir,module_name", SKILLS)
def test_wrapper_declares_skill_metadata(skill_dir, module_name):
    module = _wrapper_module(skill_dir, module_name)
    assert module.SKILL_NAME == skill_dir
    assert isinstance(module.DETECTORS, tuple)
    assert isinstance(module.SOURCE_TYPES, tuple)


# ---------------------------------------------------------------------------
# 문서에 적힌 detector == 코드가 선언한 detector == 실제 존재하는 함수
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("skill_dir,module_name", SKILLS)
def test_documented_detectors_match_code_and_exist(skill_dir, module_name):
    module = _wrapper_module(skill_dir, module_name)
    body = _section_body(_skills_md(skill_dir), "## 6. 사용하는 기존 detector 함수")
    documented = {name for name in _backticked(body) if name.startswith("find_")}

    assert documented == set(module.DETECTORS), (
        f"{skill_dir}: SKILLS.md의 detector({sorted(documented)})와 "
        f"DETECTORS({sorted(module.DETECTORS)})가 다르다"
    )
    for name in module.DETECTORS:
        assert hasattr(src_skills, name), f"{name}은 src.skills에 존재하지 않는다"
        assert callable(getattr(src_skills, name))


@pytest.mark.parametrize("skill_dir,module_name", SKILLS)
def test_detector_section_never_lists_unimplemented_functions(skill_dir, module_name):
    body = _section_body(_skills_md(skill_dir), "## 6. 사용하는 기존 detector 함수")
    for name in NOT_IMPLEMENTED_NAMES:
        assert name not in body, f"{skill_dir}: 미구현 함수 {name}이 detector 목록에 있다"


def test_no_skill_references_a_nonexistent_detector_anywhere():
    # 문서 어디에서든 find_* 이름이 나오면 실제 존재하는 함수여야 한다.
    for skill_dir, _ in SKILLS:
        for name in _backticked(_skills_md(skill_dir)):
            if name.startswith("find_"):
                assert hasattr(src_skills, name), f"{skill_dir}/SKILLS.md: {name} 없음"


def test_declared_detectors_cover_every_implemented_detector():
    # 구현된 detector 5종이 어느 Skill에도 연결되지 않고 방치되지 않게 한다.
    declared = set()
    for skill_dir, module_name in SKILLS:
        declared |= set(_wrapper_module(skill_dir, module_name).DETECTORS)
    assert declared == {
        "find_request_spike",
        "find_scan_pattern",
        "find_log_error_spike",
        "find_latency_anomaly",
        "find_metric_anomaly",
    }


# ---------------------------------------------------------------------------
# 문서에 적힌 source_type == 코드가 선언한 source_type == 실제 registry 값
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("skill_dir,module_name", SKILLS)
def test_documented_source_types_match_code(skill_dir, module_name):
    module = _wrapper_module(skill_dir, module_name)
    body = _section_body(_skills_md(skill_dir), "## 7. 사용 가능한 source_type / event_type")
    line = next(ln for ln in body.splitlines() if ln.strip().startswith("- source_type:"))
    documented = _backticked(line)

    assert documented == set(module.SOURCE_TYPES), (
        f"{skill_dir}: SKILLS.md의 source_type({sorted(documented)})과 "
        f"SOURCE_TYPES({sorted(module.SOURCE_TYPES)})가 다르다"
    )


@pytest.mark.parametrize("skill_dir,module_name", SKILLS)
def test_declared_source_types_are_real_registry_values(skill_dir, module_name):
    module = _wrapper_module(skill_dir, module_name)
    for source_type in module.SOURCE_TYPES:
        assert source_type in REAL_SOURCE_TYPES, f"{source_type}은 registry에 없다"


# ---------------------------------------------------------------------------
# 의존 방향: agent_skills -> src 한쪽뿐
# ---------------------------------------------------------------------------


def test_src_and_evaluation_never_import_agent_skills():
    offenders = []
    for directory in ("src", "evaluation"):
        for path in (PROJECT_ROOT / directory).rglob("*.py"):
            if "agent_skills" in path.read_text(encoding="utf-8"):
                offenders.append(str(path.relative_to(PROJECT_ROOT)))
    assert offenders == [], f"src/evaluation이 agent_skills를 참조한다: {offenders}"


def test_agent_skills_do_not_import_evaluation():
    # 평가는 Agent Skill의 역할이 아니다.
    offenders = []
    for path in AGENT_SKILLS_ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if re.search(r"^\s*(from|import)\s+evaluation", text, re.MULTILINE):
            offenders.append(str(path.relative_to(PROJECT_ROOT)))
    assert offenders == []
