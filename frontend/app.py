"""AWS 보안 사고 대응 대시보드 (Streamlit).

실행 (프로젝트 루트에서):
    uv run streamlit run frontend/app.py
"""

from __future__ import annotations

import sys
import time as _time
from datetime import datetime, time
from pathlib import Path

import pandas as pd
import streamlit as st

# 이 파일과 같은 폴더의 services.py, ui.py 를 어떤 위치에서 실행해도 찾을 수 있게
sys.path.insert(0, str(Path(__file__).resolve().parent))
import services as svc  # noqa: E402
import ui  # noqa: E402

st.set_page_config(page_title="TraceIT", page_icon="🛡️", layout="wide")

_ver = tuple(int(x) for x in st.__version__.split(".")[:2])
if _ver < (1, 44):
    st.error(f"Streamlit 1.44 이상이 필요합니다 (지금 {st.__version__}). `uv add \"streamlit>=1.44\"` 후 다시 실행하세요.")
    st.stop()

st.markdown(ui.CSS, unsafe_allow_html=True)

# ───────────────────────── 상태 ─────────────────────────
ss = st.session_state
ss.setdefault("result", None)        # 지금 보고 있는 분석 결과 (services.serialize_state 형식)
ss.setdefault("history", [])         # 이번 세션에서 실행·불러온 결과들
ss.setdefault("detail_id", None)     # 상세 화면에 띄울 finding_id
ss.setdefault("chat", [])
ss.setdefault("draft_question", "")
ss.setdefault("notes_error", {})     # finding_id -> 오류 메시지 (자동 재시도 막기)

SUBTITLE = "의심되는 보안 사고 상황을 분석하고, AWS 공식 보안 대응 매뉴얼을 기반으로 대응 절차를 안내합니다."
RISK_OPTIONS = list(svc.SEVERITY_ORDER)


def now_text() -> str:
    return datetime.now().strftime("%Y.%m.%d %H:%M")


def html(s: str) -> None:
    st.markdown(s, unsafe_allow_html=True)


def set_result(result: dict) -> None:
    result.setdefault("notes", {})
    ss.result = result
    ss.detail_id = None
    ss.history = [r for r in ss.history if r.get("investigation_id") != result.get("investigation_id")]
    ss.history.insert(0, result)


def open_detail(finding_id: str) -> None:
    ss.detail_id = finding_id
    ss.pop("records_table", None)
    st.switch_page(PAGES["records"])


@st.cache_data(ttl=60, show_spinner=False)
def cached_status() -> tuple[bool, str]:
    return svc.system_status()


# ───────────────────────── 보안상 주의사항 ─────────────────────────
def get_notes(result: dict, finding: dict, auto: bool = True, spinner: bool = False) -> dict | None:
    """탐지 결과의 보안상 주의사항. 없으면 보안 매뉴얼을 검색해 만들고 결과에 저장한다.

    결과 JSON 을 저장하면 주의사항도 함께 저장되므로, 발표 때는 네트워크 없이 보여줄 수 있다.
    """
    skipped = skipped_notes(finding)
    if skipped:
        return skipped
    notes = result.setdefault("notes", {})
    fid = finding["finding_id"]
    if fid in notes:
        return notes[fid]
    if not auto or fid in ss.notes_error:
        return None
    try:
        if spinner:
            with st.spinner("보안 매뉴얼에서 주의사항을 찾는 중…"):
                notes[fid] = svc.security_notes(finding)
        else:
            notes[fid] = svc.security_notes(finding)
        return notes[fid]
    except Exception as e:
        ss.notes_error[fid] = str(e)
        return None


def cached_notes(result: dict, finding: dict | None) -> dict | None:
    """이미 만들어 둔 주의사항만 꺼낸다(새로 만들지 않음)."""
    if finding is None:
        return None
    return skipped_notes(finding) or (result.get("notes") or {}).get(finding["finding_id"])


def skipped_notes(finding: dict) -> dict | None:
    """성능(performance)·자원(resource) 이상은 보안 매뉴얼을 검색하지 않는다(팀 방침).

    보안 사고로 판단된 바 없는 이상을 보안 사고처럼 설명하지 않기 위해서다.
    대신 요청하지 않은 이유를 담은 표시용 값을 돌려준다.
    """
    reason = svc.guidance_skip_reason(finding)
    if not reason:
        return None
    return {"skipped": reason, "sections": {}, "refs": []}


def skipped_body(n: dict) -> str:
    return ui.callout("info", "보안 가이드를 요청하지 않음", [n["skipped"]])


WAITING = '<p class="sx-muted">⏳ 보안 매뉴얼에서 찾는 중… 다른 내용은 먼저 보실 수 있습니다.</p>'
FAILED = '<p class="sx-muted">보안 매뉴얼에서 내용을 가져오지 못했습니다.</p>'


def notes_failed(finding: dict, key: str) -> None:
    err = ss.notes_error.get(finding["finding_id"])
    if err:
        st.warning(f"보안상 주의사항을 가져오지 못했습니다: {err}")
        if st.button("다시 시도", key=key):
            ss.notes_error.pop(finding["finding_id"], None)
            st.rerun()


def notes_preview(notes: dict | None, limit: int = 5, width: int = 70) -> list[str]:
    """카드용 짧은 목록. 항목마다 첫 문장(최대 width 자)만 보여주고, 전체는 상세 화면에서."""
    if not notes or notes.get("skipped"):
        return []
    sec = notes["sections"]
    items = (sec.get("procedure") or sec.get("actions") or sec.get("summary") or [])[:limit]
    out = []
    for text in items:
        first = text.split(". ")[0].rstrip(".")
        out.append(first if len(first) <= width else first[:width].rstrip() + "…")
    return out


def timeline_items(result: dict, current_id: str | None = None, limit: int | None = 6) -> list[dict]:
    found = sorted(result["findings"], key=lambda f: str(f.get("start_time") or ""))
    days = {str(f.get("start_time") or "")[:10] for f in found}
    many_days = len(days) > 1
    items = []
    for f in found:
        start = svc.fmt_time(f.get("start_time"))
        tm = start[5:] if many_days else start[11:]
        sub = " · ".join(x for x in (f.get("host"), ui.RISK.get(f["severity"], ("",))[0]) if x)
        items.append({"time": tm, "title": f["summary"], "sub": sub, "current": f["finding_id"] == current_id})
    if limit and len(items) > limit:
        # 현재 항목이 잘리지 않도록, 현재 항목 주변을 보여준다
        idx = next((i for i, it in enumerate(items) if it["current"]), 0)
        start = max(0, min(idx - limit // 2, len(items) - limit))
        items = items[start:start + limit]
    return items


# ───────────────────────── 화면: 홈 ─────────────────────────
def page_home() -> None:
    html(ui.page_header("사고 대시보드", SUBTITLE, now_text()))
    result = ss.result
    if not result:
        html(ui.card("분석 결과가 없습니다", "search",
                     ui.paragraphs(["사고 분석 화면에서 이벤트 파일을 골라 분석을 실행하거나, 저장해 둔 결과 JSON 을 불러오세요.",
                                    "보안 매뉴얼 화면에서는 분석 없이도 매뉴얼에 바로 질문할 수 있습니다."])))
        c1, c2, _ = st.columns([1, 1, 3])
        if c1.button("사고 분석으로", type="primary", use_container_width=True):
            st.switch_page(PAGES["analyze"])
        if c2.button("보안 매뉴얼로", use_container_width=True):
            st.switch_page(PAGES["docs"])
        return

    top = svc.headline_finding(result)
    if top is None:
        cov = svc.analysis_coverage(result)
        if cov["mismatch"]:
            title = f"선택한 데이터셋({cov['mismatch']['selected']})의 이벤트가 이 파일에 없습니다"
        elif cov["checked"] or not cov["skipped"]:
            title = "분석한 범위에서 탐지된 이상 징후가 없습니다"
        else:
            title = "문제없습니다."
        n_ev = result.get("event_count")
        if cov["mismatch"]:
            desc = (f"이 파일은 {', '.join(cov['mismatch']['in_file'])} 데이터입니다. 사고 분석 화면에서 데이터셋을 "
                    "'파일에 맞춰 자동'으로 두고 다시 분석하세요. ")
        else:
            desc = ""
        desc += f"이벤트 {f'{n_ev:,}' if isinstance(n_ev, int) else '-'}건 중 탐지기가 검사한 로그: {svc.fmt_types(cov['checked'])}."
        if cov["skipped"]:
            desc += f" 검사하지 못한 로그: {svc.fmt_types(cov['skipped'])} (분석 기능이 아직 없음)."
        desc += " 탐지 0건은 '정상'이라는 뜻이 아닙니다."
        html(ui.banner(category="탐지 없음", title=title, desc=desc,
                       occurred="-", updated=svc.fmt_time(result.get("created_at")), severity=None))
    else:
        interp = result.get("interpretation")
        desc = interp.get("overall_summary") if isinstance(interp, dict) else None
        if not isinstance(desc, str):
            others = len(result["findings"]) - 1
            where = f"{top['host']}에서 " if top.get("host") else ""
            desc = (f"{svc.fmt_time(top.get('start_time'))}, {where}{top['finding_type']} 이(가) 탐지되었습니다. "
                    + (f"같은 분석에서 다른 이상 징후 {others}건이 함께 탐지되었습니다." if others else ""))
        html(ui.banner(category=svc.CATEGORY_KO.get(top["category"], top["category"]), title=top["summary"],
                       desc=desc, occurred=svc.fmt_time(top.get("start_time")),
                       updated=svc.fmt_time(result.get("created_at")), severity=top["severity"]))

    left, right = st.columns([2, 1.05], gap="medium")
    with left:
        a, b = st.columns(2, gap="medium")
        with a:
            html(ui.status_card("서버 상황", "server", svc.area_observed(result, "Server")))
        with b:
            html(ui.status_card("네트워크 상황", "network", svc.area_observed(result, "Network")))

        c, d = st.columns(2, gap="medium")
        with c:
            if top is None:
                cov = svc.analysis_coverage(result)
                items = [f"검사한 로그: {svc.fmt_types(cov['checked'])}"]
                if cov["mismatch"]:
                    items.insert(0, f"선택한 데이터셋 {cov['mismatch']['selected']} ≠ 파일의 데이터셋 "
                                    f"{', '.join(cov['mismatch']['in_file'])} → 모든 이벤트가 분석에서 빠짐")
                if cov["skipped"]:
                    items.append(f"검사하지 못한 로그: {svc.fmt_types(cov['skipped'])}")
                items += [f"{name}: {note or status}" for name, status, note in cov["limited"]]
                body = ui.sub("분석 범위") + ui.bullets(items)
            else:
                rest = [f for f in svc.sorted_findings(result) if f["finding_id"] != top["finding_id"]]
                items = svc.finding_bullets(top)[:4]
                if rest:
                    counts = pd.Series([f["severity"] for f in rest]).value_counts()
                    parts = [f"{ui.RISK[s][0]} {counts[s]}" for s in svc.SEVERITY_ORDER if s in counts]
                    items.append(f"함께 탐지된 이상 징후 {len(rest)}건 ({', '.join(parts)})")
                body = ui.sub("조사 내용") + ui.bullets(items)
            html(ui.card("Log 조사 내용", "terminal", body))
        with d:
            notes_slot = st.empty()  # 주의사항은 화면을 다 그린 뒤 마지막에 채운다
        if top is not None and st.button("사건 상세보기 →", key="home_detail", type="primary",
                                         use_container_width=True):
            open_detail(top["finding_id"])

    with right:
        html(ui.timeline(timeline_items(result, top["finding_id"] if top else None)))
        if len(result["findings"]) > 6 and st.button("전체보기 →", key="tl_all", use_container_width=True):
            ss.detail_id = None
            st.switch_page(PAGES["records"])
        refs_slot = st.empty()

    def fill(n: dict | None, waiting: bool = False) -> None:
        if top is None:
            body = ui.bullets(["탐지된 이상 징후가 없어 매뉴얼을 검색하지 않았습니다."])
        elif n and n.get("skipped"):
            body = skipped_body(n)
        elif n:
            body = ui.sub("관련 대응 절차", "list") + ui.bullets(notes_preview(n))
        else:
            body = WAITING if waiting else FAILED
        notes_slot.markdown(ui.card("보안상 주의사항", "book", body), unsafe_allow_html=True)
        refs_slot.markdown(ui.refs((n or {}).get("refs") or []), unsafe_allow_html=True)

    notes = cached_notes(result, top)
    waiting = top is not None and notes is None and top["finding_id"] not in ss.notes_error
    fill(notes, waiting=waiting)          # 1) 모든 카드를 먼저 보여주고
    if waiting:
        notes = get_notes(result, top)    # 2) 마지막에 매뉴얼을 검색해
        fill(notes)                       # 3) 빈 자리를 채운다
    if top is not None:
        with d:
            notes_failed(top, "retry_home")


# ───────────────────────── 화면: 사고 분석 ─────────────────────────
def page_analyze() -> None:
    html(ui.page_header("사고 분석", "로그 이벤트 파일과 분석 범위를 정해 분석을 실행합니다.", now_text()))
    form_col, side_col = st.columns([1.4, 1], gap="large")

    with form_col:
        files = svc.list_event_files()
        with st.form("run"):
            if files:
                event_path = st.selectbox("이벤트 파일 (output/)", files)
            else:
                event_path = st.text_input("이벤트 파일 경로", "output/events.pkl",
                                           help="output/ 아래에서 .pkl 파일을 찾지 못해 직접 입력합니다.")
            c1, c2 = st.columns(2)
            dataset = c1.selectbox("데이터셋", ["(파일에 맞춰 자동)", "gaia", "russellmitchell"],
                                   help="파일과 다른 데이터셋을 고르면 모든 이벤트가 분석에서 빠집니다.")
            inv_id = c2.text_input("사건 ID", placeholder="비우면 자동 생성")
            c3, c4 = st.columns(2)
            host = c3.text_input("호스트", placeholder="전체")
            service = c4.text_input("서비스", placeholder="전체")
            source_types = st.text_input("로그 종류", placeholder="쉼표로 구분, 비우면 전체 (예: apache_access, auditd)")
            use_range = st.checkbox("기간 지정")
            d1, d2, d3, d4 = st.columns(4)
            start_d = d1.date_input("시작일", value=None)
            start_t = d2.time_input("시작 시각", value=time(0, 0))
            end_d = d3.date_input("종료일", value=None)
            end_t = d4.time_input("종료 시각", value=time(23, 59))
            interpret = st.checkbox("LLM 해석 포함", help="OpenAI API 를 호출하므로 시간과 비용이 듭니다.")
            submitted = st.form_submit_button("분석 시작", type="primary", use_container_width=True)

        done = False
        if submitted:
            with st.status("분석 중…", expanded=True) as status:
                try:
                    result = svc.run_analysis(
                        event_path=event_path,
                        investigation_id=inv_id or None,
                        dataset=None if dataset.startswith("(") else dataset,
                        host=host, service=service,
                        start_time=datetime.combine(start_d, start_t) if use_range and start_d else None,
                        end_time=datetime.combine(end_d, end_t) if use_range and end_d else None,
                        source_types=[s.strip() for s in source_types.split(",") if s.strip()],
                        interpret=interpret,
                        on_progress=lambda node: st.write(f"✓ {svc.node_label(node)}"),
                    )
                    set_result(result)
                    status.update(label=f"완료: 탐지 {len(result['findings'])}건", state="complete")
                    done = True
                except Exception as e:
                    status.update(label="분석 실패", state="error")
                    st.exception(e)
        if done:
            st.switch_page(PAGES["home"])  # 분석이 끝나면 대시보드로

    with side_col:
        html(ui.card("저장한 결과 불러오기", "file",
                     ui.paragraphs(["분석을 다시 실행하지 않고 결과를 볼 수 있습니다. 발표 데모에 유용합니다."])))
        uploaded = st.file_uploader("결과 JSON", type="json", label_visibility="collapsed")
        if uploaded is not None and st.button("불러오기", use_container_width=True):
            try:
                set_result(svc.result_from_json(uploaded.getvalue().decode("utf-8")))
                st.switch_page(PAGES["home"])
            except Exception as e:
                st.error(f"불러오기 실패: {e}")

        if ss.history:
            st.markdown("**이번 세션의 분석**")
            labels = {i: f"{r.get('investigation_id')} · 탐지 {len(r['findings'])}건 · {svc.fmt_time(r.get('created_at'))}"
                      for i, r in enumerate(ss.history)}
            cur = next((i for i, r in enumerate(ss.history) if r is ss.result), 0)
            pick = st.radio("분석 선택", list(labels), index=cur, format_func=labels.get, label_visibility="collapsed")
            if ss.history[pick] is not ss.result:
                ss.result = ss.history[pick]
                ss.detail_id = None
                st.rerun()


# ───────────────────────── 화면: 분석 기록 (목록 + 사건 상세) ─────────────────────────
def page_records() -> None:
    result = ss.result
    if not result:
        html(ui.page_header("분석 기록", "탐지된 이상 징후 목록과 사건 상세를 봅니다.", now_text()))
        st.info("분석 결과가 없습니다. 사고 분석 화면에서 분석을 실행하거나 결과를 불러오세요.")
        return
    finding = next((f for f in result["findings"] if f["finding_id"] == ss.detail_id), None)
    if finding is not None:
        render_detail(result, finding)
    else:
        render_list(result)


def render_list(result: dict) -> None:
    html(ui.page_header("분석 기록", "탐지된 이상 징후 목록입니다. 행을 누르면 사건 상세로 이동합니다.", now_text()))
    found = svc.sorted_findings(result)
    counts = pd.Series([f["severity"] for f in found]).value_counts() if found else {}
    chip_items = [("전체", f"{len(found)}건")]
    chip_items += [(ui.RISK[s][0], f"{counts[s]}건") for s in svc.SEVERITY_ORDER if s in counts]
    if result.get("event_count"):
        chip_items.append(("분석 이벤트", f"{result['event_count']:,}건"))
    html(ui.chips(chip_items))

    if result.get("errors"):
        with st.expander(f"분석 중 오류 {len(result['errors'])}건"):
            for name, msg in result["errors"].items():
                st.error(f"**{svc.AREA_LABELS.get(name.capitalize(), name)}**: {msg}")

    if not found:
        st.success("탐지된 이상 징후가 없습니다.")
        return

    f1, f2, f3, f4 = st.columns([1, 1, 1, 2])
    sel_sev = f1.multiselect("위험 단계", RISK_OPTIONS, format_func=lambda s: ui.RISK[s][0])
    sel_cat = f2.multiselect("분류", sorted({f["category"] for f in found}),
                             format_func=lambda c: svc.CATEGORY_KO.get(c, c))
    sel_host = f3.multiselect("호스트", sorted({f["host"] for f in found if f.get("host")}))
    keyword = f4.text_input("검색", placeholder="요약·유형에서 찾기")

    view = [f for f in found
            if (not sel_sev or f["severity"] in sel_sev)
            and (not sel_cat or f["category"] in sel_cat)
            and (not sel_host or f.get("host") in sel_host)
            and (not keyword or keyword.lower() in f"{f['summary']} {f['finding_type']}".lower())]
    st.caption(f"{len(view)} / {len(found)}건")
    if not view:
        return

    table = pd.DataFrame([{
        "위험 단계": ui.RISK[f["severity"]][0],
        "분류": svc.CATEGORY_KO.get(f["category"], f["category"]),
        "요약": f["summary"],
        "호스트": f.get("host") or "-",
        "발생 일시": svc.fmt_time(f.get("start_time")),
        "근거 수": (f.get("metrics") or {}).get("evidence_count", len(f.get("evidence") or [])),
    } for f in view])
    event = st.dataframe(table, hide_index=True, use_container_width=True, on_select="rerun",
                         selection_mode="single-row", key="records_table",
                         column_config={"요약": st.column_config.TextColumn(width="large")})
    rows = event.selection.rows if event and event.selection else []
    if rows:
        ss.detail_id = view[rows[0]]["finding_id"]
        st.rerun()

    with st.expander("분석 영역별 실행 현황"):
        rows_ = []
        for name, a in result["agents"].items():
            label = svc.AREA_LABELS.get(name, name)
            if a is None:
                failed = any(name.lower() in k.lower() for k in result.get("errors") or {})
                rows_.append({"분석 영역": label, "상태": "오류" if failed else "실행 안 함", "입력 이벤트": None, "탐지": None})
            else:
                rows_.append({"분석 영역": label, "상태": a["status"], "입력 이벤트": a["input_item_count"],
                              "탐지": a["finding_count"]})
        st.dataframe(pd.DataFrame(rows_), hide_index=True, use_container_width=True)


def render_detail(result: dict, finding: dict) -> None:
    if st.button("← 목록으로 돌아가기", type="tertiary"):
        ss.detail_id = None
        ss.pop("records_table", None)  # 표 선택을 지워야 상세가 다시 열리지 않는다
        st.rerun()

    html(ui.detail_title(finding["severity"], finding["summary"], [
        ("발생 일시", svc.fmt_time(finding.get("start_time"))),
        ("마지막 업데이트", svc.fmt_time(result.get("created_at"))),
        ("사건 ID", result.get("investigation_id") or "-"),
    ]))

    # 보안상 주의사항은 매뉴얼 검색에 시간이 걸리므로 여기서 기다리지 않는다.
    # 이미 만들어 둔 것이 있으면 바로 쓰고, 없으면 가운데 열에서 만든 뒤 카드를 채운다.
    notes = cached_notes(result, finding)
    bullets = svc.finding_bullets(finding)

    c1, c2, c3, c4 = st.columns(4, gap="small")
    with c1:
        html(ui.status_card("서버 상황", "server", svc.area_observed(result, "Server")))
    with c2:
        html(ui.status_card("네트워크 상황", "network", svc.area_observed(result, "Network")))
    with c3:
        html(ui.card("Log 조사", "terminal", ui.bullets(bullets[:3]), ui.done_badge("조사 완료")))
    with c4:
        notes_slot = st.empty()

    def fill_notes_card(n: dict | None, waiting: bool = False) -> None:
        if n and n.get("skipped"):
            notes_slot.markdown(ui.card("보안상 주의사항", "book", '<p class="sx-muted">이 탐지 유형은 보안 가이드를 '
                                        '요청하지 않습니다. 이유는 아래에 있습니다.</p>'), unsafe_allow_html=True)
        elif n:
            notes_slot.markdown(ui.card("보안상 주의사항", "book", ui.bullets(notes_preview(n, 3)),
                                        ui.done_badge("분석 완료")), unsafe_allow_html=True)
        else:
            text = "보안 매뉴얼에서 찾는 중…" if waiting else "가져오지 못했습니다."
            notes_slot.markdown(ui.card("보안상 주의사항", "book", f'<p class="sx-muted">{text}</p>'),
                                unsafe_allow_html=True)

    fill_notes_card(notes, waiting=notes is None)

    left, mid, right = st.columns([1.25, 1.15, 0.85], gap="medium")

    # ── Log 조사 내용 ──
    with left:
        html(ui.card("Log 조사 내용", "terminal", ui.sub("조사 내용") + ui.bullets(bullets)))
        evidence = finding.get("evidence") or []
        if evidence:
            st.markdown("**주요 로그 원문**")
            idx = 0
            if len(evidence) > 1:
                idx = st.selectbox("근거", range(len(evidence)), label_visibility="collapsed",
                                   format_func=lambda i: f"{evidence[i]['source_file']} : {evidence[i]['line_number']}줄")
            ev = evidence[idx]
            try:
                lines = svc.read_source_line(ev["source_file"], int(ev["line_number"]))
                target = int(ev["line_number"]) + (1 if str(ev["source_file"]).lower().endswith(".csv") else 0)
                st.code("\n".join(f"{'▶' if n == target else ' '} {n:>7}  {text}" for n, text in lines), language=None)
            except (FileNotFoundError, ValueError, OSError):
                st.caption(f"원본 파일을 열 수 없어 근거 정보만 표시합니다: {ev['source_file']}")
                st.json(ev, expanded=True)

        extra = []
        hit = find_interpretation(result.get("interpretation"), finding["finding_id"])
        if isinstance(hit, dict):
            extra += [v for v in hit.values() if isinstance(v, str) and len(v) > 20 and v != finding["finding_id"]]
        related = svc.related_findings(result, finding)
        if related:
            extra.append(f"같은 호스트 또는 같은 IP·계정에서 함께 탐지된 이상 징후가 {len(related)}건 있습니다.")
        html(ui.card("추가 조사 결과", "check",
                     ui.bullets(extra) if extra else '<p class="sx-muted">추가로 확인된 연관 이상 징후가 없습니다.</p>'))
        for f in related[:5]:
            label = f"[{ui.RISK[f['severity']][0]}] {f['summary']}"
            if st.button(label, key=f"rel_{f['finding_id']}", use_container_width=True):
                ss.detail_id = f["finding_id"]
                st.rerun()

    # ── 보안상 주의사항 ──
    with mid:
        mid_slot = st.empty()

    # ── 참고 문서 · 타임라인 ──
    with right:
        refs_slot = st.empty()
        html(ui.timeline(timeline_items(result, finding["finding_id"])))

    def fill_mid(n: dict | None, waiting: bool = False) -> None:
        if n and n.get("skipped"):
            card = ui.card("보안상 주의사항", "book", skipped_body(n))
        elif n:
            sec = n["sections"]
            body = ""
            if sec.get("summary"):
                body += ui.sub("분석 내용", "search") + ui.paragraphs(sec["summary"])
            if sec.get("procedure"):
                body += ui.sub("관련 대응 절차", "list") + ui.steps(sec["procedure"])
            if sec.get("checks"):
                body += ui.callout("warn", "확인해야 할 사항", sec["checks"])
            if sec.get("actions"):
                body += ui.callout("ok", "권장 대응 방향", sec["actions"])
            card = ui.card("보안상 주의사항", "book", body, ui.done_badge("분석 완료"))
        else:
            card = ui.card("보안상 주의사항", "book", WAITING if waiting else FAILED)
        mid_slot.markdown(card, unsafe_allow_html=True)
        refs_slot.markdown(ui.refs((n or {}).get("refs") or []), unsafe_allow_html=True)
        fill_notes_card(n, waiting=waiting)

    waiting = notes is None and finding["finding_id"] not in ss.notes_error
    fill_mid(notes, waiting=waiting)          # 1) 화면 전체를 먼저 보여주고
    if waiting:
        notes = get_notes(result, finding)    # 2) 마지막에 매뉴얼을 검색해
        fill_mid(notes)                       # 3) 빈 자리를 채운다

    with mid:
        if notes and notes.get("skipped"):
            pass
        elif notes:
            if st.button("이 사건으로 이어서 질문하기 →", use_container_width=True):
                ss.draft_question = notes["question"]
                st.switch_page(PAGES["docs"])
        else:
            notes_failed(finding, "retry_detail")


def find_interpretation(interp, finding_id: str):
    """LLM 해석 결과에서 이 finding_id 를 가리키는 부분을 찾는다(구조를 모르므로 전체를 훑는다)."""
    if isinstance(interp, dict):
        if any(v == finding_id for k, v in interp.items() if "finding_id" in k):
            return interp
        for v in interp.values():
            hit = find_interpretation(v, finding_id)
            if hit is not None:
                return hit
    elif isinstance(interp, list):
        for v in interp:
            hit = find_interpretation(v, finding_id)
            if hit is not None:
                return hit
    return None


# ───────────────────────── 화면: 보안 매뉴얼 ─────────────────────────
def page_docs() -> None:
    html(ui.page_header("보안 매뉴얼", "AWS Security Incident Response User Guide 를 근거로 답합니다.", now_text()))

    for m in ss.chat:
        with st.chat_message(m["role"]):
            st.markdown(m["content"])
            if m["role"] == "assistant" and m.get("refs"):
                html(ui.refs(m["refs"]))

    def send(question: str) -> None:
        ss.chat.append({"role": "user", "content": question})
        history = [{"role": m["role"], "content": m["content"]} for m in ss.chat]
        with st.chat_message("user"):
            st.markdown(question)
        with st.chat_message("assistant"):
            with st.spinner("보안 매뉴얼을 검색하는 중…"):
                try:
                    out = svc.ask_rag(history)
                except Exception as e:
                    ss.chat.pop()
                    st.error(f"답변을 받지 못했습니다: {e}")
                    return
        ss.chat.append({"role": "assistant", "content": out["answer"], "refs": out.get("refs") or []})
        st.rerun()

    if ss.draft_question:
        with st.container(border=True):
            st.markdown("**사건 내용으로 만든 질문** (고쳐서 보낼 수 있습니다)")
            draft = st.text_area("질문", ss.draft_question, height=200, label_visibility="collapsed")
            b1, b2, _ = st.columns([1, 1, 4])
            if b1.button("보내기", type="primary", use_container_width=True):
                ss.draft_question = ""
                send(draft)
            if b2.button("취소", use_container_width=True):
                ss.draft_question = ""
                st.rerun()

    if ss.chat and st.button("대화 지우기"):
        ss.chat = []
        st.rerun()

    if q := st.chat_input("예: Access Key 가 노출된 것 같아요. 어떤 순서로 대응하나요?"):
        send(q)


# ───────────────────────── 화면: 설정 ─────────────────────────
def page_settings() -> None:
    html(ui.page_header("설정", "결과 저장과 연결 상태를 확인합니다.", now_text()))
    c1, c2 = st.columns(2, gap="large")
    with c1:
        st.markdown("**결과 저장**")
        if ss.result:
            n_notes = len(ss.result.get("notes") or {})
            st.caption(f"보안상 주의사항 {n_notes}건이 함께 저장됩니다. 발표 때 네트워크 없이 보여줄 수 있습니다.")
            st.download_button("결과 JSON 저장", svc.result_to_json(ss.result),
                               file_name=f"investigation_{ss.result.get('investigation_id') or 'result'}.json",
                               mime="application/json", type="primary")
        else:
            st.caption("저장할 분석 결과가 없습니다.")
        st.markdown("**시연 모드**")
        on = svc.demo_mode_enabled()
        new = st.toggle("대시보드(시연 모드) 메뉴 표시", value=on, key="demo_toggle")
        if new != on:
            svc.set_demo_mode(new)
            ss.pop("demo_loaded", None)  # 켤 때마다 1단계부터
            ss.pop("demo_view", None)
            st.rerun()
        packs = svc.list_demo_packs()
        st.caption("켜면 사이드바에 '대시보드' 메뉴가 나타나 시연 자료를 단계별로 재생할 수 있습니다. 새로고침해도 유지됩니다. "
                   + (f"시연 자료 {len(packs)}개를 찾았습니다." if packs
                      else "시연 자료(output/demo)가 아직 없습니다."))
    with c2:
        st.markdown("**연결 상태**")
        cached_status.clear()
        ok, msg = cached_status()
        (st.success if ok else st.warning)(msg)
        if st.button("세션 초기화"):
            for k in list(ss.keys()):
                del ss[k]
            st.rerun()


# ───────────────────────── 화면: 대시보드 (시연 모드, 설정에서 메뉴 표시를 켜고 끔) ─────────────────────────
DEMO_HELP = [
    "팀 백엔드가 만든 시연 자료(output/demo/<자료 이름>/manifest.json 과 step_00~06 파일)를 단계별로 재생합니다.",
    "시연 자료는 output/ 폴더에 만들어지고 git 에는 올라가지 않습니다. 자료를 만든 팀원에게 output/demo 폴더를 받아 "
    "프로젝트 루트의 output/demo 에 넣거나, 분석 결과가 있는 PC 에서 아래 명령으로 만드세요.",
]


@st.cache_data(show_spinner=False)
def demo_file(pack_dir: str, name: str) -> dict:
    return svc.load_demo_file(pack_dir, name)


def sev_text(counts: dict | None) -> str:
    counts = counts or {}
    parts = [f"{ui.RISK[s][0]} {counts[s]}" for s in svc.SEVERITY_ORDER if counts.get(s)]
    return " · ".join(parts) if parts else "-"


def top_severity(counts: dict | None) -> str | None:
    return next((s for s in svc.SEVERITY_ORDER if (counts or {}).get(s)), None)


def demo_timeline(dash: dict, detail: dict) -> list[dict]:
    """단계가 진행될수록 쌓이는 타임라인.

    팀 자료의 timeline_preview 는 조사 대상 선정(4단계)부터 조사 대상 사건의 탐지만 남기므로,
    이미 공개된 같은 시간 범위의 탐지(projection_findings)를 함께 보여주고 조사 대상은 빨간 점으로 표시한다.
    진행 표시(demo_workflow)는 관측 이벤트가 아니므로 시각 없이 흐리게 맨 뒤에 둔다.
    """
    preview = dash.get("timeline_preview") or []
    observed = [e for e in preview if e.get("timeline_type") != "demo_workflow"]
    workflow = [e for e in preview if e.get("timeline_type") == "demo_workflow"]
    shown = {e.get("finding_id"): e for e in observed}
    for f in detail.get("projection_findings") or []:
        shown.setdefault(f.get("finding_id"), f)
    focus_ids = set(((detail.get("focused_incident") or {}).get("finding_ids")) or [])
    entries = sorted(shown.values(), key=lambda e: str(e.get("original_start_time") or e.get("start_time") or ""))
    items = [{"time": svc.fmt_time(e.get("original_start_time") or e.get("start_time"), with_date=False),
              "title": e.get("summary") or e.get("finding_type") or "-",
              "sub": " · ".join(x for x in (e.get("host") or e.get("service"),
                                            ui.RISK.get(e.get("severity"), ("",))[0],
                                            "조사 대상" if e.get("finding_id") in focus_ids else "") if x),
              "current": e.get("finding_id") in focus_ids}
             for e in entries]
    items += [{"time": "", "title": e.get("label") or "-", "sub": "분석 진행 표시 · 관측 이벤트 아님", "workflow": True}
              for e in workflow]
    return items


def demo_guidance_card(g: dict | None) -> tuple[str, list[dict]]:
    """보안 가이던스 카드 HTML 과 참고 페이지 목록."""
    status = (g or {}).get("status") or "not_started"
    if status == "not_requested":
        return ui.card("보안상 주의사항", "book", ui.callout(
            "info", "보안 가이드를 요청하지 않음",
            [g.get("not_requested_reason") or "이 사건은 보안 가이던스를 요청하지 않았습니다."])), []
    if status == "analyzing":
        return ui.card("보안상 주의사항", "book",
                       '<p class="sx-muted">⏳ 조사 대상 사건으로 AWS 보안 대응 매뉴얼을 조회하고 있습니다.</p>'), []
    if status != "completed" or not g.get("response"):
        return ui.card("보안상 주의사항", "book",
                       '<p class="sx-muted">조사 대상 사건이 정해지면 보안 대응 매뉴얼을 조회합니다.</p>'), []
    sec = svc.parse_rag_sections(g["response"])
    body = ""
    if sec.get("summary"):
        body += ui.sub("분석 내용", "search") + ui.paragraphs(sec["summary"])
    if sec.get("procedure"):
        body += ui.sub("관련 대응 절차", "list") + ui.steps(sec["procedure"])
    if sec.get("checks"):
        body += ui.callout("warn", "확인해야 할 사항", sec["checks"])
    if sec.get("actions"):
        body += ui.callout("ok", "권장 대응 방향", sec["actions"])
    if g.get("source_note"):
        body += f'<p class="sx-muted" style="margin-top:10px">{ui.E(g["source_note"])}</p>'
    pages = ((g.get("demo_derived") or {}).get("citation_pages")) or []
    return ui.card("보안상 주의사항", "book", body, ui.done_badge("조회 완료")), [{"page": n} for n in pages]


def md_card(key: str, title: str, ic: str, text: str, badge: str = "") -> None:
    """마크다운 본문을 카드 모양으로. 제목은 다른 카드와 같은 HTML, 본문은 st.markdown 으로 그린다."""
    with st.container(key=f"md_{key}"):
        b = f'<span class="badge">{badge}</span>' if badge else ""
        html(f'<div class="sx-ct"><span class="ic">{ui.icon(ic)}</span>{ui.E(title)}{b}</div>')
        st.markdown(text)


def page_demo() -> None:
    """대시보드: 팀 시연 자료를 단계별로 재생한다.

    홈 → 사건 상세처럼 두 화면으로 나눈다.
      요약 화면: 문제되는 곳 · 단계 · 숫자 요약 → 조사 대상 사건(크게) → 분석 영역별 탐지 | 타임라인
      상세보기 : 단계 설명 → 요약 → 보안상 주의사항 → 후보 사건 → 참고 문서 → 해석 주의점
                → 운영 상태 집계 → 보고서 받기 → 근거 로그 위치(맨 아래)
    단계를 넘겨도 지금 보고 있는 화면(요약/상세)은 그대로 유지한다.
    """
    detail_view = ss.get("demo_view") == "detail"
    html(ui.page_header("대시보드" if not detail_view else "대시보드 · 상세보기", "", now_text()))

    packs = svc.list_demo_packs()
    if not packs:
        html(ui.card("시연 자료가 없습니다", "file", ui.paragraphs(DEMO_HELP)))
        st.code("uv run python scripts/build_demo_replay.py --all", language="bash")
        st.caption(f"찾는 위치: {svc.PROJECT_ROOT / 'output' / 'demo'}")
        return

    # 시연 계획표 순서(1~4)대로, 표에 없는 자료는 뒤에
    packs.sort(key=lambda p: (svc.DEMO_SCENARIOS.get(p["scenario_key"], {}).get("no", 99), p["scenario_key"]))
    by_key = {p["scenario_key"]: p for p in packs}
    top1, top2 = st.columns([3, 2], gap="medium")
    key = top1.selectbox("재생할 자료", list(by_key), key="demo_key", label_visibility="collapsed",
                         format_func=lambda k: k)
    pack = by_key[key]
    steps = pack["steps"]
    last = len(steps) - 1
    if ss.get("demo_loaded") != key:
        ss.demo_loaded, ss.demo_step, ss.demo_play = key, 0, False
    i = max(0, min(ss.get("demo_step", 0), last))
    if i == last:
        ss.demo_play = False

    with top2:
        b1, b2, b3, b4 = st.columns(4)
        if b1.button("처음", use_container_width=True, disabled=i == 0):
            ss.demo_step, ss.demo_play = 0, False
            st.rerun()
        if b2.button("◀ 이전", use_container_width=True, disabled=i == 0):
            ss.demo_step, ss.demo_play = i - 1, False
            st.rerun()
        if b3.button("다음 ▶", use_container_width=True, disabled=i == last, type="primary"):
            ss.demo_step, ss.demo_play = i + 1, False
            st.rerun()
        playing = ss.get("demo_play", False)
        if b4.button("일시정지" if playing else "자동 재생", use_container_width=True, disabled=i == last and not playing):
            ss.demo_play = not playing
            st.rerun()

    data = demo_file(pack["_dir"], steps[i]["file"])
    demo, dash, detail = data.get("demo") or {}, data.get("dashboard") or {}, data.get("detail") or {}
    counters, status = dash.get("counters") or {}, dash.get("status") or {}

    # ── 공통 머리: 문제되는 곳 · 단계 ──
    info = svc.DEMO_SCENARIOS.get(key)
    guide_tag = ui.tag("보안 가이던스 포함" if pack.get("uses_rag") else "보안 가이던스 요청 안 함",
                       blue=bool(pack.get("uses_rag")))
    if info:
        html(ui.scenario_strip(f"{info['no']}. {info['name']}", info["area"], "",
                               pack.get("title") or key, guide_tag))
        with st.expander("문제 상황 요약"):
            html(ui.bullets(info["details"]))
    else:
        html(ui.scenario_strip(pack.get("title") or key, "-", "", key, guide_tag))
    html(ui.stepper([s["phase_label"] for s in steps], i))
    html(ui.risk_summary(dash.get("revealed_severity_counts")))

    if detail_view:
        if st.button("← 대시보드로 돌아가기", type="tertiary"):
            ss.demo_view = None
            st.rerun()
        demo_detail(pack, key, demo, dash, detail)
    else:
        demo_summary(dash, detail, counters, status)
        if st.button("상세보기 →", type="primary", key="demo_detail_btn"):
            ss.demo_view = "detail"
            st.rerun()

    # 자동 재생: 화면을 다 그린 뒤 권장 시간만큼 기다렸다가 다음 단계로
    if ss.get("demo_play"):
        if i >= last:
            ss.demo_play = False
        else:
            _time.sleep((steps[i].get("recommended_delay_ms") or 2500) / 1000)
            ss.demo_step = i + 1
            st.rerun()


def demo_summary(dash: dict, detail: dict, counters: dict, status: dict) -> None:
    """요약 화면: 분석 영역별 탐지 → 조사 대상 사건(크게) → 분석 현황 | 타임라인."""
    tiles = []
    for a in dash.get("agents") or []:
        rev = a.get("demo_revealed") or {}
        name = svc.AGENT_KO.get(a.get("agent_name"), a.get("agent_name"))
        n = rev.get("findings_count") or 0
        sc = rev.get("severity_counts")
        tiles.append((name, f"이상 징후 {n}건" if n else "이상 징후 없음", sev_text(sc) if n else "",
                      top_severity(sc) if n else None))
    html(ui.area_tiles(tiles))

    focused = detail.get("focused_incident")
    if focused:
        imp = focused.get("impact") or {}
        chip_items = [("호스트", ", ".join(imp.get("affected_hosts") or []) or "-"),
                      ("서비스", ", ".join(imp.get("affected_services") or []) or "-")]
        if imp.get("affected_ips"):
            chip_items.append(("IP", ", ".join(imp["affected_ips"][:5])))
        if imp.get("affected_users"):
            chip_items.append(("계정", ", ".join(imp["affected_users"][:5])))
        chip_items.append(("이상 징후", f"{focused.get('finding_count', 0)}건 ({sev_text(imp.get('severity_counts'))})"))
        items = ((focused.get("findings") or {}).get("items") or {}).get("items") or []
        left = ui.chips(chip_items) + ui.sub("포함된 이상 징후", "alert") + ui.bullets(
            [f"[{ui.RISK.get(f.get('severity'), ('-',))[0]}] {f.get('summary')} "
             f"({svc.fmt_time(f.get('start_time'), with_date=False)}~{svc.fmt_time(f.get('end_time'), with_date=False)})"
             for f in items])
        right = ""
        basis = (focused.get("correlation_basis") or {}).get("grouping_basis") or []
        if basis:
            right += ui.sub("하나의 사건으로 묶은 근거", "check") + ui.bullets([svc.GROUPING_KO.get(b, b) for b in basis])
        hyps = focused.get("hypotheses") or []
        right += ui.sub("가설 후보", "search")
        right += ui.bullets([h.get("statement", "") for h in hyps]) if hyps else \
            f'<p class="sx-muted">{ui.E(focused.get("hypotheses_note") or "가설 후보가 없습니다.")}</p>'
        html(ui.focus_card(top_severity(imp.get("severity_counts")), left, right))
    else:
        n = counters.get("candidate_incident_count")
        msg = (f"후보 사건 {n}건 중 조사 대상을 고르는 중입니다." if n
               else "이상 징후를 상관분석으로 묶은 뒤 조사 대상 사건을 선정합니다.")
        html(ui.focus_card(None, f'<p class="sx-muted">{ui.E(msg)}</p>', "", empty=True))

    c_area, c_tl = st.columns([1, 1.2], gap="medium")
    with c_area:
        def val(v: object) -> str:
            return "-" if v is None else str(v)
        rows = [
            f"공개된 이상 징후: {val(counters.get('revealed_findings_count'))}",
            f"후보 사건: {val(counters.get('candidate_incident_count'))}",
            f"조사 대상 사건: {val(counters.get('focused_incident_count'))}",
            f"제외된 후보: {val(counters.get('unselected_candidate_incident_count'))}",
            f"보안 가이던스: {val(svc.GUIDANCE_STATUS_KO.get(status.get('security_guidance'), status.get('security_guidance')))}",
            f"보고서: {val(svc.REPORT_STATUS_KO.get(status.get('report'), status.get('report')))}",
        ]
        body = ui.bullets(rows)
        body += '<p class="sx-muted" style="margin-top:6px">관측된 이상 징후만 집계합니다 · 정상/장애 판정 없음</p>'
        html(ui.card("분석 현황", "list", body))
    with c_tl:
        html(ui.timeline(demo_timeline(dash, detail), title="타임라인"))


def demo_detail(pack: dict, key: str, demo: dict, dash: dict, detail: dict) -> None:
    """상세보기: 줄글 → 근거·맥락 → 근거 로그 위치(맨 아래)."""
    if demo.get("step_note"):
        html(ui.callout("info", f"이 단계에서 보여주는 것 · {demo.get('phase_label', '')}", [demo["step_note"]]))

    ns = (detail.get("narrative_summary") or {}).get("text")
    if ns:
        md_card("summary", "요약", "file", ns)

    guide_html, pages = demo_guidance_card(detail.get("security_guidance"))
    html(guide_html)
    q = (detail.get("security_guidance") or {}).get("question")
    if q:
        with st.expander("매뉴얼에 보낸 질문 보기"):
            st.markdown(q)

    cand = detail.get("candidates")
    if cand and cand.get("candidate_incidents"):
        chosen = set(cand.get("focused_incident_ids") or [])
        done = bool(cand.get("selection_completed"))
        body = ""
        for k, inc in enumerate(cand["candidate_incidents"], 1):
            is_focus = inc["incident_id"] in chosen
            where = ", ".join((inc.get("affected_services") or []) + (inc.get("affected_hosts") or [])) or "-"
            tags = [ui.risk_pill(top_severity(inc.get("severity_counts")))]
            if is_focus:
                tags.append(ui.tag("조사 대상", blue=True))
            if inc.get("is_single_finding"):
                tags.append(ui.tag("단일 탐지"))
            basis = ", ".join(svc.GROUPING_KO.get(b, b) for b in inc.get("grouping_basis") or []) or "-"
            body += ui.incident_row(
                f"후보 {k} · {where}",
                [f"이상 징후 {inc.get('finding_count', 0)}건 ({sev_text(inc.get('severity_counts'))}) · "
                 + ", ".join(inc.get("finding_type_counts") or {}),
                 f"묶은 근거: {basis}"],
                tags, "focus" if is_focus else ("dim" if done else ""))
        if done and cand.get("unselected_note"):
            body += f'<p class="sx-muted">{ui.E(cand["unselected_note"])}</p>'
        elif not done:
            body += '<p class="sx-muted">같은 시간 범위 안의 이상 징후를 관계별로 묶은 후보입니다. 조사 대상은 아직 고르지 않았습니다.</p>'
        html(ui.card("후보 사건", "list", body))

    html(ui.refs(pages))
    notes = (detail.get("limitations") or {}).get("notes") or []
    if notes and demo.get("is_last_step"):
        html(ui.card("해석할 때 주의할 점", "alert", ui.bullets(notes)))
    op = dash.get("operational_state")
    if op:
        html(ui.card("운영 상태 집계", "server", ui.paragraphs([
            "정상 · 경고 · 장애 수는 집계하지 않습니다.", op.get("policy") or ""])))
    if demo.get("is_last_step"):
        report = Path(pack["_dir"]) / (detail.get("final_report_file") or "final_report.json")
        if report.exists():
            st.download_button("최종 보고서 JSON 받기", report.read_bytes(), file_name=f"{key}_report.json",
                               mime="application/json")

    focused = detail.get("focused_incident") or {}
    groups = (focused.get("evidence") or {}).get("groups") or []
    if groups:
        with st.expander(f"근거 로그 위치 ({(focused.get('evidence') or {}).get('included_evidence_count', '')}건)"):
            for g in groups:
                st.caption(g.get("finding_id"))
                st.code("\n".join(f"{it.get('source_file')} : {it.get('line_number')}줄  "
                                  f"{svc.fmt_time(it.get('timestamp'))}" for it in g.get("items") or []),
                        language=None)


# ───────────────────────── 내비게이션 ─────────────────────────
PAGES = {
    "home": st.Page(page_home, title="홈", icon=":material/home:", url_path="home", default=True),
    "dashboard": st.Page(page_demo, title="대시보드", icon=":material/dashboard:", url_path="dashboard"),
    "analyze": st.Page(page_analyze, title="사고 분석", icon=":material/search:", url_path="analyze"),
    "records": st.Page(page_records, title="분석 기록", icon=":material/description:", url_path="records"),
    "docs": st.Page(page_docs, title="보안 매뉴얼", icon=":material/menu_book:", url_path="docs"),
    "settings": st.Page(page_settings, title="설정", icon=":material/settings:", url_path="settings"),
}
# 대시보드(시연 모드) 메뉴는 설정에서 숨길 수 있다
VISIBLE = [p for k, p in PAGES.items() if k != "dashboard" or svc.demo_mode_enabled()]
current = st.navigation(VISIBLE, position="hidden")

with st.sidebar:
    html(ui.brand())
    for page in VISIBLE:
        if page.title == current.title:
            with st.container(key="navactive"):
                st.page_link(page)
        else:
            st.page_link(page)
    ok, msg = cached_status()
    html(ui.system_status(ok, msg, now_text()))

current.run()
