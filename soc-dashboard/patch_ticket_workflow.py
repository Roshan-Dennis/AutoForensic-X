"""
patch_ticket_workflow.py - ONE-TIME patch script, run once on
2026-11-03 against the live ~/soc-dashboard/main.py, to wire in the new
console ticket workflow (status/disposition/notes/SLA + the Claim/
Contain/Close/False-positive/Note routes) in place of the old single
generic /incidents/{id}/status route.

Does exactly 3 targeted string replacements, each verified to match the
current file EXACTLY ONCE before being applied (same safety discipline
as a manual find-and-replace edit) - aborts with no changes written if
any of the 3 expected blocks isn't found verbatim, rather than silently
corrupting the file. Writes a timestamped backup of main.py before
touching it, and py_compiles the result afterward.

Usage (from ~/soc-dashboard):
    python3 patch_ticket_workflow.py
"""

from __future__ import annotations

import datetime
import pathlib
import py_compile
import sys

MAIN_PY = pathlib.Path("main.py")

REPLACEMENTS = [
    (
        '        r["status"] = saved_statuses.get(r["id"], {}).get("status", "new")\n',
        '        info = saved_statuses.get(r["id"], {})\n'
        '        r["status"] = info.get("status", "open")\n'
        '        r["disposition"] = info.get("disposition")\n',
    ),
    (
        'def incident_detail(request: Request, incident_id: str):\n'
        '    incident = queries.find_incident(incident_id)\n'
        '    if incident is None:\n'
        '        return HTMLResponse(f"Incident \'{incident_id}\' not found.", status_code=404)\n'
        '    status_info = notes.get(incident_id)\n'
        '    return render(\n'
        '        request,\n'
        '        "incident_detail.html",\n'
        '        active="incidents",\n'
        '        incident=incident,\n'
        '        status_info=status_info,\n'
        '        statuses=notes.STATUSES,\n'
        '    )\n',
        'def incident_detail(request: Request, incident_id: str, error: str | None = None):\n'
        '    incident = queries.find_incident(incident_id)\n'
        '    if incident is None:\n'
        '        return HTMLResponse(f"Incident \'{incident_id}\' not found.", status_code=404)\n'
        '    status_info = notes.get(incident_id)\n'
        '    return render(\n'
        '        request,\n'
        '        "incident_detail.html",\n'
        '        active="incidents",\n'
        '        incident=incident,\n'
        '        status_info=status_info,\n'
        '        statuses=notes.STATUSES,\n'
        '        dispositions=notes.DISPOSITIONS,\n'
        '        error=error,\n'
        '    )\n',
    ),
    (
        '@app.post("/incidents/{incident_id}/status")\n'
        'def incident_set_status(incident_id: str, status: str = Form(...), note: str = Form("")):\n'
        '    try:\n'
        '        notes.set_status(incident_id, status, note=note)\n'
        '    except ValueError:\n'
        '        pass\n'
        '    return RedirectResponse(url=f"/incidents/{incident_id}", status_code=303)\n',
        '@app.post("/incidents/{incident_id}/claim")\n'
        'def incident_claim(incident_id: str, note: str = Form("")):\n'
        '    notes.claim(incident_id, actor="dashboard", note=note)\n'
        '    return RedirectResponse(url=f"/incidents/{incident_id}", status_code=303)\n'
        '\n'
        '\n'
        '@app.post("/incidents/{incident_id}/contain")\n'
        'def incident_contain(incident_id: str, note: str = Form("")):\n'
        '    notes.contain(incident_id, actor="dashboard", note=note)\n'
        '    return RedirectResponse(url=f"/incidents/{incident_id}", status_code=303)\n'
        '\n'
        '\n'
        '@app.post("/incidents/{incident_id}/close")\n'
        'def incident_close(incident_id: str, disposition: str = Form(...), note: str = Form("")):\n'
        '    try:\n'
        '        notes.close(incident_id, disposition, actor="dashboard", note=note)\n'
        '    except ValueError as e:\n'
        '        return _err_redirect(f"/incidents/{incident_id}", str(e))\n'
        '    return RedirectResponse(url=f"/incidents/{incident_id}", status_code=303)\n'
        '\n'
        '\n'
        '@app.post("/incidents/{incident_id}/false-positive")\n'
        'def incident_false_positive(incident_id: str, note: str = Form("")):\n'
        '    notes.false_positive(incident_id, actor="dashboard", note=note)\n'
        '    return RedirectResponse(url=f"/incidents/{incident_id}", status_code=303)\n'
        '\n'
        '\n'
        '@app.post("/incidents/{incident_id}/note")\n'
        'def incident_add_note(incident_id: str, note: str = Form(...)):\n'
        '    try:\n'
        '        notes.add_note(incident_id, note, actor="dashboard")\n'
        '    except ValueError as e:\n'
        '        return _err_redirect(f"/incidents/{incident_id}", str(e))\n'
        '    return RedirectResponse(url=f"/incidents/{incident_id}", status_code=303)\n',
    ),
]


def main() -> None:
    if not MAIN_PY.exists():
        print(f"FAILED: {MAIN_PY} not found in the current directory.", file=sys.stderr)
        sys.exit(1)

    text = MAIN_PY.read_text()

    for i, (old, new) in enumerate(REPLACEMENTS, start=1):
        count = text.count(old)
        if count != 1:
            print(
                f"FAILED: replacement {i} matched {count} times (expected exactly 1) - "
                f"aborting with NO changes written. main.py is unchanged.",
                file=sys.stderr,
            )
            sys.exit(1)
        text = text.replace(old, new)

    backup_path = MAIN_PY.with_suffix(f".py.bak-{int(datetime.datetime.now().timestamp())}")
    backup_path.write_text(MAIN_PY.read_text())
    MAIN_PY.write_text(text)

    try:
        py_compile.compile(str(MAIN_PY), doraise=True)
    except py_compile.PyCompileError as e:
        print(f"FAILED: patched main.py does not compile: {e}", file=sys.stderr)
        print(f"Backup is at {backup_path} - restore it if needed.", file=sys.stderr)
        sys.exit(1)

    print(f"OK: applied {len(REPLACEMENTS)} replacements to {MAIN_PY}. Backup at {backup_path}. Compiles clean.")


if __name__ == "__main__":
    main()
