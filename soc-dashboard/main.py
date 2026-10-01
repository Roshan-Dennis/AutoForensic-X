"""
main.py — AutoForensic-X SOC console (FastAPI).

Mostly a read-only viewer over the Neo4j provenance graph + soar_audit.log,
plus a set of real analyst actions rather than just display:
  - Block / Unblock an IP directly (audit.block_ip / audit.unblock_ip)
  - Kill a live process by PID (audit.kill_process)
  - Trigger an actual SOAR playbook run, dry-run or live (playbooks.run_playbook)
  - Incident triage status + notes (notes.py — local state, not in Neo4j)
Every action shells out the same way you'd do it by hand over SSH — none
of the corroboration/safety logic is reimplemented here, see audit.py and
playbooks.py's docstrings.

Run (on the Target VM):
    source ~/afx-venv/bin/activate
    pip install -r requirements.txt
    python3 main.py
Then browse to http://192.168.56.101:8000
"""

from __future__ import annotations

import json
import urllib.parse

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import audit
import config
import db
import notes
import playbooks
import queries

def _json_safe(obj):
    from datetime import date, datetime, time
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    if hasattr(obj, 'isoformat'):
        return obj.isoformat()
    if isinstance(obj, (date, datetime, time)):
        return str(obj)
    return obj



def _err_redirect(url: str, message: str) -> RedirectResponse:
    return RedirectResponse(url=f"{url}?error={urllib.parse.quote(message)}", status_code=303)

app = FastAPI(title="AutoForensic-X SOC Console")
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


def render(request: Request, template: str, **ctx):
    return templates.TemplateResponse(request, template, ctx)


@app.on_event("shutdown")
def _shutdown():
    db.close()


# ---------------------------------------------------------------------------
# 1. Overview

@app.get("/", response_class=HTMLResponse)
def overview(request: Request):
    kpis = queries.kpi_counts()
    return render(request, "overview.html", active="overview", kpis=kpis)


@app.get("/api/overview/timeline.json")
def overview_timeline():
    rows = queries.exec_timeline()
    labels = []
    counts = []
    for r in rows:
        day = r["day"]
        h = r["hour"]
        m = r["minute"]
        labels.append(f"{day} {h:02d}:{m:02d}")
        counts.append(r["count"])
    return JSONResponse({"labels": labels, "counts": counts})


# ---------------------------------------------------------------------------
# 2. Incidents queue

@app.get("/incidents", response_class=HTMLResponse)
def incidents(request: Request, severity: str = "all", technique: str = "all", source: str = "all", status: str = "all"):
    rows = queries.all_incidents(severity=severity, technique=technique, source=source)
    saved_statuses = notes.all_statuses()
    for r in rows:
        r["status"] = saved_statuses.get(r["id"], {}).get("status", "new")
    if status != "all":
        rows = [r for r in rows if r["status"] == status]
    return render(
        request,
        "incidents.html",
        active="incidents",
        incidents=rows,
        statuses=notes.STATUSES,
        filters={"severity": severity, "technique": technique, "source": source, "status": status},
    )


# ---------------------------------------------------------------------------
# 3. Incident graph view

@app.get("/incidents/{incident_id}", response_class=HTMLResponse)
def incident_detail(request: Request, incident_id: str):
    incident = queries.find_incident(incident_id)
    if incident is None:
        return HTMLResponse(f"Incident '{incident_id}' not found.", status_code=404)
    status_info = notes.get(incident_id)
    return render(
        request,
        "incident_detail.html",
        active="incidents",
        incident=incident,
        status_info=status_info,
        statuses=notes.STATUSES,
    )


@app.post("/incidents/{incident_id}/status")
def incident_set_status(incident_id: str, status: str = Form(...), note: str = Form("")):
    try:
        notes.set_status(incident_id, status, note=note)
    except ValueError:
        pass
    return RedirectResponse(url=f"/incidents/{incident_id}", status_code=303)


@app.get("/api/incidents/{incident_id}/graph.json")
def incident_graph_json(incident_id: str):
    incident = queries.find_incident(incident_id)
    if incident is None or not incident.get("focus_exec_id"):
        return JSONResponse({"nodes": [], "edges": [], "focus_exec_id": None, "root_exec_id": None})
    lineage = queries.lineage_for(incident["focus_exec_id"])
    return JSONResponse(_json_safe(lineage))


# ---------------------------------------------------------------------------
# 4. Entity pages

@app.get("/entity/process/{exec_id}", response_class=HTMLResponse)
def entity_process(request: Request, exec_id: str, error: str | None = None):
    lineage = queries.lineage_for(exec_id)
    return render(request, "entity_process.html", active="entities", exec_id=exec_id, lineage=lineage, error=error)


@app.get("/api/entity/process/{exec_id}/graph.json")
def entity_process_graph_json(exec_id: str):
    return JSONResponse(_json_safe(queries.lineage_for(exec_id)))


@app.post("/entity/process/{exec_id}/kill")
def entity_process_kill(exec_id: str, pid: int = Form(...)):
    try:
        event = audit.kill_process(pid, exec_id=exec_id)
    except ValueError as e:
        return _err_redirect(f"/entity/process/{exec_id}", str(e))

    if not event.get("logged", True):
        return _err_redirect(f"/entity/process/{exec_id}", f"Kill ran, but couldn't be logged: {event['log_error']}")
    if event["action"] in ("kill_failed", "skip_kill"):
        return _err_redirect(f"/entity/process/{exec_id}", event.get("note") or "Kill did not succeed.")
    return RedirectResponse(url=f"/entity/process/{exec_id}", status_code=303)


@app.get("/entity/ip/{ip}", response_class=HTMLResponse)
def entity_ip(request: Request, ip: str, error: str | None = None):
    data = queries.ip_entity(ip)
    return render(request, "entity_ip.html", active="entities", data=data, error=error)


@app.post("/entity/ip/{ip}/block")
def entity_ip_block(ip: str):
    try:
        event = audit.block_ip(ip)
    except ValueError:
        return _err_redirect(f"/entity/ip/{ip}", "Not a valid IP address.")

    if not event.get("logged", True):
        return _err_redirect(f"/entity/ip/{ip}", f"iptables action ran, but couldn't be logged: {event['log_error']}")
    if event["action"] == "block_failed":
        return _err_redirect(f"/entity/ip/{ip}", event.get("note") or "Block did not succeed.")
    return RedirectResponse(url=f"/entity/ip/{ip}", status_code=303)


@app.get("/entity/uid/{uid}", response_class=HTMLResponse)
def entity_uid(request: Request, uid: str):
    data = queries.uid_entity(uid)
    return render(request, "entity_uid.html", active="entities", data=data)


# ---------------------------------------------------------------------------
# 5. Hunting console

@app.get("/hunting", response_class=HTMLResponse)
def hunting(request: Request, mode: str | None = None, value: str | None = None):
    results = None
    error = None
    if mode and value:
        try:
            if mode == "alert":
                incident = queries.find_incident(f"alert-{value}")
                if incident and incident.get("focus_exec_id"):
                    results = {"kind": "lineage", "lineage": queries.lineage_for(incident["focus_exec_id"]), "label": f"Root-cause trace for alert {value}"}
                else:
                    error = f"No alert '{value}' with a correlated process was found."
            elif mode == "pid":
                proc = queries.process_by_pid(int(value))
                if proc:
                    results = {"kind": "lineage", "lineage": queries.lineage_for(proc["exec_id"]), "label": f"Lineage for PID {value}"}
                else:
                    error = f"No process with PID {value} was found."
            elif mode == "ip":
                results = {"kind": "ip", "data": queries.ip_entity(value), "label": f"Activity for {value}"}
            else:
                error = "Unknown hunting mode."
        except ValueError:
            error = "That value doesn't look valid for the selected hunt."
    return render(request, "hunting.html", active="hunting", mode=mode, value=value, results=results, error=error)


# ---------------------------------------------------------------------------
# 6. Automation history

@app.get("/automation", response_class=HTMLResponse)
def automation(request: Request, error: str | None = None):
    events = list(reversed(audit.read_events()))
    blocks = audit.active_blocks()
    return render(request, "automation.html", active="automation", events=events, blocks=blocks, error=error)


@app.post("/automation/unblock")
def automation_unblock(ip: str = Form(...)):
    try:
        event = audit.unblock_ip(ip)
    except ValueError:
        return _err_redirect("/automation", "Not a valid IP address.")

    if not event.get("logged", True):
        return _err_redirect("/automation", f"iptables action ran, but couldn't be logged: {event['log_error']}")
    if event["action"] == "unblock_failed":
        return _err_redirect("/automation", f"Unblock failed for {ip}: {event.get('note') or 'iptables rule removal did not succeed.'}")
    return RedirectResponse(url="/automation", status_code=303)


@app.post("/automation/block")
def automation_block(ip: str = Form(...)):
    try:
        event = audit.block_ip(ip)
    except ValueError:
        return _err_redirect("/automation", "Not a valid IP address.")

    if not event.get("logged", True):
        return _err_redirect("/automation", f"iptables action ran, but couldn't be logged: {event['log_error']}")
    if event["action"] == "block_failed":
        return _err_redirect("/automation", f"Block failed for {ip}: {event.get('note') or 'iptables rule add did not succeed.'}")
    return RedirectResponse(url="/automation", status_code=303)


@app.post("/playbooks/run", response_class=HTMLResponse)
def playbooks_run(request: Request, name: str = Form(...), mode: str = Form(...)):
    try:
        result = playbooks.run_playbook(name, dry_run=(mode != "live"))
    except ValueError as e:
        return HTMLResponse(str(e), status_code=400)
    return render(
        request,
        "playbook_result.html",
        active="automation",
        result=result,
        label=playbooks.PLAYBOOKS[name]["label"],
    )


# ---------------------------------------------------------------------------
# 7. MITRE coverage map

@app.get("/mitre", response_class=HTMLResponse)
def mitre(request: Request):
    return render(request, "mitre.html", active="mitre", catalog=queries.mitre_coverage())


# ---------------------------------------------------------------------------
# 8. Metrics

@app.get("/metrics", response_class=HTMLResponse)
def metrics(request: Request):
    return render(request, "metrics.html", active="metrics", m=queries.mttd_mttr())


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host=config.DASHBOARD_HOST, port=config.DASHBOARD_PORT)
