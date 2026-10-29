"""
FastAPI Server for Blast-Radius Containment Engine.
Exposes interactive REST endpoints and web dashboard for HackFront India.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Optional

# UTF-8 stdout configuration for Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from layer1_telemetry.emitter import SyntheticTelemetry, EventType, Severity
from layer2_graph_engine.engine import InMemoryEngine, CROWN_JEWELS
from layer3_incident_commander.commander import SarvamAICommander
from shared.events import Alert

app = FastAPI(
    title="Blast-Radius Containment Engine API",
    description="Real-time eBPF-powered Cloud & Identity Blast-Radius Containment Engine with Sarvam AI",
    version="0.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global engine instances
engine = InMemoryEngine()
telemetry = SyntheticTelemetry(delay_seconds=0.0)
commander = SarvamAICommander()
active_alert: Optional[Alert] = None
is_contained = False


class QueryRequest(BaseModel):
    query: str
    language: str = "auto"
    synthesize_audio: bool = True


class ContainRequest(BaseModel):
    chokepoint_node: Optional[str] = None


@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    dashboard_path = Path(__file__).parent / "web" / "index.html"
    if dashboard_path.exists():
        with open(dashboard_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>Blast-Radius Containment Engine Dashboard Initializing...</h1>")


@app.get("/api/state")
async def get_state():
    adj = engine._adj()
    nodes_list = [
        {
            "id": nid,
            "type": ndata.get("type", "service"),
            "is_crown_jewel": nid in CROWN_JEWELS,
            "is_chokepoint": active_alert is not None and active_alert.chokepoint == nid,
            "is_compromised": active_alert is not None and active_alert.entity == nid,
        }
        for nid, ndata in engine.nodes.items()
    ]
    edges_list = [{"src": e.src, "dst": e.dst, "kind": e.kind} for e in engine.edges]
    
    blast_radius = 0
    if active_alert and active_alert.entity:
        blast_radius = await engine.compute_blast_radius(active_alert.entity)

    return {
        "nodes": nodes_list,
        "edges": edges_list,
        "alert": active_alert.as_dict() if active_alert else None,
        "crown_jewels": list(CROWN_JEWELS),
        "blast_radius": blast_radius,
        "is_contained": is_contained,
    }


@app.post("/api/simulate-attack")
async def simulate_attack():
    global active_alert, is_contained
    is_contained = False
    
    events = []
    async for event in telemetry.simulate_attack(scenario="supply_chain_npm", start_pid=9999):
        events.append(event.as_dict())
        await engine.ingest_event(event)

    active_alert = Alert(
        id=f"ALERT-LIVE-{int(asyncio.get_event_loop().time())}",
        title="Unauthorized Vault Access from Staging Pod",
        description="Malicious npm package initiated lateral pivot to UPI Ledger",
        severity=Severity.CRITICAL,
        entity="svc:staging-pod",
        source_event_ids=[e["event_id"] if "event_id" in e else "ev" for e in events],
    )
    active_alert = await engine.run_on_alert(active_alert)

    return {
        "status": "attack_simulated",
        "events_count": len(events),
        "events": events,
        "alert": active_alert.as_dict(),
    }


@app.post("/api/analyze")
async def run_analysis():
    global active_alert
    entity = active_alert.entity if active_alert and active_alert.entity else "svc:staging-pod"
    paths = await engine.find_attack_paths(entity, max_hops=6, k=3)
    radius = await engine.compute_blast_radius(entity)
    ppr = await engine.compute_personalized_pagerank(entity)
    choke = await engine.find_chokepoint(entity)

    if active_alert:
        active_alert.blast_radius = radius
        if choke:
            active_alert.chokepoint = choke.node_id
            active_alert.blast_radius_pct = choke.blast_reduction_pct

    return {
        "entity": entity,
        "attack_paths": [p.__dict__ for p in paths],
        "blast_radius": radius,
        "personalized_pagerank": ppr,
        "chokepoint": choke.__dict__ if choke else None,
    }


@app.post("/api/contain")
async def execute_containment(req: Optional[ContainRequest] = None):
    global is_contained, active_alert
    entity = active_alert.entity if active_alert and active_alert.entity else "svc:staging-pod"
    choke_node = (req and req.chokepoint_node) or (active_alert and active_alert.chokepoint) or "svc:payment-gateway"
    
    plan = await engine.generate_containment_plan(entity, choke_node)
    
    # Sever edges in memory
    engine.edges = [e for e in engine.edges if e.src != choke_node and e.dst != choke_node]
    is_contained = True
    
    new_radius = await engine.compute_blast_radius(entity)
    if active_alert:
        active_alert.blast_radius = new_radius

    return {
        "status": "contained",
        "chokepoint": choke_node,
        "original_radius": plan.original_blast_radius,
        "contained_radius": new_radius,
        "reduction_pct": plan.blast_reduction_pct,
        "k8s_network_policy": plan.k8s_network_policy,
        "iptables_rule": plan.iptables_rule,
    }


@app.post("/api/commander/query")
async def commander_query(req: QueryRequest):
    response_text = await commander.process_voice_query(
        req.query, language=req.language, alert_context=active_alert
    )
    
    audio_url = None
    if req.synthesize_audio:
        tts_filename = f"incident_audio/tts_{abs(hash(req.query)) % 100000}.wav"
        audio_path = await commander.generate_voice_alert(
            text=response_text,
            target_language_code="hi-IN" if "hai" in req.query.lower() or "kya" in req.query.lower() else "en-IN",
            output_file=tts_filename,
        )
        if audio_path and Path(audio_path).exists():
            audio_url = f"/audio/{Path(audio_path).name}"

    return {
        "query": req.query,
        "response": response_text,
        "audio_url": audio_url,
    }


@app.post("/api/report/cert-in")
async def create_cert_in_report():
    report = await commander.generate_cert_in_report(active_alert)
    html_path = report.save_html()
    filename = Path(html_path).name
    return {
        "incident_id": report.incident_id,
        "disclosure_deadline": report.disclosure_deadline.isoformat(),
        "report_url": f"/reports/{filename}",
        "data": report.to_pdf_dict(),
    }


@app.get("/reports/{filename}")
async def get_report_file(filename: str):
    p = Path("reports") / filename
    if p.exists():
        return FileResponse(p, media_type="text/html")
    raise HTTPException(status_code=404, detail="Report not found")


@app.get("/audio/{filename}")
async def get_audio_file(filename: str):
    p = Path("incident_audio") / filename
    if p.exists():
        return FileResponse(p, media_type="audio/wav")
    raise HTTPException(status_code=404, detail="Audio file not found")


def main():
    import uvicorn
    uvicorn.run("server:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
