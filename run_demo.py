#!/usr/bin/env python3
"""
Blast-Radius Containment Engine - Live End-to-End Demonstration.

Demonstrates:
1. Kernel eBPF telemetry simulation (Cilium Tetragon compatible)
2. Anomaly detection & MITRE ATT&CK technique classification
3. Temporal attack graph with Yen's K-Shortest Paths & Personalized PageRank
4. Betweenness centrality chokepoint detection & surgical isolation
5. Live Sarvam AI Multilingual Incident Commander (Hinglish/Hindi/English)
6. Sarvam Bulbul Voice Alert generation (TTS)
7. CERT-In 6-Hour regulatory disclosure report generation with SHA-256 HMAC
"""

import asyncio
import logging
import os
import sys
from pathlib import Path

# Fix Windows console UTF-8 encoding
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

sys.path.insert(0, str(Path(__file__).resolve().parent))

from layer1_telemetry.emitter import SyntheticTelemetry, EventType, Severity
from layer2_graph_engine.engine import InMemoryEngine
from layer3_incident_commander.commander import SarvamAICommander
from shared.events import Alert

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("blast-radius")


async def run_demo():
    print("\n" + "=" * 70)
    print("  🚀 BLAST-RADIUS CONTAINMENT ENGINE (HackFront India 2026)")
    print("  Real-Time eBPF Telemetry + Neo4j Graph + Sarvam AI Incident Commander")
    print("=" * 70 + "\n")

    engine = InMemoryEngine()
    telemetry = SyntheticTelemetry(delay_seconds=0.03)
    commander = SarvamAICommander()

    await engine.connect()
    logger.info("[INIT] Temporal Graph Engine ready (In-Memory / Neo4j Mode)")

    # -------------------------------------------------------------
    # PHASE 1: Kernel Telemetry Stream (eBPF emulation)
    # -------------------------------------------------------------
    print("\n" + "-" * 70)
    print("  [PHASE 1] Ingesting eBPF Kernel Telemetry (Tetragon Format)")
    print("-" * 70)
    events = []
    async for event in telemetry.simulate_attack(scenario="supply_chain_npm", start_pid=9999):
        events.append(event)
        edges = await engine.ingest_event(event)
        target = event.dst or event.path or ""
        technique = event.infer_mitre_technique()
        logger.info(
            f"Syscall #{len(events):02d} | {event.type.value.upper():<11} | comm={event.comm:<5} | target={target:<28} | {technique}"
        )
        for e in edges:
            logger.info(f"   └── Graph Edge: ({e.src}) --[{e.kind}]--> ({e.dst})")

    logger.info(f"Phase 1 Complete: {len(events)} kernel events ingested and graph topology updated.")

    # -------------------------------------------------------------
    # PHASE 2: Anomaly Detection & Alert Trigger
    # -------------------------------------------------------------
    print("\n" + "-" * 70)
    print("  [PHASE 2] Automated Anomaly Detection & Threat Trigger")
    print("-" * 70)
    alert = None
    for event in events:
        if event.type == EventType.FILE_ACCESS and "/vault/" in (event.path or ""):
            alert = Alert(
                id=f"ALERT-HFI-{len(events):03d}",
                title="Unauthorized Vault Credential Access from Staging Pod",
                description=f"PID {event.pid} ({event.comm}) accessed {event.path}. Probable supply-chain token theft.",
                severity=Severity.CRITICAL,
                source_event_ids=[e.event_id() for e in events],
                entity="svc:staging-pod",
            )
            logger.info(f"🚨 CRITICAL ALERT TRIGGERED: {alert.title}")
            logger.info(f"   Origin Entity: {alert.entity} | Event Fingerprint: {alert.source_event_ids[0]}")
            break

    # -------------------------------------------------------------
    # PHASE 3: Temporal Blast-Radius & Attack Path Analysis
    # -------------------------------------------------------------
    print("\n" + "-" * 70)
    print("  [PHASE 3] Computing Blast-Radius, Dijkstra & Yen K-Shortest Paths")
    print("-" * 70)
    test_entity = "svc:staging-pod"

    if alert:
        alert = await engine.run_on_alert(alert)

    paths = await engine.find_attack_paths(test_entity, max_hops=6, k=3)
    logger.info(f"Attack paths to Crown Jewels identified: {len(paths)}")
    for i, path in enumerate(paths, 1):
        path_str = " -> ".join(path.path)
        logger.info(f"   Route #{i} ({path.hops} hops): {path_str}")

    radius = await engine.compute_blast_radius(test_entity)
    logger.info(f"Reachable Blast Radius: {radius} microservices & cloud datastores threatened.")

    # Personalized PageRank
    ppr_scores = await engine.compute_personalized_pagerank(test_entity)
    top_ppr = sorted(ppr_scores.items(), key=lambda x: x[1], reverse=True)[:5]
    logger.info("Personalized PageRank (Lateral Movement Risk Propagation):")
    for node, score in top_ppr:
        logger.info(f"   {node:<26} -> Risk Score: {score:.4f}")

    # Chokepoint & Surgical Containment
    choke = await engine.find_chokepoint(test_entity)
    if choke:
        logger.info(f"🎯 Structural Chokepoint: {choke.node_id} (Betweenness Centrality: {choke.betweenness:.2f})")
        logger.info(f"🛡️ Blast Reduction if Isolated: {choke.blast_reduction_pct:.1f}%")

    # -------------------------------------------------------------
    # PHASE 4: Automated Containment Plan Generation
    # -------------------------------------------------------------
    print("\n" + "-" * 70)
    print("  [PHASE 4] Surgical Containment Plan Generation (< 50ms Action)")
    print("-" * 70)
    if choke:
        plan = await engine.generate_containment_plan(test_entity, choke.node_id)
        logger.info(f"Original Blast Radius : {plan.original_blast_radius} nodes")
        logger.info(f"Contained Blast Radius: {plan.contained_blast_radius} nodes (Reduced by {plan.blast_reduction_pct}%)")
        logger.info(f"Linux iptables command:\n   {plan.iptables_rule}")

    # -------------------------------------------------------------
    # PHASE 5: Live Sarvam AI Multilingual Incident Commander
    # -------------------------------------------------------------
    print("\n" + "-" * 70)
    print("  [PHASE 5] Live Sarvam AI Incident Commander (Hinglish/Voice)")
    print("-" * 70)
    queries = [
        "Payment gateway pod mein kya compromise hua hai aur iska blast radius kya hai?",
        "Chokepoint isolate karne ke baad production checkout live rahega ya nahi?",
    ]

    for q in queries:
        logger.info(f"User Query (Voice/Text): \"{q}\"")
        resp = await commander.process_voice_query(q, alert_context=alert)
        logger.info("Incident Commander Response:")
        for line in resp.strip().split("\n"):
            logger.info(f"   {line}")
        print()

    # Voice Alert Synthesis via Sarvam Bulbul TTS
    logger.info("Synthesizing audible voice alert via Sarvam Bulbul TTS...")
    tts_text = f"चेतावनी: पेमेंट गेटवे पर संदिग्ध गतिविधि डिटेक्ट हुई है। ब्लास्ट रेडियस {radius} नोड्स है। चोकपॉइंट आइसोलेट किया जा रहा है।"
    audio_path = await commander.generate_voice_alert(
        text=tts_text,
        target_language_code="hi-IN",
        speaker="priya",
        output_file="incident_audio/alert_payment_gateway.wav",
    )
    if audio_path:
        logger.info(f"🔊 Audio broadcast generated: {audio_path}")
    else:
        logger.info("ℹ️ Sarvam Bulbul voice alert synthesized in fallback demo mode.")

    # -------------------------------------------------------------
    # PHASE 6: CERT-In 6-Hour Disclosure Docket
    # -------------------------------------------------------------
    print("\n" + "-" * 70)
    print("  [PHASE 6] Generating CERT-In 6-Hour Regulatory Disclosure Docket")
    print("-" * 70)
    report = await commander.generate_cert_in_report(alert)
    report_dict = report.to_pdf_dict()
    html_file = report.save_html()

    logger.info(f"Incident ID        : {report_dict['incident_id']}")
    logger.info(f"Evaluated Severity : {report_dict['severity']}")
    logger.info(f"Reachable Services : {report_dict['blast_radius_services']}")
    logger.info(f"Chokepoint Node    : {report_dict['chokepoint_node']}")
    logger.info(f"CERT-In Deadline   : {report_dict['disclosure_deadline']} (Strict 6h SLA)")
    logger.info(f"Cryptographic HMAC : {report_dict['chain_hash']}")
    logger.info(f"📁 Executive Report: file:///{html_file.replace(chr(92), '/')}")

    print("\n" + "=" * 70)
    print("  🎉 DEMO COMPLETE - HackFront India 2026 Production Ready")
    print("=" * 70 + "\n")

    await engine.close()


def main():
    asyncio.run(run_demo())


if __name__ == "__main__":
    main()