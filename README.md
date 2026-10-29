# Blast-Radius Containment Engine
> **Real-time, eBPF-powered cloud & identity blast-radius containment engine with Sarvam AI Incident Commander for Indian FinTechs and NBFCs facing RBI & CERT-In compliance pressure.**

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CERT-In Compliant](https://img.shields.io/badge/CERT--In-6--Hour%20SLA-orange.svg)](#layer-3-incident-commander-sarvam-ai--cert-in)
[![Sarvam AI](https://img.shields.io/badge/Powered%20By-Sarvam%20AI-purple.svg)](https://sarvam.ai)
[![Tests Passing](https://img.shields.io/badge/tests-12%20passed-brightgreen.svg)](#testing)

---

## Executive Summary

Indian FinTechs, payment aggregators, and NBFCs operate under strict regulatory mandates:
1. **RBI Cyber Security Framework**: Zero-trust microsegmentation and immediate blast-radius isolation.
2. **CERT-In April 2022 Directions (Section 70B IT Act)**: Strict **6-hour mandatory reporting SLA** for cyber incidents.

When a staging container, developer credential, or npm package is compromised, security teams cannot afford minutes of manual triage while attackers move laterally toward crown jewels like **UPI ledgers** and **Aadhaar vaults**.

The **Blast-Radius Containment Engine** bridges kernel-level eBPF observability, graph mathematics, and sovereign Indian generative AI to detect, calculate, isolate, and report cyber incidents in **under 50 milliseconds**.

---

## 3-Layer Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│                   Layer 1: Kernel Telemetry (eBPF)                     │
│  - Cilium Tetragon sensor compatibility & raw JSON ingestion           │
│  - Captures execve, tcp_connect, file_access syscall events            │
│  - Real-time MITRE ATT&CK technique classification                     │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Normalized KernelEvent Stream
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                   Layer 2: Temporal Graph Engine                       │
│  - Neo4j Async Driver + High-Performance Pure Python/NetworkX Engine   │
│  - Dijkstra shortest path to Crown Jewels (UPI Ledger, Aadhaar Vault)  │
│  - Yen's K-Shortest Paths for multi-route attack vector detection     │
│  - Personalized PageRank (PPR) lateral movement risk scoring           │
│  - Brandes Betweenness Centrality for critical chokepoint isolation    │
│  - Surgical containment plan: iptables rules & K8s NetworkPolicy       │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ Blast Radius & Chokepoint Metrics
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│         Layer 3: Incident Commander (Sarvam AI + CERT-In)              │
│  - Multilingual CISO assistant powered by Sarvam 105B Conversations   │
│  - Natural language reasoning in Hindi, Hinglish, and English         │
│  - Audio SOC alert synthesis via Sarvam Bulbul TTS (Priya voice)      │
│  - Automated CERT-In 6-Hour Disclosure Docket generation               │
│  - Cryptographic HMAC-SHA256 evidence chain verification               │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Key Capabilities

### 1. Kernel Telemetry (Layer 1)
- **Cilium Tetragon Compatibility**: Ingests raw `process_exec` and `process_kprobe` telemetry streams.
- **Supply-Chain Attack Simulation**: Built-in deterministic attack scenarios modeling malicious npm packages, credential theft from Vault (`.pem` keys), and lateral pivots to database services.
- **MITRE ATT&CK Mapping**: Maps every syscall directly to MITRE tactics (T1059 Command Execution, T1552 Credential Access, T1021 Lateral Movement, T1567 Exfiltration).

### 2. Graph Engine (Layer 2)
- **Crown Jewels Guarded**: `db:upi-ledger`, `db:aadhaar-vault`, and `svc:payment-gateway`.
- **Yen's K-Shortest Paths**: Finds loopless alternative paths an attacker can take if a primary route is blocked.
- **Personalized PageRank (PPR)**: Calculates dynamic probability of lateral compromise propagating from the patient-zero pod across the microservice graph.
- **Surgical Chokepoint Detection**: Identifies the single high-betweenness bridge node that shrinks the blast radius by **> 90%** with minimal production blast effect.

### 3. Incident Commander (Layer 3)
- **Sarvam AI 105B Conversations**: Real-time triage in English, Hindi, and Hinglish. Directly understands queries like:
  > *"Payment gateway pod mein kya compromise hua hai aur iska blast radius kya hai?"*
- **Sarvam Bulbul TTS**: Synthesizes audible voice broadcasts for SOC monitors in natural Indian accents (`priya` / `aditya`).
- **CERT-In 6-Hour Compliance Docket**: Generates print-ready executive HTML/PDF disclosure reports complete with:
  - Incident tracking ID
  - Regulatory disclosure deadline countdown
  - Affected Indian critical infrastructure breakdown
  - Cryptographic SHA-256 evidence chain & HMAC signature

---

## Quickstart

### Prerequisites
- Python 3.10+
- (Optional) Neo4j 5.0+ (falls back automatically to in-memory graph engine)
- Sarvam AI API Key (configured in `.env`)

### Installation
```bash
git clone https://github.com/Skeletor-Pirate/blast-radius-engine.git
cd blast-radius-engine
pip install -e .
```

### Environment Configuration
Copy the template and configure your Sarvam AI credentials:
```bash
cp .env.example .env
```
In `.env`:
```ini
SARVAM_AI_API_KEY=your_sarvam_api_key_here
NEO4J_URI=bolt://localhost:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=password
```

---

## Running the Demonstration

### 1. Terminal End-to-End Demo
Run the complete multi-phase demonstration in your terminal:
```bash
python run_demo.py
```
This executes:
1. eBPF kernel telemetry capture of an npm supply-chain attack.
2. Anomaly detection triggering a critical alert on vault credential access.
3. Graph analysis computing Yen's paths, blast radius, and structural chokepoint.
4. Surgical containment plan generation with ready-to-run iptables rules.
5. Live Sarvam AI Hinglish response and Bulbul audio synthesis (`incident_audio/alert_payment_gateway.wav`).
6. CERT-In compliance report generation (`reports/CERT_IN_INC-*.html`).

### 2. Interactive Web Command Center
Start the web dashboard server:
```bash
python server.py
```
Open **`http://localhost:8000`** in your browser to access:
- **Interactive Graph Canvas**: Real-time particle animations showing lateral attack vectors and containment barriers.
- **Live Sarvam AI Voice Box**: Ask questions in Hindi/Hinglish/English and listen to synthesized voice alerts.
- **CERT-In Report Viewer**: Download and inspect formal regulatory dockets.

---

## Testing

Run the full pytest suite:
```bash
pytest -v
```
Output:
```
tests/test_blast_radius.py::test_ingest_event PASSED                     [  8%]
tests/test_blast_radius.py::test_blast_radius PASSED                     [ 16%]
tests/test_blast_radius.py::test_attack_paths PASSED                     [ 25%]
tests/test_blast_radius.py::test_chokepoint PASSED                       [ 33%]
tests/test_blast_radius.py::test_run_on_alert PASSED                     [ 41%]
tests/test_blast_radius.py::test_severity_calculation PASSED             [ 50%]
tests/test_advanced_engine.py::test_personalized_pagerank PASSED         [ 58%]
tests/test_advanced_engine.py::test_containment_plan_generation PASSED   [ 66%]
tests/test_advanced_engine.py::test_tetragon_json_emitter PASSED         [ 75%]
tests/test_advanced_engine.py::test_mitre_mapping PASSED                 [ 83%]
tests/test_advanced_engine.py::test_cert_in_report_generation PASSED     [ 91%]
tests/test_advanced_engine.py::test_multi_scenario_telemetry PASSED      [100%]

============================= 12 passed in 1.12s ==============================
```

---

## HackFront India 2026 Alignment

Built for the **Cybersecurity & Sovereign AI Track**:
- **Technical Depth (30%)**: Kernel eBPF telemetry + Yen's K-Shortest Paths + Personalized PageRank + Brandes Betweenness Centrality on Neo4j/In-Memory graph.
- **Named User & Credible Payer**: CISOs at Indian FinTechs, NBFCs, and UPI payment gateways facing RBI/CERT-In statutory audits.
- **2-Minute Demo**: Supply-chain attack simulation -> real-time graph visualization -> live Sarvam AI multilingual voice triage -> 1-click CERT-In 6-hour compliance docket.

---

## License

MIT License. Copyright (c) 2026 Skeletor-Pirate.