import pytest
from layer1_telemetry.emitter import SyntheticTelemetry, TetragonJsonEmitter, EventType
from layer2_graph_engine.engine import InMemoryEngine, CROWN_JEWELS
from layer3_incident_commander.commander import SarvamAICommander, CERTInReport
from shared.events import KernelEvent, Alert, Severity, MITRETechnique


@pytest.mark.asyncio
async def test_personalized_pagerank():
    engine = InMemoryEngine()
    scores = await engine.compute_personalized_pagerank("svc:staging-pod")
    assert "svc:staging-pod" in scores
    assert scores["svc:staging-pod"] == 1.0
    # Payment gateway should have high risk score
    assert "svc:payment-gateway" in scores
    assert scores["svc:payment-gateway"] > 0.3


@pytest.mark.asyncio
async def test_containment_plan_generation():
    engine = InMemoryEngine()
    plan = await engine.generate_containment_plan("svc:staging-pod", "svc:payment-gateway")
    assert plan.chokepoint_node == "svc:payment-gateway"
    assert plan.original_blast_radius == 8
    assert "iptables" in plan.iptables_rule
    assert "NetworkPolicy" in plan.k8s_network_policy
    assert "payment-gateway" in plan.k8s_network_policy


@pytest.mark.asyncio
async def test_tetragon_json_emitter():
    exec_line = '{"process_exec": {"process": {"pid": 4321, "comm": "curl", "arguments": "http://10.0.0.1"}}}'
    ev = TetragonJsonEmitter.parse_line(exec_line)
    assert ev is not None
    assert ev.type == EventType.EXECVE
    assert ev.pid == 4321
    assert ev.comm == "curl"


@pytest.mark.asyncio
async def test_mitre_mapping():
    ev_file = KernelEvent(
        type=EventType.FILE_ACCESS,
        pid=1001,
        comm="cat",
        path="/vault/credentials/.pem",
    )
    assert ev_file.infer_mitre_technique() == MITRETechnique.T1552_CREDENTIAL_ACCESS.value

    ev_net = KernelEvent(
        type=EventType.TCP_CONNECT,
        pid=1002,
        comm="psql",
        dst="db:upi-ledger",
        dst_port=5432,
    )
    assert ev_net.infer_mitre_technique() == MITRETechnique.T1021_LATERAL_MOVEMENT.value


@pytest.mark.asyncio
async def test_cert_in_report_generation():
    commander = SarvamAICommander()
    alert = Alert(
        id="TEST-INC-999",
        title="UPI Ledger Access Detected",
        description="Compromised pod accessing payment ledger",
        severity=Severity.CRITICAL,
        entity="svc:staging-pod",
        blast_radius=8,
        chokepoint="svc:payment-gateway",
        source_event_ids=["sha1", "sha2"],
        threatened_crown_jewels=["db:upi-ledger"],
    )
    report = await commander.generate_cert_in_report(alert)
    assert isinstance(report, CERTInReport)
    assert "INC-" in report.incident_id
    assert report.blast_radius == 8
    assert report.chokepoint == "svc:payment-gateway"
    assert report.chain_hash != ""

    # Test HTML export
    html = report.to_html()
    assert "CERT-In Cyber Incident Disclosure Report" in html
    assert "Section 70B" in html
    assert "svc:payment-gateway" in html

    # Test Markdown export
    md = report.to_markdown()
    assert "CERT-In Incident Disclosure Docket" in md
    assert "svc:staging-pod" in md


@pytest.mark.asyncio
async def test_multi_scenario_telemetry():
    telemetry = SyntheticTelemetry(delay_seconds=0.0)
    events = []
    async for ev in telemetry.simulate_attack(scenario="k8s_container_breakout"):
        events.append(ev)
    assert len(events) == 4
    assert any(e.comm == "nsenter" for e in events)
    assert any(e.dst == "db:aadhaar-vault" for e in events)
