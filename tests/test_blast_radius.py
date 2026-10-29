import pytest
from layer2_graph_engine.engine import InMemoryEngine, CROWN_JEWELS, AttackPath, Chokepoint
from shared.events import KernelEvent, Alert, EventType, Severity


@pytest.mark.asyncio
async def test_ingest_event():
    engine = InMemoryEngine()
    event = KernelEvent(
        type=EventType.EXECVE,
        pid=1234,
        comm="curl",
        dst="10.0.0.1",
        severity=Severity.LOW,
    )
    edges = await engine.ingest_event(event)
    assert len(edges) == 1
    assert edges[0].kind == "executes"


@pytest.mark.asyncio
async def test_blast_radius():
    engine = InMemoryEngine()
    radius = await engine.compute_blast_radius("svc:staging-pod")
    assert radius == 8


@pytest.mark.asyncio
async def test_attack_paths():
    engine = InMemoryEngine()
    paths = await engine.find_attack_paths("svc:staging-pod", max_hops=6, k=3)
    assert len(paths) == 3
    # Shortest path should be 1 hop
    assert paths[0].hops == 1
    assert paths[0].path[1] in CROWN_JEWELS


@pytest.mark.asyncio
async def test_chokepoint():
    engine = InMemoryEngine()
    choke = await engine.find_chokepoint("svc:staging-pod")
    assert choke is not None
    assert choke.node_id == "svc:payment-gateway"
    assert choke.blast_reduction_pct >= 90.0


@pytest.mark.asyncio
async def test_run_on_alert():
    engine = InMemoryEngine()
    alert = Alert(
        id="TEST-001",
        title="Test alert",
        description="Test",
        severity=Severity.HIGH,
        entity="svc:staging-pod",
    )
    result = await engine.run_on_alert(alert)
    assert result.blast_radius == 8
    assert result.chokepoint == "svc:payment-gateway"
    assert result.severity in [Severity.HIGH, Severity.CRITICAL]


@pytest.mark.asyncio
async def test_severity_calculation():
    engine = InMemoryEngine()
    # 1 hop + radius > 10 = CRITICAL
    assert engine._severity_from_distance(1, 15) == Severity.CRITICAL
    # 2 hops = HIGH
    assert engine._severity_from_distance(2, 5) == Severity.HIGH
    # 3-4 hops = MEDIUM
    assert engine._severity_from_distance(3, 5) == Severity.MEDIUM
    # >4 hops = LOW
    assert engine._severity_from_distance(5, 5) == Severity.LOW