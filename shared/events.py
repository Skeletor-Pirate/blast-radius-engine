"""
Shared event schema for the Blast-Radius Containment Engine.

This module is the single contract between Layer 1 (kernel telemetry),
Layer 2 (graph engine), and Layer 3 (Sarvam AI Incident Commander).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class EventType(str, Enum):
    """The three core syscall classes the engine models."""

    EXECVE = "execve"            # process execution
    TCP_CONNECT = "tcp_connect"  # network socket creation
    FILE_ACCESS = "file_access"  # file open/read/write


class Severity(str, Enum):
    """Anomaly severity computed by detection and blast-radius engines."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MITRETechnique(str, Enum):
    """Mapped MITRE ATT&CK techniques for CERT-In reporting."""

    T1059_EXECUTION = "T1059: Command & Scripting Interpreter"
    T1552_CREDENTIAL_ACCESS = "T1552: Unsecured Credentials Access"
    T1021_LATERAL_MOVEMENT = "T1021: Remote Service / Lateral Movement"
    T1567_EXFILTRATION = "T1567: Exfiltration Over Web / Cloud Service"
    T1078_PRIVILEGE_ABUSE = "T1078: Valid Accounts & Token Misuse"
    T1498_NETWORK_IMPACT = "T1498: Network Denial / Disruption"


class KernelEvent(BaseModel):
    """
    One normalised kernel-level event.
    Compatible with Cilium Tetragon, eBPF tracepoints, and Windows emulator.
    """

    ts: float = Field(default_factory=time.time)
    type: EventType
    pid: int
    uid: int = 0
    comm: str = ""
    binary: Optional[str] = None
    cwd: Optional[str] = None
    args: list[str] = Field(default_factory=list)
    dst: Optional[str] = None       # IP, domain, or target service
    dst_port: Optional[int] = None
    path: Optional[str] = None
    src: Optional[str] = None       # Source IP or source pod
    src_port: Optional[int] = None
    severity: Severity = Severity.INFO
    mitre_technique: Optional[str] = None
    raw: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ts")
    @classmethod
    def _clamp_ts(cls, v: float) -> float:
        return max(0.0, float(v))

    def event_id(self) -> str:
        """Deterministic SHA-256 fingerprint so the graph can de-duplicate events."""
        payload = json.dumps(
            {
                "type": self.type.value,
                "pid": self.pid,
                "uid": self.uid,
                "comm": self.comm,
                "binary": self.binary,
                "dst": self.dst,
                "dst_port": self.dst_port,
                "path": self.path,
                "args": self.args,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode()).hexdigest()[:16]

    def infer_mitre_technique(self) -> str:
        """Heuristically assign MITRE ATT&CK technique."""
        if self.mitre_technique:
            return self.mitre_technique
        if self.type == EventType.FILE_ACCESS and self.path and any(k in self.path for k in ["vault", "credentials", ".pem", "secret", "key"]):
            return MITRETechnique.T1552_CREDENTIAL_ACCESS.value
        if self.type == EventType.EXECVE and any(c in self.comm for c in ["npm", "bash", "sh", "curl", "wget", "python"]):
            return MITRETechnique.T1059_EXECUTION.value
        if self.type == EventType.TCP_CONNECT and (self.dst or self.dst_port):
            return MITRETechnique.T1021_LATERAL_MOVEMENT.value
        if self.path and any(k in self.path for k in ["s3", "backup", "exfil", "pii", "dump"]):
            return MITRETechnique.T1567_EXFILTRATION.value
        return MITRETechnique.T1078_PRIVILEGE_ABUSE.value

    def as_dict(self) -> dict[str, Any]:
        data = self.model_dump()
        if not data.get("mitre_technique"):
            data["mitre_technique"] = self.infer_mitre_technique()
        return data


class GraphEdge(BaseModel):
    """
    Directed relationship between two nodes in the temporal attack graph.
    """

    src: str          # source node id (e.g. pid:9999, svc:staging-pod)
    dst: str          # destination node id (e.g. svc:payment-gateway, db:upi-ledger)
    kind: str         # "executes" | "connects_to" | "accesses" | "assumes_role"
    weight: float = 1.0
    ts: float = Field(default_factory=time.time)
    evidence: list[str] = Field(default_factory=list)  # event ids contributing to edge

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()


class Alert(BaseModel):
    """
    Security alert triggering graph blast-radius analysis & containment.
    """

    id: str
    ts: float = Field(default_factory=time.time)
    title: str
    description: str
    severity: Severity = Severity.HIGH
    source_event_ids: list[str] = Field(default_factory=list)
    entity: Optional[str] = None           # compromised node id
    blast_radius: Optional[int] = None     # total reachable nodes
    chokepoint: Optional[str] = None       # critical node to isolate
    blast_radius_pct: Optional[float] = None # reduction % when chokepoint severed
    threatened_crown_jewels: list[str] = Field(default_factory=list)
    cryptographic_chain_hash: Optional[str] = None

    def compute_evidence_hash(self, secret_key: str = "cert_in_compliance_secret") -> str:
        """Compute an HMAC-SHA256 evidence chain verification token."""
        data = f"{self.id}|{self.ts}|{self.entity}|{self.blast_radius}|{self.chokepoint}|{','.join(sorted(self.source_event_ids))}"
        self.cryptographic_chain_hash = hmac.new(
            secret_key.encode(), data.encode(), hashlib.sha256
        ).hexdigest()
        return self.cryptographic_chain_hash

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()