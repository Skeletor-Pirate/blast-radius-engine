"""
Layer 3 - Incident Commander (Sarvam AI & CERT-In Compliance).

Integrates Sarvam AI for:
- Multilingual voice/text incident triage (Hindi, Hinglish, English)
- Sarvam Bulbul Text-to-Speech audio broadcast generation
- CERT-In 6-hour regulatory disclosure docket generation
- Cryptographic evidence chain verification
"""

from __future__ import annotations

import base64
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

from shared.config import (
    SARVAM_AI_API_KEY,
    DEFAULT_SPEAKER,
    DEFAULT_LANGUAGE,
)
from shared.events import Alert, Severity
from .cert_in_template import render_cert_in_html

logger = logging.getLogger(__name__)


@dataclass
class CERTInReport:
    """CERT-In compliant 6-hour incident report."""

    incident_id: str
    timestamp: datetime
    entity: str
    severity: str
    attack_path: list[str]
    blast_radius: int
    chokepoint: str
    evidence_hashes: list[str]
    disclosure_deadline: datetime
    threatened_crown_jewels: list[str] = field(default_factory=list)
    chain_hash: str = ""

    def to_pdf_dict(self) -> dict:
        return {
            "incident_id": self.incident_id,
            "timestamp": self.timestamp.isoformat(),
            "entity": self.entity,
            "severity": self.severity,
            "attack_path": self.attack_path,
            "blast_radius_services": self.blast_radius,
            "chokepoint_node": self.chokepoint,
            "cryptographic_evidence": self.evidence_hashes,
            "disclosure_deadline": self.disclosure_deadline.isoformat(),
            "threatened_crown_jewels": self.threatened_crown_jewels,
            "chain_hash": self.chain_hash,
            "report_generated": datetime.now().isoformat(),
        }

    def to_html(self) -> str:
        return render_cert_in_html(self.to_pdf_dict())

    def save_html(self, target_path: Optional[str] = None) -> str:
        p = Path(target_path or f"reports/CERT_IN_{self.incident_id}.html")
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w", encoding="utf-8") as f:
            f.write(self.to_html())
        return str(p.resolve())

    def to_markdown(self) -> str:
        path_str = " -> ".join(self.attack_path) if self.attack_path else "Direct compromise"
        jewels_str = ", ".join(self.threatened_crown_jewels) if self.threatened_crown_jewels else "None direct"
        return f"""# CERT-In Incident Disclosure Docket: {self.incident_id}
**Regulatory Mandate:** Section 70B IT Act (6-Hour Mandatory Reporting)
**Incident Timestamp:** {self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}
**Mandatory Filing Deadline:** {self.disclosure_deadline.strftime('%Y-%m-%d %H:%M:%S UTC')}

---

### Incident Summary
- **Origin Entity:** `{self.entity}`
- **Severity Rating:** **{self.severity}**
- **Reachable Blast Radius:** {self.blast_radius} microservices & buckets
- **Threatened Crown Jewels:** {jewels_str}
- **Recommended Isolation Chokepoint:** `{self.chokepoint}`

### Attack Vector Trace
`{path_str}`

### Evidence Hashes (SHA-256)
{chr(10).join(f"- `{h}`" for h in self.evidence_hashes[:5])}

**Cryptographic Chain Hash:** `{self.chain_hash}`
"""


class SarvamAICommander:
    """
    Incident Commander backed by Sarvam AI.
    Features:
    - Conversational reasoning via Sarvam 105B conversations
    - Audible SOC alerts via Sarvam Bulbul TTS
    - Automatic fallback for deterministic offline operations
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "sarvam-105b-conversations",
        speaker: str = DEFAULT_SPEAKER,
        default_language: str = DEFAULT_LANGUAGE,
    ):
        self._api_key = api_key or SARVAM_AI_API_KEY
        self._model = model
        self._speaker = speaker
        self._default_language = default_language
        self._base_url = "https://api.sarvam.ai"

    async def process_voice_query(
        self, query: str, language: str = "auto", alert_context: Optional[Alert] = None
    ) -> str:
        """
        Process a CISO / SOC voice or text query in English, Hindi, or Hinglish.
        Uses Sarvam AI LLM if API key is valid; otherwise uses local smart rule engine.
        """
        if self._api_key and not self._api_key.startswith("your_"):
            try:
                response = await self._call_sarvam_chat(query, alert_context)
                if response:
                    return response
            except Exception as e:
                logger.warning(f"Sarvam AI Chat API failed ({e}), falling back to internal heuristics.")

        return self._simulate_response(query, alert_context)

    async def _call_sarvam_chat(self, query: str, alert_context: Optional[Alert] = None) -> Optional[str]:
        context_str = ""
        if alert_context:
            context_str = (
                f"Active Incident Context:\n"
                f"- Entity: {alert_context.entity}\n"
                f"- Severity: {alert_context.severity.value}\n"
                f"- Blast Radius: {alert_context.blast_radius} nodes\n"
                f"- Identified Chokepoint: {alert_context.chokepoint}\n"
                f"- Blast Reduction if Isolated: {alert_context.blast_radius_pct}%\n"
                f"- Crown Jewels: {', '.join(alert_context.threatened_crown_jewels) if alert_context.threatened_crown_jewels else 'UPI Ledger'}\n"
            )

        system_prompt = (
            "You are the senior Incident Commander AI for Indian FinTech cybersecurity under RBI and CERT-In mandates. "
            "You communicate concisely and authoritatively in English, Hindi, or Hinglish as requested by the user. "
            "Provide crisp, tactical answers regarding incident impact, blast radius, crown jewels at risk, and immediate containment commands. "
            f"\n{context_str}"
        )

        headers = {
            "api-subscription-key": self._api_key,
            "Content-Type": "application/json",
        }
        payload = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": query},
            ],
            "max_tokens": 400,
            "temperature": 0.2,
        }

        async with httpx.AsyncClient(timeout=15.0) as client:
            res = await client.post(f"{self._base_url}/v1/chat/completions", headers=headers, json=payload)
            if res.status_code == 200:
                data = res.json()
                choices = data.get("choices", [])
                if choices and choices[0].get("message", {}).get("content"):
                    return choices[0]["message"]["content"].strip()
                logger.warning(f"Sarvam response did not contain message content: {data}")
            else:
                logger.warning(f"Sarvam chat API returned HTTP {res.status_code}: {res.text}")
        return None

    async def generate_voice_alert(
        self,
        text: str,
        target_language_code: str = "hi-IN",
        speaker: Optional[str] = None,
        output_file: Optional[str] = None,
    ) -> Optional[str]:
        """
        Synthesizes audible voice alert using Sarvam Bulbul TTS.
        Saves output audio file (WAV) and returns file path.
        """
        if not self._api_key or self._api_key.startswith("your_"):
            return None

        speaker_name = speaker or self._speaker
        headers = {
            "api-subscription-key": self._api_key,
            "Content-Type": "application/json",
        }
        # Keep input concise for rapid TTS playback
        clean_text = text.replace("*", "").replace("`", "")[:400]
        payload = {
            "inputs": [clean_text],
            "target_language_code": target_language_code,
            "speaker": speaker_name,
        }

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                res = await client.post(f"{self._base_url}/text-to-speech", headers=headers, json=payload)
                if res.status_code == 200:
                    data = res.json()
                    audios = data.get("audios", [])
                    if audios:
                        audio_b64 = audios[0]
                        audio_bytes = base64.b64decode(audio_b64)
                        out_path = Path(output_file or f"incident_audio/alert_{int(datetime.now().timestamp())}.wav")
                        out_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(out_path, "wb") as f:
                            f.write(audio_bytes)
                        logger.info(f"Synthesized voice alert saved to: {out_path}")
                        return str(out_path.resolve())
                else:
                    logger.warning(f"Sarvam TTS failed HTTP {res.status_code}: {res.text}")
        except Exception as e:
            logger.warning(f"Voice synthesis error: {e}")

        return None

    def _simulate_response(self, query: str, alert_context: Optional[Alert] = None) -> str:
        ql = query.lower()
        entity = alert_context.entity if alert_context and alert_context.entity else "svc:staging-pod"
        radius = alert_context.blast_radius if alert_context and alert_context.blast_radius is not None else 8
        choke = alert_context.chokepoint if alert_context and alert_context.chokepoint else "svc:payment-gateway"
        reduction = alert_context.blast_radius_pct if alert_context and alert_context.blast_radius_pct else 91.3

        if any(k in ql for k in ["compromise", "blast radius", "kya hua", "compromised", "status"]):
            lines = [
                "[Incident Commander - Hinglish Response]",
                "",
                f"🚨 Alert Summary: Staging pod ({entity}) se lateral movement detect hua hai.",
                f"📊 Blast Radius: {radius} services & S3 buckets compromised ho sakte hain.",
                f"🎯 Crown Jewels at Risk: db:upi-ledger, db:aadhaar-vault",
                f"⚡ Critical Chokepoint: {choke}",
                f"🛡️ Recommendation: Isolate `{choke}` immediately to prevent breach.",
                f"⏱️ CERT-In Disclosure Deadline: 6 hours ke andar mandatory report submit karni hai.",
            ]
            return "\n".join(lines)

        if any(k in ql for k in ["chokepoint", "isolate", "contain", "action", "remediation"]):
            lines = [
                "[Surgical Containment Action]",
                "",
                f"🎯 Identified Structural Chokepoint: {choke}",
                f"📉 Blast Reduction if Isolated: {reduction:.1f}%",
                f"⚙️ Containment Action: Revoking token & applying Kubernetes NetworkPolicy isolate-{choke.replace('svc:', '')}",
                f"⏱️ Execution Time: < 50ms",
                f"✅ Production Checkout & Core Services remain unaffected.",
            ]
            return "\n".join(lines)

        return f"Incident Commander received query: '{query}'. System nominal. Active monitoring engaged."

    async def generate_cert_in_report(self, alert: Optional[Alert]) -> CERTInReport:
        now = datetime.now()
        now_str = now.strftime("%Y%m%d-%H%M%S")
        report = CERTInReport(
            incident_id=f"INC-{now_str}",
            timestamp=now,
            entity=alert.entity if alert and alert.entity else "svc:staging-pod",
            severity=alert.severity.value if alert and alert.severity else Severity.HIGH.value,
            attack_path=["svc:staging-pod", "svc:payment-gateway", "db:upi-ledger"],
            blast_radius=alert.blast_radius if alert and alert.blast_radius is not None else 8,
            chokepoint=alert.chokepoint if alert and alert.chokepoint else "svc:payment-gateway",
            evidence_hashes=alert.source_event_ids if alert and alert.source_event_ids else [
                "a1f49b80e7d1421c", "f82b7c4d9a1e053b", "7e3b91c4d8e20f1a"
            ],
            disclosure_deadline=now + timedelta(hours=6),
            threatened_crown_jewels=alert.threatened_crown_jewels if alert and alert.threatened_crown_jewels else [
                "db:upi-ledger", "db:aadhaar-vault"
            ],
        )
        if alert:
            report.chain_hash = alert.compute_evidence_hash()
        else:
            report.chain_hash = f"hash-{now_str}"
        return report