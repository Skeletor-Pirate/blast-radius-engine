"""
Configuration loader for Blast-Radius Containment Engine.
Loads environment variables from .env if present.
"""

from __future__ import annotations
import os
from pathlib import Path
from dotenv import load_dotenv

# Search for .env in current directory or project root
_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists():
    load_dotenv(dotenv_path=_env_path)
else:
    load_dotenv()

SARVAM_AI_API_KEY = os.getenv("SARVAM_AI_API_KEY", "")
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

BLAST_RADIUS_CHOKEPOINT_THRESHOLD = float(os.getenv("BLAST_RADIUS_CHOKEPOINT_THRESHOLD", "90.0"))
ENABLE_AUDIO_BROADCAST = os.getenv("ENABLE_AUDIO_BROADCAST", "true").lower() in ("true", "1", "yes")
DEFAULT_SPEAKER = os.getenv("DEFAULT_SPEAKER", "priya")
DEFAULT_LANGUAGE = os.getenv("DEFAULT_LANGUAGE", "hi-IN")
