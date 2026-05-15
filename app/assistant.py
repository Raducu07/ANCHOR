# app/assistant.py
"""
Governed Vet Assistant router (PR 1).

PR 1 exposes a single read-only endpoint that publishes the assistant's mode
contracts. No generation, no receipts, no persistence.
"""
from __future__ import annotations

from typing import Any, Dict

from fastapi import APIRouter

from app.assistant_contracts import build_contract_discovery_payload

router = APIRouter(prefix="/v1/assistant", tags=["assistant"])


@router.get("/contracts")
def get_assistant_contracts() -> Dict[str, Any]:
    """
    Read-only contract discovery.

    Returns the assistant's mode contracts, storage policy, and which modes
    are currently active. This endpoint is unauthenticated: it carries no
    clinic data and is safe to expose for capability discovery.
    """
    return build_contract_discovery_payload()
