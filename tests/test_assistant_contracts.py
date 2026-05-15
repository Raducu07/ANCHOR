from __future__ import annotations

import os
import sys
from pathlib import Path

# Make repo root importable in both local runs and CI.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

# Allow importing app modules without needing a live database connection.
os.environ.setdefault("DATABASE_URL", "postgresql://anchor:anchor@localhost/anchor_test")
os.environ.setdefault("RATE_LIMIT_ENABLED", "1")
os.environ.setdefault("RATE_LIMIT_SECRET", "test-secret")

from app.assistant import get_assistant_contracts  # noqa: E402
from app.assistant_contracts import (  # noqa: E402
    CONTRACT_VERSION,
    HUMAN_REVIEW_REQUIRED,
    MODE_CONTRACTS,
    STATUS_ACTIVE,
    STATUS_CONTRACT_ONLY,
    STORAGE_POLICY,
    build_contract_discovery_payload,
)
from app.assistant_models import AssistantMode  # noqa: E402


def test_assistant_contracts_available() -> None:
    payload = get_assistant_contracts()

    assert isinstance(payload, dict)
    assert payload["contract_version"] == CONTRACT_VERSION
    assert isinstance(payload["modes"], list)
    # All six modes must be present in the published contract.
    assert len(payload["modes"]) == 6
    returned = {m["mode"] for m in payload["modes"]}
    expected = {m.value for m in AssistantMode}
    assert returned == expected


def test_client_communication_contract_active() -> None:
    payload = build_contract_discovery_payload()

    by_mode = {m["mode"]: m for m in payload["modes"]}
    cc = by_mode[AssistantMode.client_communication.value]

    assert cc["status"] == STATUS_ACTIVE
    assert payload["active_modes"] == [AssistantMode.client_communication.value]

    assert "communication_goal" in cc["required_fields"]
    assert "clinician_confirmed_facts" in cc["required_fields"]


def test_future_modes_not_active() -> None:
    payload = build_contract_discovery_payload()

    by_mode = {m["mode"]: m for m in payload["modes"]}

    for mode in AssistantMode:
        if mode == AssistantMode.client_communication:
            continue
        entry = by_mode[mode.value]
        assert entry["status"] == STATUS_CONTRACT_ONLY, (
            f"{mode.value} should be contract_defined_only, got {entry['status']}"
        )


def test_assistant_contract_declares_metadata_only() -> None:
    payload = build_contract_discovery_payload()
    assert payload["storage_policy"] == STORAGE_POLICY
    assert payload["storage_policy"] == "metadata_only_by_default"

    for entry in payload["modes"]:
        assert entry["content_storage"] == "not_stored_by_default"


def test_assistant_contract_declares_human_review_required() -> None:
    payload = build_contract_discovery_payload()
    assert payload["human_review_required"] is True
    assert HUMAN_REVIEW_REQUIRED is True

    for entry in payload["modes"]:
        assert entry["human_review_required"] is True


def test_assistant_contract_has_clinical_boundary_rules() -> None:
    payload = build_contract_discovery_payload()

    required_prohibited = {
        "diagnosis",
        "treatment recommendation",
        "prescribing",
        "dose calculation",
        "imaging interpretation",
        "lab interpretation",
        "triage/discharge decision",
    }

    for entry in payload["modes"]:
        prohibited = entry.get("prohibited_outputs")
        assert isinstance(prohibited, list) and prohibited, (
            f"mode {entry['mode']} must declare prohibited_outputs"
        )
        # Every clinical-prohibited token must appear in every mode.
        missing = required_prohibited - set(prohibited)
        assert not missing, f"mode {entry['mode']} missing prohibited tokens: {missing}"

        # hard_boundary must be set for every mode.
        assert entry.get("hard_boundary"), f"mode {entry['mode']} missing hard_boundary"


def test_mode_contracts_cover_every_enum_value() -> None:
    for mode in AssistantMode:
        assert mode in MODE_CONTRACTS, f"contract missing for mode {mode.value}"
