"""Test helpers for Phase 2A-1 Learn endpoints.

We avoid a live Postgres (mirroring the Assistant test approach) by building a
minimal FastAPI app per test and overriding `get_db` with a small stateful
in-memory fake that interprets the exact SQL the Learn router issues.

The fake also simulates tenant scoping: rows carry a `clinic_id` and reads are
filtered by the session's current clinic, so cross-tenant isolation can be
exercised even without real RLS.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

CLINIC_A = "11111111-1111-4111-8111-111111111111"
CLINIC_B = "33333333-3333-4333-8333-333333333333"
ADMIN_USER = "22222222-2222-4222-8222-222222222222"
STAFF_USER = "44444444-4444-4444-8444-444444444444"
OTHER_USER = "55555555-5555-4555-8555-555555555555"

# Deterministic module ids.
MOD_LITERACY = "aaaaaaa1-0000-4000-8000-000000000001"
MOD_BIAS = "aaaaaaa1-0000-4000-8000-000000000002"
MOD_ETHICS = "aaaaaaa1-0000-4000-8000-000000000003"
MOD_CONF = "aaaaaaa1-0000-4000-8000-000000000004"
MOD_TRANSP = "aaaaaaa1-0000-4000-8000-000000000005"
MOD_INACTIVE = "aaaaaaa1-0000-4000-8000-000000000099"

ALL_AUDIENCE = ["vet", "nurse", "practice_manager", "admin", "reception", "locum"]


def _module(module_id: str, slug: str, title: str, category: str, minutes: int,
            *, is_active: bool = True, role_applicability: Optional[List[str]] = None,
            version: str = "1.0.0") -> Dict[str, Any]:
    return {
        "module_id": module_id,
        "module_slug": slug,
        "version": version,
        "title": title,
        "summary": f"Summary for {title}.",
        "learning_objectives": [f"Objective for {slug}"],
        "role_applicability": list(role_applicability or ALL_AUDIENCE),
        "cpd_minutes": minutes,
        "category": category,
        "rcvs_principle_mappings": ["ai_literacy"],
        "eu_ai_act_article_mappings": ["article_4"],
        "content_reference": f"docs/learn/modules/{slug}.md",
        "is_active": is_active,
    }


def default_modules() -> Dict[str, Dict[str, Any]]:
    mods = [
        _module(MOD_LITERACY, "ai-literacy-foundations-v1",
                "AI Literacy Foundations for Veterinary Teams", "literacy", 30),
        _module(MOD_BIAS, "bias-detection-in-ai-outputs-v1",
                "Recognising Biased, Inaccurate, or Misleading AI Outputs",
                "bias_detection", 25),
        _module(MOD_ETHICS, "ethical-and-safe-ai-use-v1",
                "Ethical and Safe Use of AI in Clinical Workflows", "ethical_use", 20,
                role_applicability=["vet", "nurse"]),
        _module(MOD_CONF, "confidentiality-and-ai-v1",
                "Confidentiality and Data Protection When Using AI",
                "confidentiality", 20),
        _module(MOD_TRANSP, "explaining-ai-to-clients-v1",
                "Explaining AI Use to Pet Owners", "transparency", 15),
        _module(MOD_INACTIVE, "retired-module-v1",
                "Retired Module", "literacy", 10, is_active=False),
    ]
    return {m["module_id"]: m for m in mods}


class _Result:
    def __init__(self, row: Optional[Dict[str, Any]] = None,
                 rows: Optional[List[Dict[str, Any]]] = None,
                 scalar: Any = None):
        self._row = row
        self._rows = rows
        self._scalar = scalar

    def mappings(self) -> "_Result":
        return self

    def first(self) -> Optional[Dict[str, Any]]:
        return self._row

    def fetchone(self) -> Optional[Dict[str, Any]]:
        return self._row

    def all(self) -> List[Dict[str, Any]]:
        return list(self._rows or [])

    def scalar(self) -> Any:
        return self._scalar


class LearnFakeDB:
    """In-memory fake interpreting the Learn router / trust-delta SQL."""

    def __init__(self) -> None:
        self.current_clinic = CLINIC_A
        self.modules: Dict[str, Dict[str, Any]] = default_modules()
        self.completions: List[Dict[str, Any]] = []
        self.exports: List[Dict[str, Any]] = []
        # Default clinic_users membership for completion-rate-by-role.
        self.clinic_users: List[Dict[str, Any]] = [
            {"user_id": ADMIN_USER, "clinic_id": CLINIC_A, "role": "admin"},
            {"user_id": STAFF_USER, "clinic_id": CLINIC_A, "role": "staff"},
            {"user_id": OTHER_USER, "clinic_id": CLINIC_A, "role": "staff"},
        ]
        self.committed = False
        self.rolled_back = False

    # -- seeding helpers used by tests --
    def add_completion(self, *, user_id: str, module_id: str, clinic_id: str = CLINIC_A,
                       acknowledgement_provided: bool = False,
                       completed_at: Optional[datetime] = None) -> Dict[str, Any]:
        mod = self.modules[module_id]
        row = {
            "completion_id": f"c0000000-0000-4000-8000-{len(self.completions):012d}",
            "clinic_id": clinic_id,
            "user_id": user_id,
            "module_id": module_id,
            "module_version": mod["version"],
            "completed_at": completed_at or datetime.now(timezone.utc),
            "acknowledgement_provided": acknowledgement_provided,
            "cpd_minutes_credited": mod["cpd_minutes"],
            "is_voided": False,
            "void_reason": None,
            "voided_at": None,
            "voided_by_user_id": None,
        }
        self.completions.append(row)
        return row

    # -- context manager support (trust path uses `with SessionLocal() as db`) --
    def __enter__(self) -> "LearnFakeDB":
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False

    def begin(self) -> None:
        return None

    def commit(self) -> None:
        self.committed = True

    def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        return None

    # -- scoped views --
    def _scoped_completions(self) -> List[Dict[str, Any]]:
        return [c for c in self.completions if c["clinic_id"] == self.current_clinic]

    def _scoped_exports(self) -> List[Dict[str, Any]]:
        return [e for e in self.exports if e["clinic_id"] == self.current_clinic]

    def _scoped_users(self) -> List[Dict[str, Any]]:
        return [u for u in self.clinic_users if u["clinic_id"] == self.current_clinic]

    def execute(self, statement: Any, params: Optional[Dict[str, Any]] = None) -> _Result:
        sql = str(getattr(statement, "text", statement))
        p = dict(params or {})

        # ---- learning_modules: list ----
        if "FROM learning_modules" in sql and "ORDER BY title" in sql and "INSERT" not in sql:
            rows = [m for m in self.modules.values() if m["is_active"]]
            if "category" in p:
                rows = [m for m in rows if m["category"] == p["category"]]
            if "role" in p:
                rows = [m for m in rows if p["role"] in m["role_applicability"]]
            rows = sorted(rows, key=lambda m: m["title"])
            return _Result(rows=rows)

        # ---- learning_modules: catalogue count (trust delta) ----
        if ("FROM learning_modules" in sql and "COUNT(*)" in sql
                and "is_active = true" in sql and "learning_completions" not in sql):
            return _Result(scalar=sum(1 for m in self.modules.values() if m["is_active"]))

        # ---- learning_modules: single (detail or create-fetch) ----
        if "FROM learning_modules" in sql and "module_id = :module_id" in sql:
            return _Result(row=self.modules.get(p.get("module_id")))

        # ---- learning_completions: INSERT ----
        if "INSERT INTO learning_completions" in sql:
            key = (p["clinic_id"], p["user_id"], p["module_id"], p["module_version"])
            for c in self.completions:
                if (c["clinic_id"], c["user_id"], c["module_id"], c["module_version"]) == key:
                    raise IntegrityError("duplicate completion", p, Exception("unique_violation"))
            row = {
                "completion_id": p["completion_id"],
                "clinic_id": p["clinic_id"],
                "user_id": p["user_id"],
                "module_id": p["module_id"],
                "module_version": p["module_version"],
                "completed_at": datetime.now(timezone.utc),
                "acknowledgement_provided": p["acknowledgement_provided"],
                "cpd_minutes_credited": p["cpd_minutes_credited"],
                "is_voided": False,
                "void_reason": None,
                "voided_at": None,
                "voided_by_user_id": None,
            }
            self.completions.append(row)
            return _Result(row=row)

        # ---- learning_completions: void UPDATE ----
        if "UPDATE learning_completions" in sql and "is_voided = true" in sql:
            for c in self._scoped_completions():
                if c["completion_id"] == p["completion_id"] and not c["is_voided"]:
                    c["is_voided"] = True
                    c["void_reason"] = p["void_reason"]
                    c["voided_at"] = datetime.now(timezone.utc)
                    c["voided_by_user_id"] = p["actor"]
                    return _Result(row=c)
            return _Result(row=None)

        # ---- v_cpd_records: aggregate for a user ----
        if "FROM v_cpd_records" in sql and "user_id = :user_id" in sql:
            rows = [c for c in self._scoped_completions()
                    if c["user_id"] == p["user_id"] and not c["is_voided"]]
            if not rows:
                return _Result(row=None)
            times = [c["completed_at"] for c in rows]
            return _Result(row={
                "total_modules_completed": len(rows),
                "total_cpd_minutes": sum(c["cpd_minutes_credited"] for c in rows),
                "first_completion_at": min(times),
                "most_recent_completion_at": max(times),
            })

        # ---- learning_completions: list (me / user / cpd) ----
        if "FROM learning_completions" in sql and "user_id = :user_id" in sql:
            rows = [c for c in self._scoped_completions() if c["user_id"] == p["user_id"]]
            if "is_voided = false" in sql:
                rows = [c for c in rows if not c["is_voided"]]
            rows = sorted(rows, key=lambda c: c["completed_at"], reverse=True)
            return _Result(rows=rows)

        # ---- cpd_exports: INSERT ----
        if "INSERT INTO cpd_exports" in sql:
            payload = p["export_payload"]
            if isinstance(payload, str):
                payload = json.loads(payload)
            row = {
                "export_id": p["export_id"],
                "clinic_id": p["clinic_id"],
                "user_id": p["user_id"],
                "generated_by_user_id": p["generated_by_user_id"],
                "export_version": p["export_version"],
                "export_hash": p["export_hash"],
                "export_payload": payload,
                "generated_at": datetime.now(timezone.utc),
            }
            self.exports.append(row)
            return _Result(row=row)

        # ---- cpd_exports: list for user ----
        if "FROM cpd_exports" in sql and "user_id = :user_id" in sql:
            rows = [e for e in self._scoped_exports() if e["user_id"] == p["user_id"]]
            rows = sorted(rows, key=lambda e: e["generated_at"], reverse=True)
            return _Result(rows=rows)

        # ---- cpd_exports: single (metadata or payload) ----
        if "FROM cpd_exports" in sql and "export_id = :export_id" in sql:
            for e in self._scoped_exports():
                if e["export_id"] == p["export_id"]:
                    return _Result(row=e)
            return _Result(row=None)

        # ---- trust delta scalars ----
        if "COUNT(DISTINCT user_id)" in sql and "learning_completions" in sql:
            users = {c["user_id"] for c in self._scoped_completions() if not c["is_voided"]}
            return _Result(scalar=len(users))

        if "SUM(cpd_minutes_credited)" in sql:
            total = sum(c["cpd_minutes_credited"] for c in self._scoped_completions()
                        if not c["is_voided"])
            return _Result(scalar=total)

        if "category = 'bias_detection'" in sql:
            count = 0
            for c in self._scoped_completions():
                if c["is_voided"]:
                    continue
                mod = self.modules.get(c["module_id"])
                if mod and mod["category"] == "bias_detection":
                    count += 1
            return _Result(scalar=count)

        if "MAX(completed_at)" in sql:
            times = [c["completed_at"] for c in self._scoped_completions()
                     if not c["is_voided"]]
            return _Result(scalar=max(times) if times else None)

        if "FROM clinic_users" in sql and "GROUP BY cu.role" in sql:
            by_role: Dict[str, Dict[str, set]] = {}
            users_with = {c["user_id"] for c in self._scoped_completions()
                          if not c["is_voided"]}
            for u in self._scoped_users():
                d = by_role.setdefault(u["role"], {"total": set(), "with": set()})
                d["total"].add(u["user_id"])
                if u["user_id"] in users_with:
                    d["with"].add(u["user_id"])
            rows = [
                {"role": role, "total_users": len(d["total"]),
                 "users_with_completions": len(d["with"])}
                for role, d in by_role.items()
            ]
            return _Result(rows=rows)

        return _Result(row=None)


def build_learn_app(fake: LearnFakeDB, *, clinic_id: str = CLINIC_A,
                    user_id: str = ADMIN_USER, role: str = "admin") -> FastAPI:
    from app.auth_and_rls import require_clinic_user
    from app.db import get_db
    from app.learn_v1 import router as learn_router

    app = FastAPI()
    app.include_router(learn_router)

    def _fake_db_dep(request: Request):
        fake.current_clinic = getattr(request.state, "clinic_id", clinic_id)
        yield fake

    def _fake_auth(request: Request) -> Dict[str, str]:
        request.state.clinic_id = clinic_id
        request.state.clinic_user_id = user_id
        request.state.role = role
        return {"clinic_id": clinic_id, "clinic_user_id": user_id, "role": role}

    app.dependency_overrides[get_db] = _fake_db_dep
    app.dependency_overrides[require_clinic_user] = _fake_auth
    return app


def build_trust_app(fake: LearnFakeDB, monkeypatch: Any, *, clinic_id: str = CLINIC_A,
                    user_id: str = ADMIN_USER, role: str = "admin") -> FastAPI:
    from app import portal_trust
    from app.auth_and_rls import require_clinic_user

    def _set_ctx(db: Any, *, clinic_id: str, **kwargs: Any) -> None:
        fake.current_clinic = clinic_id

    monkeypatch.setattr(portal_trust, "SessionLocal", lambda: fake)
    monkeypatch.setattr(portal_trust, "set_rls_context", _set_ctx)
    monkeypatch.setattr(portal_trust, "clear_rls_context", lambda db: None)

    app = FastAPI()
    app.include_router(portal_trust.router)

    def _fake_auth(request: Request) -> Dict[str, str]:
        request.state.clinic_id = clinic_id
        request.state.clinic_user_id = user_id
        request.state.role = role
        return {"clinic_id": clinic_id, "clinic_user_id": user_id, "role": role}

    app.dependency_overrides[require_clinic_user] = _fake_auth
    return app


def client_for(app: FastAPI) -> TestClient:
    return TestClient(app)
