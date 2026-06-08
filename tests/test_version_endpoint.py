"""
Patch 11B-b8-b — `/v1/version` build metadata precedence tests.

Covers the `git_sha` fallback chain (`GIT_SHA` → `RENDER_GIT_COMMIT` → null)
and the unchanged `BUILD_ID` behaviour. Schema-shape assertion guards
against future refactors that drop fields.

No DB. No admin auth. No clinic auth. No rate limiter. Pure TestClient
against `/v1/version`.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app


_EXPECTED_KEYS = {"name", "env", "git_sha", "build", "now_utc"}


def _get_version(monkeypatch: pytest.MonkeyPatch) -> dict:
    client = TestClient(app)
    response = client.get("/v1/version")
    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == _EXPECTED_KEYS, body
    assert body["name"] == "ANCHOR API"
    assert isinstance(body["env"], str)
    assert isinstance(body["now_utc"], str)
    return body


def test_version_git_sha_null_when_both_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GIT_SHA", raising=False)
    monkeypatch.delenv("RENDER_GIT_COMMIT", raising=False)
    monkeypatch.delenv("BUILD_ID", raising=False)

    body = _get_version(monkeypatch)

    assert body["git_sha"] is None
    assert body["build"] is None


def test_version_git_sha_falls_back_to_render_git_commit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GIT_SHA", raising=False)
    monkeypatch.setenv("RENDER_GIT_COMMIT", "abc1234deadbeef")
    monkeypatch.delenv("BUILD_ID", raising=False)

    body = _get_version(monkeypatch)

    assert body["git_sha"] == "abc1234deadbeef"
    assert body["build"] is None


def test_version_git_sha_uses_explicit_when_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GIT_SHA", "deadbeef0000")
    monkeypatch.delenv("RENDER_GIT_COMMIT", raising=False)
    monkeypatch.delenv("BUILD_ID", raising=False)

    body = _get_version(monkeypatch)

    assert body["git_sha"] == "deadbeef0000"
    assert body["build"] is None


def test_version_git_sha_explicit_wins_over_render(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GIT_SHA", "deadbeef0000")
    monkeypatch.setenv("RENDER_GIT_COMMIT", "abc1234deadbeef")
    monkeypatch.delenv("BUILD_ID", raising=False)

    body = _get_version(monkeypatch)

    assert body["git_sha"] == "deadbeef0000"
    assert body["build"] is None


def test_version_build_id_echoes_when_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GIT_SHA", raising=False)
    monkeypatch.delenv("RENDER_GIT_COMMIT", raising=False)
    monkeypatch.setenv("BUILD_ID", "build-12345")

    body = _get_version(monkeypatch)

    assert body["build"] == "build-12345"
    assert body["git_sha"] is None
