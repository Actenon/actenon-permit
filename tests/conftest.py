"""Shared test fixtures for Actenon-Permit tests."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def _ensure_mock_stripe_key(monkeypatch):
    """Every test gets the mock secret in env. NEVER a real key."""
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")


@pytest.fixture
def tmp_db(monkeypatch, tmp_path) -> Path:
    """Point ACTENON_DB_PATH at a fresh file in a tmp dir for each test."""
    db_path = tmp_path / "test.db"
    monkeypatch.setenv("ACTENON_DB_PATH", str(db_path))
    # Reset any cached default store from a previous test.
    from actenon_permit.state import reset_default_store

    reset_default_store()
    yield db_path
    reset_default_store()


@pytest.fixture
def fresh_env(monkeypatch, tmp_path) -> Path:
    """Clean env + clean db for end-to-end demo tests."""
    db_path = tmp_path / "demo.db"
    monkeypatch.setenv("ACTENON_DB_PATH", str(db_path))
    monkeypatch.setenv("MOCK_STRIPE_KEY", "sk_mock_123")
    # Use a stable signing key so cross-process grant validation works.
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "test-signing-key-not-secret")
    from actenon_permit.state import reset_default_store

    reset_default_store()
    yield tmp_path
    reset_default_store()
