"""Tests for the nits: exception rename (Leash* → Permit*) and permit init-key."""

from __future__ import annotations

import os

import pytest

# ---------------------------------------------------------------------------
# Nit 1: LeashDenied → PermitDenied, LeashApprovalRequired → PermitApprovalRequired
# ---------------------------------------------------------------------------


def test_permit_denied_is_canonical_name():
    """PermitDenied is the canonical exception class."""
    from actenon_permit import PermitDenied

    e = PermitDenied("test reason", rule_matched="test:rule")
    assert isinstance(e, Exception)
    assert e.reason == "test reason"
    assert e.rule_matched == "test:rule"
    assert str(e) == "test reason"


def test_permit_approval_required_is_canonical_name():
    """PermitApprovalRequired is the canonical exception class."""
    from actenon_permit import PermitApprovalRequired

    e = PermitApprovalRequired("needs human", rule_matched="approval:email.send")
    assert isinstance(e, Exception)
    assert e.reason == "needs human"
    assert e.rule_matched == "approval:email.send"


def test_leash_denied_backward_compat_alias():
    """LeashDenied is a backward-compat alias for PermitDenied.

    Old code that catches LeashDenied must still work.
    """
    from actenon_permit import LeashDenied, PermitDenied

    assert LeashDenied is PermitDenied, "LeashDenied must be an alias for PermitDenied"
    e = PermitDenied("test")
    assert isinstance(e, LeashDenied), "PermitDenied must be catchable as LeashDenied"


def test_leash_approval_required_backward_compat_alias():
    """LeashApprovalRequired is a backward-compat alias for PermitApprovalRequired."""
    from actenon_permit import LeashApprovalRequired, PermitApprovalRequired

    assert LeashApprovalRequired is PermitApprovalRequired
    e = PermitApprovalRequired("test")
    assert isinstance(e, LeashApprovalRequired)


def test_old_import_path_still_works():
    """Importing from the old path (pdp module) still works with both names."""
    from actenon_permit.pdp import LeashDenied, PermitDenied  # noqa: F401

    assert LeashDenied is PermitDenied


# ---------------------------------------------------------------------------
# Nit 2: permit init-key + persisted key file
# ---------------------------------------------------------------------------


def test_init_key_writes_file_with_correct_permissions(tmp_path):
    """permit init-key writes a 64-char hex key with mode 0600."""
    import stat

    from actenon_permit.cli import init_key

    key_path = tmp_path / "signing-key"
    init_key(path=key_path, force=False)

    assert key_path.is_file()
    content = key_path.read_text(encoding="utf-8").strip()
    assert len(content) == 64, f"expected 64-char hex key, got {len(content)} chars"
    int(content, 16)  # must be valid hex

    # Mode must be 0600 — the key is the root of trust.
    mode = stat.S_IMODE(os.stat(key_path).st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_init_key_refuses_to_overwrite(tmp_path):
    """permit init-key refuses to overwrite an existing key without --force."""
    from actenon_permit.cli import init_key

    key_path = tmp_path / "signing-key"
    key_path.write_text("existing-key")

    with pytest.raises((SystemExit, Exception)) as exc_info:
        init_key(path=key_path, force=False)
    # typer.Exit(code=1) — exit code should be 1
    if hasattr(exc_info.value, "code"):
        code = exc_info.value.code
        assert code == 1 or str(code) == "1"
    # The existing key must be untouched.
    assert key_path.read_text() == "existing-key"


def test_init_key_force_overwrites(tmp_path):
    """permit init-key --force overwrites an existing key."""
    from actenon_permit.cli import init_key

    key_path = tmp_path / "signing-key"
    key_path.write_text("old-key")

    init_key(path=key_path, force=True)
    new_content = key_path.read_text(encoding="utf-8").strip()
    assert new_content != "old-key"
    assert len(new_content) == 64


def test_persisted_key_loads_and_validates_across_processes(tmp_path, monkeypatch):
    """A key persisted by init-key is loaded by _get_signing_key, so grants
    minted in one process validate in another."""
    from actenon_permit.cli import init_key
    from actenon_permit.model import _get_signing_key

    key_path = tmp_path / "signing-key"
    init_key(path=key_path, force=False)

    # Point the loader at our test key.
    monkeypatch.setenv("ACTENON_SIGNING_KEY_FILE", str(key_path))
    monkeypatch.delenv("ACTENON_SIGNING_KEY", raising=False)

    # The loaded key must match what init_key wrote.
    loaded = _get_signing_key().decode("utf-8")
    written = key_path.read_text(encoding="utf-8").strip()
    assert loaded == written


def test_env_var_overrides_persisted_key(tmp_path, monkeypatch):
    """ACTENON_SIGNING_KEY env var takes precedence over the key file."""
    from actenon_permit.cli import init_key
    from actenon_permit.model import _get_signing_key

    key_path = tmp_path / "signing-key"
    init_key(path=key_path, force=False)

    monkeypatch.setenv("ACTENON_SIGNING_KEY_FILE", str(key_path))
    monkeypatch.setenv("ACTENON_SIGNING_KEY", "env-var-wins")

    assert _get_signing_key() == b"env-var-wins"


def test_ephemeral_key_warning_mentions_init_key(monkeypatch, tmp_path, capsys):
    """When no key is available, the warning tells the user to run permit init-key."""
    import actenon_permit.model as model_mod

    monkeypatch.delenv("ACTENON_SIGNING_KEY", raising=False)
    monkeypatch.delenv("ACTENON_SIGNING_KEY_FILE", raising=False)
    # Point the default key file at a non-existent path so no persisted key is found.
    monkeypatch.setattr(model_mod, "_default_key_file_path", lambda: tmp_path / "nonexistent-key")
    monkeypatch.setattr(model_mod, "_WARNED_ABOUT_DEV_KEY", False)
    monkeypatch.setattr(model_mod, "_SUPPRESS_DEV_KEY_WARNING", False)
    monkeypatch.setattr(model_mod, "_DEV_KEY", None)

    model_mod._get_signing_key()
    captured = capsys.readouterr()
    assert "permit init-key" in captured.err, "warning should mention `permit init-key`"
    assert "EPHEMERAL" in captured.err
