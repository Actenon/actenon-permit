"""Protocol drift gate for actenon-permit.

This test module fails when:
  - The pinned actenon-protocol version does not match permit's expected version.
  - Permit's refusal-code taxonomy (imported via actenon-kernel) disagrees
    with the protocol's catalogue.
  - The gateway emits a DENY response without structured disclosed_code
    and internal_code fields.
  - An unregistered refusal code is emitted.
  - Permit imports Cloud UI or tenant implementation (boundary preservation).
  - The protocol package imports Permit (boundary preservation).

Run with: `uv run pytest tests/test_protocol_drift.py -v`
"""

from __future__ import annotations

import pytest
from actenon.outcomes import (
    TAXONOMY_VERSION as KERNEL_TAXONOMY_VERSION,
)

# Permit imports FailureCode transitively via actenon-kernel.
from actenon.outcomes import (
    FailureCode,
    refusal_code_to_failure_code,
    to_disclosed_code,
    to_internal_code,
    to_retryable,
)
from actenon_protocol import (
    PROTOCOL_VERSION,
    RefusalCode,
    resolve_alias,
)
from actenon_protocol.canonicalisation import canonicalize_json

# ---------------------------------------------------------------------------
# 0. Pinned protocol version
# ---------------------------------------------------------------------------

EXPECTED_PROTOCOL_VERSION = "1.0.0"


def test_protocol_version_is_pinned():
    """The installed actenon-protocol version must match permit's pin."""
    assert PROTOCOL_VERSION == EXPECTED_PROTOCOL_VERSION


def test_permit_uses_kernel_sourced_taxonomy():
    """Permit imports FailureCode from actenon.outcomes, which is now
    sourced from the protocol. Verify the transitive chain works.

    FailureCode is a separate StrEnum (it has positive outcomes ALLOWED
    and APPROVAL_REQUIRED that are not in the protocol's refusal
    catalogue). The ``canonical`` property maps each refusal member to
    its canonical protocol code.
    """
    from actenon_protocol import TAXONOMY_VERSION as PROTOCOL_TAXONOMY_VERSION
    assert KERNEL_TAXONOMY_VERSION == PROTOCOL_TAXONOMY_VERSION
    # Verify a few key members' canonical values.
    assert FailureCode.PCCB_REQUIRED.canonical == "PROOF_MISSING"
    assert FailureCode.SIGNATURE_INVALID.canonical == "SIGNATURE_INVALID"
    assert FailureCode.DUPLICATE_REPLAY.canonical == "REPLAY_DETECTED"
    assert FailureCode.AUDIENCE_MISMATCH.canonical == "AUDIENCE_MISMATCH"
    assert FailureCode.REVOKED.canonical == "AUTHORITY_REVOKED"
    assert FailureCode.NOT_ACTIVE.canonical == "POLICY_REFUSAL"
    # Positive outcomes are NOT in the protocol's refusal catalogue.
    protocol_values = {c.value for c in RefusalCode}
    assert "ALLOWED" not in protocol_values
    assert "APPROVAL_REQUIRED" not in protocol_values
    assert FailureCode.ALLOWED.canonical == "ALLOWED"
    assert FailureCode.APPROVAL_REQUIRED.canonical == "APPROVAL_REQUIRED"


# ---------------------------------------------------------------------------
# 1. Refusal-code taxonomy agreement
# ---------------------------------------------------------------------------

def test_permit_emitted_codes_are_all_registered():
    """Every REFUSAL code the permit PDP can emit must be registered in the
    protocol catalogue (either as a canonical code or as a compatibility
    alias).

    Note: ALLOWED and APPROVAL_REQUIRED are NOT refusal codes — they are
    positive outcomes. They are correctly absent from the refusal catalogue.
    """
    # These are the refusal FailureCode members the PDP emits (from pdp.py).
    # ALLOWED and APPROVAL_REQUIRED are positive outcomes, not refusals.
    permit_emitted_refusal_codes = [
        "NOT_ACTIVE",
        "REVOKED",
        "EXPIRED",
        "SCOPE_DENIED",
        "OUT_OF_SCOPE",
        "BUDGET_EXCEEDED",
        "RATE_LIMITED",
        "ENGINE_ERROR",
    ]
    for code in permit_emitted_refusal_codes:
        try:
            resolve_alias(code)
        except KeyError:
            pytest.fail(
                f"permit-emitted refusal code {code!r} is not registered in the "
                f"protocol catalogue. Add it to actenon-protocol's "
                f"refusals/catalogue.v1.yaml."
            )


def test_historical_aliases_resolve_deterministically():
    """Deprecated refusal aliases MUST behave deterministically — the
    same alias always resolves to the same canonical code.

    The kernel's FailureCode keeps historical NAMES and VALUES
    (PCCB_REQUIRED.value == "PCCB_REQUIRED") for backward compatibility.
    The ``canonical`` property maps each to the protocol's canonical code.
    ``refusal_code_to_failure_code()`` returns FailureCode members;
    ``resolve_alias()`` returns canonical strings. Both must agree.
    """
    cases = [
        ("PCCB_REQUIRED", "PROOF_MISSING"),
        ("PCCB_EXPIRED", "PROOF_EXPIRED"),
        ("DUPLICATE_REPLAY", "REPLAY_DETECTED"),
        ("NOT_ACTIVE", "POLICY_REFUSAL"),
        ("REVOKED", "AUTHORITY_REVOKED"),
        ("EXPIRED", "PROOF_EXPIRED"),
        ("SCOPE_DENIED", "POLICY_REFUSAL"),
        ("OUT_OF_SCOPE", "POLICY_REFUSAL"),
        ("BUDGET_EXCEEDED", "POLICY_REFUSAL"),
        ("RATE_LIMITED", "POLICY_REFUSAL"),
        ("ENGINE_ERROR", "OUTCOME_UNKNOWN"),
    ]
    for alias, expected_canonical in cases:
        # Resolving twice must give the same result.
        r1 = resolve_alias(alias)
        r2 = resolve_alias(alias)
        assert r1 == r2 == expected_canonical, (
            f"alias {alias!r} resolved to {r1!r} then {r2!r}, expected {expected_canonical!r}"
        )
        # Via the kernel's refusal_code_to_failure_code — the returned
        # FailureCode member's ``canonical`` must be the canonical protocol code.
        fc = refusal_code_to_failure_code(alias)
        assert fc.canonical == expected_canonical, (
            f"refusal_code_to_failure_code({alias!r}).canonical = {fc.canonical!r}, "
            f"expected {expected_canonical!r}"
        )


def test_unknown_refusal_code_raises_not_silently_mapped():
    """Unknown refusal codes MUST raise KeyError, NOT be silently mapped
    to a generic outcome."""
    with pytest.raises(KeyError):
        refusal_code_to_failure_code("NOT_A_REAL_CODE")
    with pytest.raises(KeyError):
        resolve_alias("NOT_A_REAL_CODE")


# ---------------------------------------------------------------------------
# 2. Disclosure model — structured DENY response
# ---------------------------------------------------------------------------

def test_gateway_deny_response_has_structured_codes():
    """The gateway's DENY response (when proof verification fails) MUST
    carry disclosed_code, internal_code, and retryable fields per the
    protocol's two-layer disclosure model.

    This test verifies the disclosure helpers that the gateway uses to
    construct those fields. The gateway's DENY response shape is enforced
    by the CI workflow's source-code inspection step.
    """
    # Verify the helpers produce the protocol-correct disclosure.
    assert to_disclosed_code("SIGNATURE_INVALID", "public") == "PROOF_INVALID"
    assert to_internal_code("SIGNATURE_INVALID", "public") is None
    assert to_retryable("SIGNATURE_INVALID") is False

    assert to_disclosed_code("SIGNATURE_INVALID", "trusted") == "PROOF_INVALID"
    assert to_internal_code("SIGNATURE_INVALID", "trusted") == "SIGNATURE_INVALID"

    # PROOF_EXPIRED is safe to disclose publicly (the expiry is in the proof).
    assert to_disclosed_code("PROOF_EXPIRED", "public") == "PROOF_EXPIRED"

    # REPLAY_DETECTED is safe to disclose publicly.
    assert to_disclosed_code("REPLAY_DETECTED", "public") == "REPLAY_DETECTED"

    # Verify the gateway source actually emits these fields.
    import inspect

    from actenon_permit.gateway import Gateway
    src = inspect.getsource(Gateway.call_tool)
    assert "disclosed_code" in src, (
        "gateway.call_tool does not emit disclosed_code in DENY response"
    )
    assert "internal_code" in src, (
        "gateway.call_tool does not emit internal_code in DENY response"
    )
    assert "retryable" in src, (
        "gateway.call_tool does not emit retryable in DENY response"
    )


def test_public_disclosed_codes_are_safe():
    """The disclosed_code under 'public' policy MUST NOT leak cryptographic
    detail. SIGNATURE_INVALID, AUDIENCE_MISMATCH, TARGET_MISMATCH,
    ACTION_MISMATCH, PARAMETER_MISMATCH, ISSUER_UNTRUSTED all collapse to
    PROOF_INVALID under public disclosure."""
    unsafe_detailed_codes = [
        "SIGNATURE_INVALID",
        "AUDIENCE_MISMATCH",
        "TARGET_MISMATCH",
        "ACTION_MISMATCH",
        "PARAMETER_MISMATCH",
        "ISSUER_UNTRUSTED",
    ]
    for code in unsafe_detailed_codes:
        disclosed = to_disclosed_code(code, "public")
        assert disclosed == "PROOF_INVALID", (
            f"unsafe code {code!r} disclosed as {disclosed!r} under public policy — "
            f"should be 'PROOF_INVALID'"
        )
        internal = to_internal_code(code, "public")
        assert internal is None, (
            f"unsafe code {code!r} internal_code {internal!r} leaked under public policy — "
            f"should be None"
        )


# ---------------------------------------------------------------------------
# 3. Boundary preservation
# ---------------------------------------------------------------------------

def test_permit_does_not_import_cloud():
    """Permit's source code MUST NOT import actenon_cloud or app.*
    (Cloud's package).

    This test scans the permit source tree for forbidden imports rather
    than checking sys.modules (which may be polluted by other tests in
    the same session, e.g. the cross-repo conformance test that imports
    cloud's ed25519_signer).
    """
    import ast
    from pathlib import Path
    permit_src = Path(__file__).resolve().parent.parent / "src" / "actenon_permit"
    violations = []
    for py_file in permit_src.rglob("*.py"):
        try:
            tree = ast.parse(py_file.read_text(), filename=str(py_file))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("actenon_cloud") or alias.name.startswith("app"):
                        violations.append(f"{py_file.name}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom) and node.module and (node.module.startswith("actenon_cloud") or node.module.startswith("app")):
                violations.append(f"{py_file.name}: from {node.module} import ...")
    assert not violations, (
        f"permit source imports cloud modules: {violations}"
    )


def test_protocol_does_not_import_permit():
    """The protocol package MUST NOT import actenon_permit."""
    import sys
    loaded = set(sys.modules.keys())
    {m for m in loaded if m.startswith("actenon_permit")}
    # The protocol package itself should not import permit. We verify
    # by checking the protocol's __init__ source.
    import actenon_protocol
    with open(actenon_protocol.__file__) as f:
        init_code = f.read()
    assert "actenon_permit" not in init_code, (
        "actenon_protocol.__init__ imports actenon_permit"
    )


def test_permit_does_not_import_cloud_ui_or_tenant():
    """Permit MUST NOT import Cloud UI or tenant implementation."""
    import sys
    loaded = set(sys.modules.keys())
    # Cloud's UI lives in actenon_cloud.app.pilot_ui; tenant in
    # actenon_cloud.app.models.tenant. Neither should be loaded by permit.
    forbidden = {
        m for m in loaded
        if "pilot_ui" in m or "tenant" in m
    }
    # Filter out permit's own modules (which don't have these in their names)
    permit_forbidden = {
        m for m in forbidden
        if not m.startswith("actenon_permit")
    }
    assert not permit_forbidden, (
        f"permit imported cloud UI/tenant modules: {permit_forbidden}"
    )


# ---------------------------------------------------------------------------
# 4. Canonicalisation agreement (transitive via kernel)
# ---------------------------------------------------------------------------

def test_canonicalisation_byte_equivalence():
    """Permit's canonicalisation (via the kernel) must produce byte-identical
    output to the protocol's reference implementation."""
    from actenon_permit.model import canonical_json as permit_canonicalize_json
    test_inputs = [
        {"action": "payment.refund", "amount_cents": 2500},
        {"b": 1, "a": 2},
        ["a", "b", "c"],
    ]
    for inp in test_inputs:
        permit_out = permit_canonicalize_json(inp)
        protocol_out = canonicalize_json(inp)
        # Note: permit's canonical_json allows floats, so we only test
        # float-free inputs here. The protocol rejects floats; the kernel
        # rejects floats; permit's Grant HMAC uses this loose canonical_json.
        # This is a known drift item (audit P-01) — out of scope for this
        # integration phase.
        assert permit_out == protocol_out, (
            f"canonicalisation mismatch for {inp!r}: "
            f"permit={permit_out!r} protocol={protocol_out!r}"
        )


# ---------------------------------------------------------------------------
# 5. Protocol version rejection
# ---------------------------------------------------------------------------

def test_unsupported_major_version_is_rejected():
    """A protocol version with major != 1 must be rejected."""
    from actenon_protocol.types.common import ProtocolVersion
    from pydantic import TypeAdapter, ValidationError
    adapter = TypeAdapter(ProtocolVersion)
    assert adapter.validate_python("1.0.0") == "1.0.0"
    with pytest.raises(ValidationError):
        adapter.validate_python("2.0.0")
    with pytest.raises(ValidationError):
        adapter.validate_python("0.9.0")
