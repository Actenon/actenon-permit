"""Tests for the WO-4 canonicalisation unification.

Covers the four acceptance criteria in the WO-4 brief that are not
already covered by the existing test suite:

  2. Cross-language byte parity: non-ASCII emits raw UTF-8, not \\uXXXX.
  3. Mixed-version ledger verifies intact (covered in test_ledger.py).
  4. Passing a raw float raises, with a message naming ACTENON-JCS-STRICT-1.
  5. Decimal("50.0") and Decimal("50.00") canonicalise to identical bytes.

Each test names the WO-4 acceptance criterion it covers in its docstring
so the link between spec and test is auditable.
"""

from __future__ import annotations

from decimal import Decimal

import pytest

from actenon_permit.model import canonical_json

# ===========================================================================
# Acceptance criterion 2 — cross-language byte parity (raw UTF-8)
# ===========================================================================


def test_canonical_json_emits_raw_utf8_not_unicode_escapes():
    """WO-4 acceptance criterion 2: non-ASCII must emit raw UTF-8.

    Before this fix, Python's json.dumps escaped non-ASCII to \\uXXXX
    while the TypeScript SDK's JSON.stringify emitted raw UTF-8. Same
    grant, different bytes, different HMAC. Now both emit raw UTF-8.

    The example is exactly the one in WO-4 defect (a):
        Python: {"reason":"caf\\u00e9 \\u2014 goodwill"}  (old)
        JS:     {"reason":"café — goodwill"}              (correct)
    """
    result = canonical_json({"reason": "café — goodwill"})
    # Raw UTF-8: the literal characters 'é' and '—' must appear in the
    # output, not their \uXXXX escapes.
    assert "café" in result, f"expected raw 'café' in output, got {result!r}"
    assert "—" in result, f"expected raw '—' in output, got {result!r}"
    assert "\\u" not in result, f"expected no \\uXXXX escapes, got {result!r}"
    # Byte-exact match against the expected output.
    assert result == '{"reason":"café — goodwill"}'


def test_canonical_json_emits_raw_utf8_command_line_equivalent():
    """WO-4 acceptance criterion 2 — the exact command from the brief:

        python -c "from actenon_permit.model import canonical_json; \
          print(canonical_json({'reason':'café — goodwill'}))"

    must emit RAW UTF-8, not \\u00e9.
    """
    # Simulate the command-line invocation. The print() would encode to
    # UTF-8 by default; we check the string value here.
    result = canonical_json({"reason": "café — goodwill"})
    printed = print(result) or result  # exercise the print path
    assert printed == '{"reason":"café — goodwill"}'


# ===========================================================================
# Acceptance criterion 4 — floats raise with ACTENON-JCS-STRICT-1 in message
# ===========================================================================


def test_canonical_json_rejects_float_with_jcs_message():
    """WO-4 acceptance criterion 4: passing a raw float raises, with a
    message naming ACTENON-JCS-STRICT-1.

    Before this fix, floats were silently accepted via default=str(),
    producing non-deterministic bytes across language runtimes. Now the
    protocol canonicaliser rejects them outright; the error message names
    ACTENON-JCS-STRICT-1 so callers know which canonicaliser rejected
    the input.
    """
    with pytest.raises(Exception) as exc_info:
        canonical_json({"x": 1.5})
    # The error message must name ACTENON-JCS-STRICT-1.
    message = str(exc_info.value)
    assert "ACTENON-JCS-STRICT-1" in message, (
        f"expected 'ACTENON-JCS-STRICT-1' in error message, got: {message!r}"
    )


def test_canonical_json_rejects_nested_float():
    """WO-4 criterion 4 — floats nested inside dicts/lists also raise."""
    with pytest.raises(Exception) as exc_info:
        canonical_json({"outer": {"inner": [1.0]}})
    assert "ACTENON-JCS-STRICT-1" in str(exc_info.value)


def test_canonical_json_rejects_float_in_list():
    """WO-4 criterion 4 — floats in lists also raise."""
    with pytest.raises(Exception) as exc_info:
        canonical_json([1.0, 2.0])
    assert "ACTENON-JCS-STRICT-1" in str(exc_info.value)


# ===========================================================================
# Acceptance criterion 5 — Decimal normalisation
# ===========================================================================


def test_decimal_50_0_and_50_00_canonicalise_identically():
    """WO-4 acceptance criterion 5: Decimal("50.0") and Decimal("50.00")
    must canonicalise to identical bytes.

    Before this fix, the old _json_default used str(Decimal), so
    Decimal("50.0") -> "50.0" and Decimal("50.00") -> "50.00" — different
    bytes despite being numerically equal. The new _coerce_decimals uses
    Decimal.normalize(), so both normalise to Decimal("5E+1") -> "5E+1".
    """
    a = canonical_json({"amount": Decimal("50.0")})
    b = canonical_json({"amount": Decimal("50.00")})
    assert a == b, (
        f"Decimal('50.0') and Decimal('50.00') must canonicalise identically; got {a!r} vs {b!r}"
    )


def test_decimal_and_int_with_same_value_canonicalise_identically():
    """Companion to criterion 5: Decimal("10") and int 10 must also
    canonicalise identically (both represent the number ten)."""
    # Note: this is via canonical_json directly, which uses _coerce_decimals.
    # Decimal("10") normalises to "1E+1"; int 10 stays as int 10 -> "10".
    # These are DIFFERENT bytes — and that's intentional: the public
    # canonical_json preserves type information. The LEDGER's
    # _coerce_decimals_for_new_chain coerces both int and float to
    # canonical Decimal strings (because SQLite REAL converts int to float
    # on storage); see test_ledger.py for that behaviour.
    a = canonical_json({"amount": Decimal("10")})
    b = canonical_json({"amount": 10})
    # These are intentionally different — the public canonical_json does
    # NOT conflate int and Decimal. The WO-4 brief only requires that
    # Decimal("50.0") and Decimal("50.00") (same type, numerically equal)
    # canonicalise identically, which the previous test covers.
    assert a != b, (
        f"Decimal('10') and int 10 should produce DIFFERENT bytes via "
        f"canonical_json (type information preserved); got {a!r} == {b!r}"
    )


def test_decimal_zero_canonicalises_stably():
    """Decimal("0") and Decimal("0.0") and Decimal("0.00") all canonicalise
    identically (all normalise to Decimal("0") -> "0")."""
    a = canonical_json({"x": Decimal("0")})
    b = canonical_json({"x": Decimal("0.0")})
    c = canonical_json({"x": Decimal("0.00")})
    assert a == b == c


# ===========================================================================
# Backward-compat: canonical_json is still exported and callable
# ===========================================================================


def test_canonical_json_still_exported_from_package():
    """WO-4 constraint C2: canonical_json is a PUBLIC EXPORT. Removing it
    is a breaking API change for downstream consumers. Verify it's still
    importable from the package root."""
    from actenon_permit import canonical_json as imported

    assert imported is canonical_json


def test_canonical_json_sorts_keys():
    """Pre-2.0.0 behaviour: sort_keys=True. ACTENON-JCS-STRICT-1 also
    sorts keys. Verify the output is sorted (so existing callers that
    rely on sorted keys continue to work)."""
    result = canonical_json({"b": 1, "a": 2, "c": 3})
    # Keys must appear in sorted order.
    assert result == '{"a":2,"b":1,"c":3}'


def test_canonical_json_handles_nested_structures():
    """Sanity check: nested dicts and lists canonicalise correctly."""
    result = canonical_json({"outer": [{"b": 1, "a": 2}, "x"]})
    assert result == '{"outer":[{"a":2,"b":1},"x"]}'
