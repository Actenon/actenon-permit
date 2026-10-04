"""Exact fixed-point authority accounting, independent of Decimal context.

One budget unit is 10^-9 of the named currency/metric. Unsupported precision
is refused, never rounded. Durable units are decimal integer TEXT, avoiding
both SQLite REAL loss and its signed-64-bit integer limit. Legacy REAL columns
remain compatibility mirrors and never authorize spending after migration.
"""

import math
from decimal import Decimal, InvalidOperation

SCALE = 9
MAX_UNITS = 10**48 - 1


def check_float(value):
    if not math.isfinite(value):
        raise ValueError("budget amount must be a finite number")
    if math.ulp(value) > 1e-9:
        raise ValueError("budget float cannot preserve fixed-point precision; use an exact decimal")


def units(value):
    from .state import StateError

    if isinstance(value, bool) or not isinstance(value, (Decimal, float, int)):
        raise StateError("budget amount must be a finite number")
    if isinstance(value, float):
        try:
            check_float(value)
        except ValueError as exc:
            raise StateError(str(exc)) from exc
    try:
        number = Decimal(str(value))
    except (InvalidOperation, ValueError) as exc:
        raise StateError("budget amount must be a finite number") from exc
    if not number.is_finite():
        raise StateError("budget amount must be a finite number")
    sign, digits, exponent = number.as_tuple()
    coefficient = int("".join(map(str, digits)))
    shift = exponent + SCALE
    if shift < 0:
        # A malicious exponent must not allocate a giant power of ten.
        if coefficient and -shift > len(digits):
            raise StateError("budget amount exceeds supported fixed-point precision")
        divisor = 10 ** min(-shift, len(digits))
        coefficient, remainder = divmod(coefficient, divisor)
        if remainder:
            raise StateError("budget amount exceeds supported fixed-point precision")
    elif coefficient:
        if len(digits) + shift > 48:
            raise StateError("budget amount exceeds supported fixed-point range")
        coefficient *= 10**shift
    if coefficient > MAX_UNITS:
        raise StateError("budget amount exceeds supported fixed-point range")
    return -coefficient if sign else coefficient


def from_units(value):
    """Construct an exact Decimal without arithmetic that rounds to context."""
    integer = int(value)
    sign = "-" if integer < 0 else ""
    whole, fractional = divmod(abs(integer), 10**SCALE)
    return Decimal(f"{sign}{whole}.{fractional:09d}")


def amount(value):
    return from_units(units(value))


def add(*values):
    return from_units(sum(units(value) for value in values))


def subtract(left, right):
    return from_units(units(left) - units(right))


def decimal_text(number):
    """Exact exponent notation; matches normalize() without context rounding."""
    if not number.is_finite():
        return str(number)
    sign, raw_digits, exponent = number.as_tuple()
    digits = list(raw_digits)
    if not any(digits):
        return "-0" if sign else "0"
    while digits[-1] == 0:
        digits.pop()
        exponent += 1
    return str(Decimal((sign, tuple(digits), exponent)))


def exact_json_numbers(value):
    """Versioned audit normalizer; never used as Protocol action hashing."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float, Decimal)):
        return decimal_text(Decimal(str(value)))
    if isinstance(value, dict):
        return {key: exact_json_numbers(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [exact_json_numbers(item) for item in value]
    return value


def migrate(cur):
    """Add/fill exact columns under the caller's schema write transaction.

    Legacy available balance is narrowed by float uncertainty and all retained
    reservations against its signed cap. This cannot recover lost evidence,
    but cannot restore already charged authority. Small conservative margins
    remain held after legacy settlement. Unrepresentable data fails setup.
    """
    definitions = (
        ("grants", "remaining_units", "remaining"),
        ("rate_events", "reserved_units", "reserved_amount"),
        ("rate_events", "actual_units", "actual_cost"),
        ("budget_overruns", "amount_units", "amount"),
        ("effect_reservations", "reserved_units", "reserved_amount"),
    )
    for table, exact, legacy in definitions:
        columns = {row[1] for row in cur.execute(f"PRAGMA table_info({table})")}
        if exact not in columns:
            cur.execute(f"ALTER TABLE {table} ADD COLUMN {exact} TEXT")
        for row_id, old in cur.execute(
            f"SELECT rowid,{legacy} FROM {table} WHERE {exact} IS NULL AND {legacy} IS NOT NULL"
        ).fetchall():
            stored_units = units(Decimal(str(old)))
            if table == "grants":
                from .model import Grant

                grant_id, body = cur.execute(
                    "SELECT id,body FROM grants WHERE rowid = ?", (row_id,)
                ).fetchone()
                grant = Grant.model_validate_json(body)
                costs = cur.execute(
                    "SELECT reserved_amount,committed,actual_cost FROM rate_events WHERE grant_id = ?",
                    (grant_id,),
                ).fetchall()
                spent_upper = 0
                for reserved, committed, actual in costs:
                    if committed and actual is None:
                        from .state import StateError

                        raise StateError("legacy committed budget reservation lacks cost evidence")
                    spent_upper += legacy_bound(actual if committed else reserved, upper=True)
                stored_units = max(
                    0,
                    min(
                        legacy_bound(old, upper=False),
                        units(grant.budget.limit) - spent_upper,
                    ),
                )
                grant.budget.remaining = from_units(stored_units)
                cur.execute(
                    "UPDATE grants SET body = ?,remaining = ? WHERE rowid = ?",
                    (grant.model_dump_json(), float(grant.budget.remaining), row_id),
                )
            elif table == "budget_overruns":
                stored_units = legacy_bound(old, upper=True)
            cur.execute(
                f"UPDATE {table} SET {exact} = ? WHERE rowid = ?",
                (str(stored_units), row_id),
            )


def legacy_bound(value, *, upper):
    """Conservative unit bound for a finite nonnegative legacy REAL value."""
    from .state import StateError

    units(Decimal(str(value)))  # legacy REAL is bounded conservatively below
    if value < 0:
        raise StateError("legacy budget value must be non-negative")
    if value == 0:
        return 0
    adjacent = math.nextafter(float(value), math.inf if upper else -math.inf)
    if not math.isfinite(adjacent):
        raise StateError("legacy budget uncertainty exceeds supported range")
    number = Decimal.from_float(adjacent)
    _, digits, exponent = number.as_tuple()
    coefficient = int("".join(map(str, digits)))
    shift = exponent + SCALE
    if shift >= 0:
        bound = coefficient * 10**shift
    else:
        quotient, remainder = divmod(coefficient, 10 ** (-shift))
        bound = quotient + (1 if upper and remainder else 0)
    if bound > MAX_UNITS:
        raise StateError("legacy budget uncertainty exceeds supported range")
    return bound
