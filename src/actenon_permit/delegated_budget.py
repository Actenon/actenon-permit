"""Shared ancestor accounting inside the authority store's write transaction.

Delegation creates a narrower spending ceiling, not new money. Each reservation
retains its charged owners so settlement never infers a different payer chain.
This module does not classify actions or replace PDP authorization.
"""

from datetime import UTC, datetime

from .budget import from_units, subtract, units
from .model import Grant, GrantStatus


class DelegatedBudgetMixin:
    @staticmethod
    def _init_delegated_budget_schema(cur):
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS reservation_budget_owners (
                action_id TEXT NOT NULL,
                grant_id TEXT NOT NULL,
                PRIMARY KEY(action_id, grant_id)
            );
            CREATE INDEX IF NOT EXISTS idx_reservation_budget_owner
                ON reservation_budget_owners(grant_id, action_id);
        """)

    def _budget_lineage(self, cur, grant_id, *, live=True, dispatch=False):
        from .state import StateError

        owners, seen = [], set()
        next_id = grant_id
        now = datetime.now(UTC)
        while next_id:
            if next_id in seen or len(seen) >= 64:
                raise StateError("delegated budget lineage is cyclic or too deep")
            seen.add(next_id)
            row = cur.execute(
                "SELECT body, remaining_units FROM grants WHERE id = ?", (next_id,)
            ).fetchone()
            if row is None:
                raise StateError("delegated budget ancestor is missing")
            grant = Grant.model_validate_json(row[0])
            grant.budget.remaining = from_units(row[1])
            if live:
                statuses = (
                    {GrantStatus.ACTIVE, GrantStatus.EXHAUSTED}
                    if dispatch
                    else {GrantStatus.ACTIVE}
                )
                if grant.status not in statuses:
                    raise StateError(f"budget owner {grant.id} status is {grant.status.value}")
                if grant.expires_at <= now:
                    raise StateError(f"budget owner {grant.id} is expired")
            owners.append(grant)
            next_id = grant.parent_grant_id
        if len(owners) > 1:
            # Both links and immutable ceilings must be authenticated. Root
            # reserve() without delegation remains a trusted PDP-following API.
            if any(not owner.verify() for owner in owners):
                raise StateError("delegated budget authority signature is invalid")
            for child, parent in zip(owners, owners[1:], strict=False):
                if (
                    child.budget.currency != parent.budget.currency
                    or child.budget.limit > parent.budget.limit
                    or child.expires_at > parent.expires_at
                    or child.delegation_depth != parent.delegation_depth + 1
                    or not set(child.scopes.allow).issubset(parent.scopes.allow)
                    or not child.scopes.allow
                    and parent.scopes.allow
                    or not set(parent.scopes.deny).issubset(child.scopes.deny)
                    or not set(parent.approval_rules).issubset(child.approval_rules)
                    or parent.rate.max > 0
                    and (child.rate.max == 0 or child.rate.max > parent.rate.max)
                    or child.rate.per_seconds < parent.rate.per_seconds
                ):
                    raise StateError("delegated authority widens its parent constraints")
        if owners[-1].delegation_depth != 0:
            raise StateError("delegated budget lineage has no root authority")
        return owners

    def _write_owner_balance(self, cur, grant, remaining, now_iso, *, settle=True):
        cur.execute(
            "UPDATE grants SET remaining = ?, remaining_units = ?, updated_at = ? WHERE id = ?",
            (float(remaining), str(units(remaining)), now_iso, grant.id),
        )
        if settle:
            self._settled_status(cur, grant, remaining, now_iso)
        grant.budget.remaining = remaining
        cur.execute("UPDATE grants SET body = ? WHERE id = ?", (grant.model_dump_json(), grant.id))

    def _owner_rate_count(self, cur, grant_id, since):
        return cur.execute(
            """SELECT COUNT(*) FROM rate_events e
               JOIN reservation_budget_owners o ON o.action_id = e.action_id
               WHERE o.grant_id = ? AND e.ts >= ?""",
            (grant_id, since),
        ).fetchone()[0]

    def _settle_budget_owners(self, cur, grant_id, action_id, adjustment, now_iso):
        from .state import StateError

        rows = cur.execute(
            """SELECT g.body,g.remaining_units FROM reservation_budget_owners o
               LEFT JOIN grants g ON g.id = o.grant_id WHERE o.action_id = ?""",
            (action_id,),
        ).fetchall()
        if not rows or any(row[0] is None for row in rows):
            raise StateError("reservation budget ownership is missing")
        remaining = None
        for body, raw in rows:
            owner = Grant.model_validate_json(body)
            value = self._settled_balance(cur, owner.id, from_units(raw), adjustment)
            self._write_owner_balance(cur, owner, value, now_iso)
            if owner.id == grant_id:
                remaining = value
        if remaining is None:
            raise StateError("reservation budget ownership does not match its grant")
        return remaining

    def _migrate_delegated_budgets(self, cur):
        """Charge retained legacy spending to ancestors once, conservatively.

        The leaf was already debited. Charge each authenticated ancestor for
        held reservations or committed actual cost, recording any overrun debt.
        No historical spend/unknown effect is forgiven on reopening. Missing or
        invalid retained lineage fails setup and requires operator repair.
        """
        from .state import StateError

        events = cur.execute(
            """SELECT action_id,grant_id,reserved_units,committed,actual_units
               FROM rate_events e WHERE NOT EXISTS
               (SELECT 1 FROM reservation_budget_owners o WHERE o.action_id = e.action_id)"""
        ).fetchall()
        now_iso = datetime.now(UTC).isoformat()
        for action_id, grant_id, reserved, committed, actual in events:
            owners = self._budget_lineage(cur, grant_id, live=False)
            raw_cost = actual if committed else reserved
            if raw_cost is None or from_units(raw_cost) < 0:
                raise StateError("legacy delegated reservation lacks valid cost evidence")
            cost = from_units(raw_cost)
            for owner in owners:
                if owner.id != grant_id:
                    value = self._settled_balance(
                        cur, owner.id, owner.budget.remaining, subtract(0, cost)
                    )
                    self._write_owner_balance(cur, owner, value, now_iso, settle=cost > 0)
                cur.execute(
                    "INSERT INTO reservation_budget_owners(action_id,grant_id) VALUES (?,?)",
                    (action_id, owner.id),
                )
