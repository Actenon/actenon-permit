"""Structured exception hierarchy for the Actenon SDK.

All exceptions inherit from ``ActenonError``. The hierarchy is:

  ActenonError
    ├── IntentNotFoundError
    ├── ProofMissingError
    ├── ExecutionRefusedError      (action was refused — no provider call)
    ├── ExecutionFailedError       (provider call failed)
    ├── OutcomeUnknownError        (provider call timed out / partial)
    ├── ProviderError              (adapter raised unexpectedly)
    └── RetryableError             (mixin: retryable=True)

Error messages NEVER contain credentials, secrets, or provider tokens.
"""

from __future__ import annotations


class ActenonError(Exception):
    """Base exception for all SDK errors."""

    def __init__(self, message: str, *, rule: str | None = None) -> None:
        super().__init__(message)
        self.rule = rule

    @property
    def retryable(self) -> bool:
        """Whether the error is retryable. Override in subclasses."""
        return False


class IntentNotFoundError(ActenonError):
    """Raised when an intent id is not found in the store."""


class ProofMissingError(ActenonError):
    """Raised when a resource-owned submission is attempted without a proof."""


class ExecutionRefusedError(ActenonError):
    """The action was refused before any provider call.

    Reasons include: proof invalid, action out of scope, parameter
    validation failed, credential resolution failed, dev-credential
    in production mode.
    """

    def __init__(self, message: str, *, rule: str | None = None, reason: str = "") -> None:
        super().__init__(message, rule=rule)
        self.reason = reason


class ExecutionFailedError(ActenonError):
    """The provider call was attempted and failed."""


class OutcomeUnknownError(ActenonError):
    """The provider call was attempted but the outcome could not be
    determined (timeout, partial response, reconciliation pending).

    This error is retryable — the caller may re-submit (with the same
    idempotency key) or poll for reconciliation.
    """

    @property
    def retryable(self) -> bool:
        return True


class ProviderError(ActenonError):
    """The adapter raised an unexpected exception.

    The message is sanitised — it does not contain the credential value.
    """

    def __init__(self, message: str, *, rule: str | None = None, retryable: bool = False) -> None:
        super().__init__(message, rule=rule)
        self._retryable = retryable

    @property
    def retryable(self) -> bool:
        return self._retryable


class RetryableError(ActenonError):
    """Mixin: the error is retryable. The caller may re-submit with
    the same idempotency key."""

    @property
    def retryable(self) -> bool:
        return True
