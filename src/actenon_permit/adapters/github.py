"""GitHub reference adapter for Actenon-Permit.

This is the first reference adapter implementing the ``ProviderAdapter``
contract. It supports four low-risk, consequential actions:

  * ``issue.create``   - open a new issue on a repository
  * ``issue.comment``  - add a comment to an existing issue
  * ``branch.create``  - create a branch from a ref (default: repo default)
  * ``pr.open``        - open a pull request from head -> base

Design choices
--------------

* **Low-risk demo default.** Issue/comment/branch/PR are reversible (an
  issue can be closed, a comment deleted, a branch deleted, a PR closed).
  No destructive production actions (no force-pushes, no repo deletions,
  no member additions) are exposed by this adapter.

* **Test mode.** When ``test_mode=True``, the adapter does NOT touch the
  network. It returns deterministic mock responses with realistic shapes.
  This is what the safe end-to-end demo and the security tests use.

* **Parameter validation is strict.** Unknown fields are rejected with
  ``InvalidParametersError``. Required fields are checked. This enforces
  the "adapters must not silently ignore unsupported parameters" rule.

* **Redaction.** The GitHub token never appears in any response field.
  Issue/PR URLs with token query params (which GitHub would never return,
  but defensive code is cheap) are stripped.

* **Idempotency.** GitHub's REST API supports ``Idempotency-Key`` header
  on a subset of endpoints. Where unsupported, the adapter simulates
  idempotency in-process by caching ``(key, params_hash) -> response``.
  Duplicate keys with different params raise ``InvalidParametersError``.

* **Reconciliation.** After ``execute()`` returns, the broker calls
  ``reconcile()`` which (in non-test mode) issues a GET to confirm the
  resource exists. In test mode, reconcile is a no-op.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from ..credentials import Credential
from . import (
    AdapterError,
    InvalidParametersError,
    ProviderAdapter,
    ProviderPartialResponseError,
    ProviderResponse,
    ProviderTimeoutError,
    UnsupportedActionError,
    ValidationResult,
)

GITHUB_API = "https://api.github.com"


# ---------------------------------------------------------------------------
# Per-action parameter schemas.
#
# Each action declares:
#   required: list[str]            - fields that MUST be present
#   optional: dict[str, Any]       - fields that MAY be present, with defaults
# All other fields are "unknown" and cause validation failure.
#
# Action keys are the canonical (namespaced) form: ``github.issue.create``,
# ``github.issue.comment``, etc. The adapter also accepts the bare form
# (``issue.create``) for backward compatibility with v1.0-3 callers.
# ---------------------------------------------------------------------------

_ACTION_SCHEMAS: dict[str, dict[str, Any]] = {
    "github.issue.create": {
        "required": ["owner", "repo", "title"],
        "optional": {"body": "", "labels": []},
    },
    "github.issue.comment": {
        "required": ["owner", "repo", "issue_number", "body"],
        "optional": {},
    },
    "github.branch.create": {
        "required": ["owner", "repo", "branch"],
        "optional": {"from": None},  # None means "repo default branch"
    },
    "github.pr.open": {
        "required": ["owner", "repo", "title", "head", "base"],
        "optional": {"body": "", "draft": False},
    },
}

# Backward-compat aliases: bare action name -> canonical namespaced name.
_ACTION_ALIASES: dict[str, str] = {
    "github.issue.create": "github.issue.create",
    "github.issue.comment": "github.issue.comment",
    "github.branch.create": "github.branch.create",
    "github.pr.open": "github.pr.open",
    # Bare aliases (v1.0-3 callers):
    "issue.create": "github.issue.create",
    "issue.comment": "github.issue.comment",
    "branch.create": "github.branch.create",
    "pr.open": "github.pr.open",
}


def _normalise_action(action: str) -> str:
    """Normalise an action name to its canonical form.

    Accepts both ``github.issue.create`` (canonical) and
    ``issue.create`` (backward-compat alias). Returns the canonical
    form, or the original string if it's not a known alias (in which
    case validate_params will reject it as unknown).
    """
    if action in _ACTION_ALIASES:
        return _ACTION_ALIASES[action]
    return action


class GitHubAdapter(ProviderAdapter):
    """GitHub reference adapter.

    Construct with ``test_mode=True`` for the safe demo and tests, or
    ``test_mode=False`` with a real ``GITHUB_TOKEN`` for live use.

    The token is resolved by the broker from a credential reference
    (typically ``"github_token"``) and passed in as a ``Credential``.
    The adapter NEVER receives the token as a constructor argument -
    that would defeat the broker boundary.
    """

    provider_id = "github"

    def __init__(self, *, test_mode: bool = False, api_base: str = GITHUB_API):
        self.test_mode = test_mode
        self.api_base = api_base.rstrip("/")
        # Idempotency cache: key -> (params_hash, ProviderResponse)
        self._idem_cache: dict[str, tuple[str, ProviderResponse]] = {}

    # ------------------------------------------------------------------
    # Discovery + validation
    # ------------------------------------------------------------------

    def supported_actions(self) -> list[str]:
        # Return the canonical (namespaced) action names.
        return list(_ACTION_SCHEMAS.keys())

    def validate_params(self, action: str, params: dict[str, Any]) -> ValidationResult:
        action = _normalise_action(action)
        schema = _ACTION_SCHEMAS.get(action)
        if schema is None:
            return ValidationResult(
                ok=False,
                errors=[{"field": "action", "reason": f"unknown action: {action}"}],
            )
        known = set(schema["required"]) | set(schema["optional"].keys())
        unknown = [k for k in params if k not in known]
        missing = [k for k in schema["required"] if k not in params]
        errors: list[dict[str, str]] = []
        for k in unknown:
            errors.append({"field": k, "reason": "unsupported parameter"})
        for k in missing:
            errors.append({"field": k, "reason": "required parameter missing"})
        # Type checks for known fields.
        for k in schema["required"]:
            if k in params:
                v = params[k]
                if k in ("owner", "repo", "title", "body", "branch", "head", "base", "from") and not isinstance(v, str):
                    errors.append({"field": k, "reason": f"expected string, got {type(v).__name__}"})
                if k == "issue_number" and (not isinstance(v, int) or v < 1):
                    errors.append({"field": k, "reason": "expected positive integer"})
        if "labels" in params and not isinstance(params["labels"], list):
            errors.append({"field": "labels", "reason": "expected list of strings"})
        if "draft" in params and not isinstance(params["draft"], bool):
            errors.append({"field": "draft", "reason": "expected bool"})
        return ValidationResult(ok=not errors and not unknown, unknown_fields=unknown, errors=errors)

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def execute(
        self,
        action: str,
        params: dict[str, Any],
        credential: Credential,
        *,
        idempotency_key: str | None = None,
        timeout_seconds: float | None = None,
    ) -> ProviderResponse:
        action = _normalise_action(action)
        if action not in _ACTION_SCHEMAS:
            raise UnsupportedActionError(
                f"github adapter does not support action '{action}'",
                provider=self.provider_id,
            )

        # Idempotency check (in-process cache; GitHub's Idempotency-Key
        # header is only supported on a subset of endpoints, so we layer
        # our own dedup on top for all four actions).
        if idempotency_key is not None:
            params_hash = _hash_params(action, params)
            cached = self._idem_cache.get(idempotency_key)
            if cached is not None:
                cached_hash, cached_resp = cached
                if cached_hash != params_hash:
                    raise InvalidParametersError(
                        [{"field": "*", "reason":
                          f"idempotency key '{idempotency_key}' was already used with different params"}],
                        provider=self.provider_id,
                    )
                return cached_resp

        # Validate params strictly.
        vr = self.validate_params(action, params)
        if not vr.ok:
            raise InvalidParametersError(vr.errors, provider=self.provider_id)

        if self.test_mode:
            raw = self._test_call(action, params)
        else:
            raw = self._live_call(action, params, credential, timeout_seconds)

        response = self.map_response(action, raw)
        response = self.reconcile(action, params, response)
        response = self.redact(action, params, response)

        if idempotency_key is not None:
            self._idem_cache[idempotency_key] = (_hash_params(action, params), response)

        return response

    # ------------------------------------------------------------------
    # Response mapping
    # ------------------------------------------------------------------

    def map_response(self, action: str, raw: Any) -> ProviderResponse:
        if not isinstance(raw, dict):
            raise ProviderPartialResponseError(
                provider=self.provider_id,
                action=action,
                missing_fields=["*"],
            )
        if action == "github.issue.create":
            required = ["number", "node_id", "html_url"]
            missing = [f for f in required if f not in raw]
            if missing:
                raise ProviderPartialResponseError(
                    provider=self.provider_id, action=action, missing_fields=missing
                )
            return ProviderResponse(
                ok=True,
                action=action,
                provider_action_id=raw["node_id"],
                provider_evidence={
                    "issue_number": raw["number"],
                    "issue_url": raw["html_url"],
                    "issue_node_id": raw["node_id"],
                },
                raw=raw,
            )
        if action == "github.issue.comment":
            required = ["id", "node_id", "html_url"]
            missing = [f for f in required if f not in raw]
            if missing:
                raise ProviderPartialResponseError(
                    provider=self.provider_id, action=action, missing_fields=missing
                )
            return ProviderResponse(
                ok=True,
                action=action,
                provider_action_id=raw["node_id"],
                provider_evidence={
                    "comment_id": raw["id"],
                    "comment_url": raw["html_url"],
                    "comment_node_id": raw["node_id"],
                },
                raw=raw,
            )
        if action == "github.branch.create":
            required = ["ref", "node_id", "url"]
            missing = [f for f in required if f not in raw]
            if missing:
                raise ProviderPartialResponseError(
                    provider=self.provider_id, action=action, missing_fields=missing
                )
            return ProviderResponse(
                ok=True,
                action=action,
                provider_action_id=raw["node_id"],
                provider_evidence={
                    "branch_ref": raw["ref"],
                    "branch_url": raw["url"],
                    "branch_node_id": raw["node_id"],
                },
                raw=raw,
            )
        if action == "github.pr.open":
            required = ["number", "node_id", "html_url"]
            missing = [f for f in required if f not in raw]
            if missing:
                raise ProviderPartialResponseError(
                    provider=self.provider_id, action=action, missing_fields=missing
                )
            return ProviderResponse(
                ok=True,
                action=action,
                provider_action_id=raw["node_id"],
                provider_evidence={
                    "pr_number": raw["number"],
                    "pr_url": raw["html_url"],
                    "pr_node_id": raw["node_id"],
                },
                raw=raw,
            )
        raise UnsupportedActionError(
            f"github adapter cannot map response for action '{action}'",
            provider=self.provider_id,
        )

    # ------------------------------------------------------------------
    # Reconciliation
    # ------------------------------------------------------------------

    def reconcile(
        self, action: str, params: dict[str, Any], response: ProviderResponse
    ) -> ProviderResponse:
        if self.test_mode:
            # In test mode there's nothing to reconcile against - the
            # response was synthesised deterministically.
            return response
        # Live mode: GET the resource to confirm it landed.
        try:
            owner = params["owner"]
            repo = params["repo"]
            if action == "github.issue.create":
                issue_num = response.provider_evidence.get("issue_number")
                self._http_get(
                    credential_value=None,  # reconcile doesn't strictly need auth for public repos
                    path=f"/repos/{owner}/{repo}/issues/{issue_num}",
                )
            elif action == "github.issue.comment":
                # Comments are visible via the issue timeline; we trust
                # the create response.
                pass
            elif action == "github.branch.create":
                branch = params["branch"]
                self._http_get(
                    credential_value=None,
                    path=f"/repos/{owner}/{repo}/branches/{branch}",
                )
            elif action == "github.pr.open":
                pr_num = response.provider_evidence.get("pr_number")
                self._http_get(
                    credential_value=None,
                    path=f"/repos/{owner}/{repo}/pulls/{pr_num}",
                )
        except urllib.error.HTTPError as e:
            # Reconciliation fetch failed. Mark the response as
            # "unreconciled" but DO NOT fail the call - the side effect
            # may have landed (GitHub often returns 201 then a transient
            # 404 on immediate read due to eventual consistency). The
            # broker's ledger records the original response.
            response.provider_evidence["reconcile_status"] = f"unreconciled: HTTP {e.code}"
        except Exception as e:
            response.provider_evidence["reconcile_status"] = (
                f"unreconciled: {type(e).__name__}"
            )
        else:
            response.provider_evidence["reconcile_status"] = "ok"
        return response

    # ------------------------------------------------------------------
    # Redaction
    # ------------------------------------------------------------------

    def redact(
        self, action: str, params: dict[str, Any], response: ProviderResponse
    ) -> ProviderResponse:
        # Defensive: never let the credential value leak into evidence.
        # We don't have the credential here (only the response), so we
        # redact by field name and by pattern.
        sensitive_keys = {"token", "authorization", "password", "secret", "api_key"}
        cleaned_evidence: dict[str, Any] = {}
        for k, v in response.provider_evidence.items():
            if k.lower() in sensitive_keys:
                cleaned_evidence[k] = "<redacted>"
                continue
            if isinstance(v, str) and v.startswith(("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_")):
                cleaned_evidence[k] = "<redacted>"
                continue
            if isinstance(v, str) and "token=" in v:
                # Strip query-string tokens from URLs.
                v = v.split("token=")[0] + "<redacted>"
            cleaned_evidence[k] = v
        # Drop the raw payload entirely - it may contain auth echoes.
        return ProviderResponse(
            ok=response.ok,
            action=response.action,
            provider_action_id=response.provider_action_id,
            provider_evidence=cleaned_evidence,
            cost=response.cost,
            raw=None,
        )

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    def health(self) -> dict[str, Any]:
        if self.test_mode:
            return {
                "ok": True,
                "provider": self.provider_id,
                "detail": "test mode (no network)",
            }
        # Live mode: hit /rate_limit which is cheap and unauthenticated
        # for public endpoints, but authenticated rate limits are tighter
        # so we use it as a reachability probe.
        try:
            self._http_get(credential_value=None, path="/rate_limit")
            return {"ok": True, "provider": self.provider_id, "detail": "api reachable"}
        except Exception as e:
            return {
                "ok": False,
                "provider": self.provider_id,
                "detail": f"api unreachable: {type(e).__name__}",
            }

    # ------------------------------------------------------------------
    # HTTP layer (live mode)
    # ------------------------------------------------------------------

    def _live_call(
        self,
        action: str,
        params: dict[str, Any],
        credential: Credential,
        timeout_seconds: float | None,
    ) -> dict[str, Any]:
        # Build the request.
        owner = params["owner"]
        repo = params["repo"]
        if action == "github.issue.create":
            path = f"/repos/{owner}/{repo}/issues"
            body: dict[str, Any] = {"title": params["title"]}
            if params.get("body"):
                body["body"] = params["body"]
            if params.get("labels"):
                body["labels"] = params["labels"]
            return self._http_post(credential.value, path, body, timeout_seconds)
        if action == "github.issue.comment":
            issue_num = params["issue_number"]
            path = f"/repos/{owner}/{repo}/issues/{issue_num}/comments"
            body = {"body": params["body"]}
            return self._http_post(credential.value, path, body, timeout_seconds)
        if action == "github.branch.create":
            branch = params["branch"]
            sha = params.get("from") or self._default_branch_sha(credential.value, owner, repo, timeout_seconds)
            path = f"/repos/{owner}/{repo}/git/refs"
            body = {"ref": f"refs/heads/{branch}", "sha": sha}
            return self._http_post(credential.value, path, body, timeout_seconds)
        if action == "github.pr.open":
            path = f"/repos/{owner}/{repo}/pulls"
            body: dict[str, Any] = {
                "title": params["title"],
                "head": params["head"],
                "base": params["base"],
            }
            if params.get("body"):
                body["body"] = params["body"]
            body["draft"] = bool(params.get("draft", False))
            return self._http_post(credential.value, path, body, timeout_seconds)
        raise UnsupportedActionError(
            f"github adapter cannot execute action '{action}'", provider=self.provider_id
        )

    def _default_branch_sha(
        self, token: str, owner: str, repo: str, timeout_seconds: float | None
    ) -> str:
        """Look up the SHA of the repo's default branch (used as the
        ``from`` for ``branch.create`` when not specified)."""
        repo_info = self._http_get(token, path=f"/repos/{owner}/{repo}", timeout_seconds=timeout_seconds)
        default_branch = repo_info.get("default_branch", "main")
        ref_info = self._http_get(
            token,
            path=f"/repos/{owner}/{repo}/git/refs/heads/{default_branch}",
            timeout_seconds=timeout_seconds,
        )
        sha = ref_info.get("object", {}).get("sha")
        if not sha:
            raise ProviderPartialResponseError(
                provider=self.provider_id,
                action="github.branch.create",
                missing_fields=["object.sha"],
            )
        return sha

    def _http_post(
        self,
        token: str,
        path: str,
        body: dict[str, Any],
        timeout_seconds: float | None,
    ) -> dict[str, Any]:
        url = self.api_base + path
        data = json.dumps(body).encode("utf-8")
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
            "User-Agent": "actenon-permit-broker",
        }
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        return self._http_send(req, timeout_seconds)

    def _http_get(
        self,
        credential_value: str | None,
        path: str,
        timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        url = self.api_base + path
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "actenon-permit-broker",
        }
        if credential_value:
            headers["Authorization"] = f"Bearer {credential_value}"
        req = urllib.request.Request(url, headers=headers, method="GET")
        return self._http_send(req, timeout_seconds)

    def _http_send(self, req: urllib.request.Request, timeout_seconds: float | None) -> dict[str, Any]:
        try:
            with urllib.request.urlopen(req, timeout=timeout_seconds or 30) as resp:
                body = resp.read().decode("utf-8")
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as e:
            # Sanitise: never include the request body or headers in the
            # error message - they may contain the token.
            raise AdapterError(
                f"github api returned HTTP {e.code} for {req.method} {req.full_url.split('?')[0]}",
                retryable=500 <= e.code < 600,
                provider=self.provider_id,
            ) from e
        except TimeoutError as e:
            raise ProviderTimeoutError(
                provider=self.provider_id,
                action=req.method,
                timeout_seconds=timeout_seconds or 30.0,
            ) from e
        except urllib.error.URLError as e:
            # Network failure - retryable.
            raise AdapterError(
                f"github api unreachable: {type(e.reason).__name__ if not isinstance(e.reason, str) else e.reason}",
                retryable=True,
                provider=self.provider_id,
            ) from e

    # ------------------------------------------------------------------
    # Test-mode calls (deterministic, no network)
    # ------------------------------------------------------------------

    def _test_call(self, action: str, params: dict[str, Any]) -> dict[str, Any]:
        # Deterministic synthetic IDs based on params so test assertions
        # are reproducible.
        seed = _hash_params(action, params)
        if action == "github.issue.create":
            return {
                "id": 1_000_000 + (seed % 9_000_000),
                "number": 1 + (seed % 999),
                "node_id": f"I_kwD{seed:016x}",
                "html_url": f"https://github.com/{params['owner']}/{params['repo']}/issues/{1 + (seed % 999)}",
                "title": params["title"],
                "state": "open",
            }
        if action == "github.issue.comment":
            return {
                "id": 10_000_000 + (seed % 9_000_000),
                "node_id": f"IC_kwD{seed:016x}",
                "html_url": f"https://github.com/{params['owner']}/{params['repo']}/issues/{params['issue_number']}#issuecomment-{10_000_000 + (seed % 9_000_000)}",
                "body": params["body"],
            }
        if action == "github.branch.create":
            return {
                "ref": f"refs/heads/{params['branch']}",
                "node_id": f"BR_kwD{seed:016x}",
                "url": f"https://api.github.com/repos/{params['owner']}/{params['repo']}/git/refs/heads/{params['branch']}",
                "object": {"sha": f"{seed:040x}", "type": "commit"},
            }
        if action == "github.pr.open":
            return {
                "id": 100_000 + (seed % 9_000_000),
                "number": 1 + (seed % 999),
                "node_id": f"PR_kwD{seed:016x}",
                "html_url": f"https://github.com/{params['owner']}/{params['repo']}/pull/{1 + (seed % 999)}",
                "title": params["title"],
                "head": {"ref": params["head"]},
                "base": {"ref": params["base"]},
                "state": "open",
                "draft": bool(params.get("draft", False)),
            }
        raise UnsupportedActionError(
            f"github adapter cannot synthesise test response for '{action}'",
            provider=self.provider_id,
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _hash_params(action: str, params: dict[str, Any]) -> int:
    import hashlib

    canonical = json.dumps({"action": action, "params": params}, sort_keys=True, default=str)
    return int.from_bytes(hashlib.sha256(canonical.encode("utf-8")).digest()[:8], "big")


__all__ = ["GitHubAdapter"]
