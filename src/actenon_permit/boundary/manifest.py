"""Boundary Manifest — declarative mapping from HTTP endpoints to Actenon actions.

The manifest is the adoption primitive. It converts resource-boundary
protection from bespoke security code into reviewable configuration.

Usage::

    from actenon_permit.boundary import BoundaryManifest

    manifest = BoundaryManifest.from_file("actenon.boundary.yaml")
    for boundary in manifest.boundaries:
        print(f"{boundary.id}: {boundary.route} -> {boundary.action}")
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class TargetMapping:
    type: str = ""
    from_expr: str = ""  # e.g. "body.payment_intent_id"


@dataclass(frozen=True)
class ParameterMapping:
    from_expr: str = ""  # e.g. "body.amount"
    type: str = "string"


@dataclass(frozen=True)
class ProofConfig:
    source: str = "header"  # "header" or "body"
    name: str = "X-Actenon-Proof"


@dataclass(frozen=True)
class EnforcementConfig:
    mode: str = "enforce"  # "observe", "warn", "enforce"
    proof_header: str = "X-Actenon-Proof"
    replay_store: str = "memory"  # "memory" or "sqlite"


@dataclass(frozen=True)
class TrustedIssuer:
    issuer: str
    jwks_uri: str = ""
    audiences: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class BoundaryEntry:
    """A single boundary mapping: one HTTP route -> one Actenon action."""
    id: str
    route: str  # e.g. "POST /refunds"
    action: str  # e.g. "payment.refund"
    target: TargetMapping = field(default_factory=TargetMapping)
    parameters: dict[str, ParameterMapping] = field(default_factory=dict)
    execution_mode: str = "resource_owned"
    audience: str = ""
    proof: ProofConfig = field(default_factory=ProofConfig)

    @property
    def method(self) -> str:
        """HTTP method (GET, POST, etc.)."""
        return self.route.split()[0].upper() if " " in self.route else "POST"

    @property
    def path(self) -> str:
        """HTTP path pattern (e.g. /refunds)."""
        return self.route.split()[1] if " " in self.route else self.route


@dataclass
class BoundaryManifest:
    """The full boundary manifest — drives middleware, tests, and deployment."""
    version: str = "1.0.0"
    service_name: str = ""
    framework: str = "fastapi"
    trusted_issuers: list[TrustedIssuer] = field(default_factory=list)
    enforcement: EnforcementConfig = field(default_factory=EnforcementConfig)
    boundaries: list[BoundaryEntry] = field(default_factory=list)

    @classmethod
    def from_file(cls, path: str | Path) -> BoundaryManifest:
        """Load a manifest from a YAML or JSON file."""
        path = Path(path)
        content = path.read_text(encoding="utf-8")
        if path.suffix in (".yaml", ".yml"):
            import yaml
            raw = yaml.safe_load(content)
        else:
            raw = json.loads(content)
        return cls.from_dict(raw)

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> BoundaryManifest:
        """Parse a manifest from a dict."""
        meta = raw.get("metadata", {})
        enforcement_raw = raw.get("enforcement", {})
        enforcement = EnforcementConfig(
            mode=enforcement_raw.get("mode", "enforce"),
            proof_header=enforcement_raw.get("proof_header", "X-Actenon-Proof"),
            replay_store=enforcement_raw.get("replay_store", "memory"),
        )
        issuers = [
            TrustedIssuer(
                issuer=i["issuer"],
                jwks_uri=i.get("jwks_uri", ""),
                audiences=i.get("audiences", []),
            )
            for i in raw.get("trusted_issuers", [])
        ]
        boundaries = []
        for b in raw.get("boundaries", []):
            target_raw = b.get("target", {})
            target = TargetMapping(
                type=target_raw.get("type", ""),
                from_expr=target_raw.get("from", ""),
            )
            params = {}
            for name, p in b.get("parameters", {}).items():
                params[name] = ParameterMapping(
                    from_expr=p.get("from", ""),
                    type=p.get("type", "string"),
                )
            proof_raw = b.get("proof", {})
            proof = ProofConfig(
                source=proof_raw.get("source", "header"),
                name=proof_raw.get("name", "X-Actenon-Proof"),
            )
            boundaries.append(BoundaryEntry(
                id=b["id"],
                route=b["route"],
                action=b["action"],
                target=target,
                parameters=params,
                execution_mode=b.get("execution_mode", "resource_owned"),
                audience=b.get("audience", ""),
                proof=proof,
            ))
        return cls(
            version=raw.get("version", "1.0.0"),
            service_name=meta.get("service_name", ""),
            framework=meta.get("framework", "fastapi"),
            trusted_issuers=issuers,
            enforcement=enforcement,
            boundaries=boundaries,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a dict."""
        return {
            "version": self.version,
            "metadata": {
                "service_name": self.service_name,
                "framework": self.framework,
            },
            "trusted_issuers": [
                {"issuer": i.issuer, "jwks_uri": i.jwks_uri, "audiences": i.audiences}
                for i in self.trusted_issuers
            ],
            "enforcement": {
                "mode": self.enforcement.mode,
                "proof_header": self.enforcement.proof_header,
                "replay_store": self.enforcement.replay_store,
            },
            "boundaries": [
                {
                    "id": b.id,
                    "route": b.route,
                    "action": b.action,
                    "target": {"type": b.target.type, "from": b.target.from_expr},
                    "parameters": {
                        name: {"from": p.from_expr, "type": p.type}
                        for name, p in b.parameters.items()
                    },
                    "execution_mode": b.execution_mode,
                    "audience": b.audience,
                    "proof": {"source": b.proof.source, "name": b.proof.name},
                }
                for b in self.boundaries
            ],
        }

    def to_yaml(self) -> str:
        """Serialise to YAML."""
        import yaml
        return yaml.dump(self.to_dict(), default_flow_style=False, sort_keys=False)

    def to_json(self) -> str:
        """Serialise to JSON."""
        return json.dumps(self.to_dict(), indent=2)

    def save(self, path: str | Path) -> None:
        """Save to a file (format from extension)."""
        path = Path(path)
        if path.suffix in (".yaml", ".yml"):
            path.write_text(self.to_yaml(), encoding="utf-8")
        else:
            path.write_text(self.to_json(), encoding="utf-8")

    def get_boundary(self, method: str, path: str) -> BoundaryEntry | None:
        """Find a boundary matching the HTTP method + path."""
        for b in self.boundaries:
            if b.method.upper() == method.upper() and _path_matches(b.path, path):
                return b
        return None


def _path_matches(pattern: str, actual: str) -> bool:
    """Check if an actual path matches a pattern (supports {param} syntax)."""
    # Convert {param} to a wildcard
    import re
    regex = re.sub(r"\{[^}]+\}", r"[^/]+", pattern)
    regex = f"^{regex}$"
    return bool(re.match(regex, actual))


def extract_value(from_expr: str, body: dict, headers: dict, path_params: dict, query: dict) -> Any:
    """Extract a value from the request using a 'source.field' expression.

    Supported sources: body, header, path, query
    Example: "body.payment_intent_id" -> body["payment_intent_id"]
    """
    parts = from_expr.split(".", 1)
    if len(parts) != 2:
        return None
    source, field = parts
    if source == "body":
        return body.get(field)
    if source == "header":
        return headers.get(field) or headers.get(field.lower())
    if source == "path":
        return path_params.get(field)
    if source == "query":
        return query.get(field)
    return None


__all__ = [
    "BoundaryEntry",
    "BoundaryManifest",
    "EnforcementConfig",
    "ParameterMapping",
    "ProofConfig",
    "TargetMapping",
    "TrustedIssuer",
    "extract_value",
]
