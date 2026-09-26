"""Actenon Boundary Kit — frictionless resource-boundary adoption.

The boundary kit converts resource-boundary protection from bespoke
security code into reviewable configuration. The adoption flow:

  1. actenon protect discover ./my-api   — find consequential endpoints
  2. Review actenon.boundary.yaml        — confirm action mappings
  3. actenon protect apply               — generate middleware + tests
  4. actenon protect test                — prove enforcement works
  5. Deploy in observe mode              — validate real traffic
  6. Switch to enforce mode              — activate protection
"""

from __future__ import annotations

from .manifest import (
    BoundaryEntry,
    BoundaryManifest,
    EnforcementConfig,
    ParameterMapping,
    ProofConfig,
    TargetMapping,
    TrustedIssuer,
    extract_value,
)
from .middleware import BoundaryMiddleware
from .proofs import (
    INTENT_HEADER,
    Ed25519PublicKeyVerifier,
    mint_boundary_proof,
    proof_headers,
    trust_root_from_issuers,
)

__all__ = [
    "BoundaryEntry",
    "BoundaryManifest",
    "BoundaryMiddleware",
    "Ed25519PublicKeyVerifier",
    "EnforcementConfig",
    "INTENT_HEADER",
    "ParameterMapping",
    "ProofConfig",
    "TargetMapping",
    "TrustedIssuer",
    "extract_value",
    "mint_boundary_proof",
    "proof_headers",
    "trust_root_from_issuers",
]
