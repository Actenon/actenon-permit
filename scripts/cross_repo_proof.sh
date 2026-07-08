#!/usr/bin/env bash
# Cross-repo proof loop: validates that all three repos work as one system.
#
# Prerequisites:
#   - Kernel, Permit, and Cloud repos checked out locally
#   - uv installed (https://docs.astral.sh/uv/)
#
# Usage:
#   KERNEL_PATH=/path/to/actenon-kernel \
#   PERMIT_PATH=/path/to/actenon-permit \
#   CLOUD_PATH=/path/to/actenon-cloud \
#   bash scripts/cross_repo_proof.sh

set -euo pipefail

KERNEL_PATH="${KERNEL_PATH:?KERNEL_PATH must be set}"
PERMIT_PATH="${PERMIT_PATH:?PERMIT_PATH must be set}"
CLOUD_PATH="${CLOUD_PATH:?CLOUD_PATH must be set}"

export UV_CACHE_DIR="${UV_CACHE_DIR:-$HOME/.cache/uv}"

echo "=============================================="
echo "  Cross-Repo Proof Loop"
echo "  Kernel:  $KERNEL_PATH"
echo "  Permit:  $PERMIT_PATH"
echo "  Cloud:   $CLOUD_PATH"
echo "=============================================="
echo ""

# 1. Kernel conformance mark
echo "--- 1. Kernel conformance mark ---"
cd "$KERNEL_PATH"
python -m venv .venv 2>/dev/null || true
export PATH="$KERNEL_PATH/.venv/bin:$PATH"
pip install -e ".[dev,asymmetric]" -q 2>/dev/null
python -m actenon.cli conformance run --require-complete
echo ""

# 2. Permit mints/uses a grant and gateway-enforced action
echo "--- 2. Permit: grant + gateway-enforced action ---"
cd "$PERMIT_PATH"
export PATH="$PERMIT_PATH/.venv/bin:$PATH"
uv sync --extra dev 2>/dev/null
rm -f actenon.db*
uv run permit demo --auto-approve 2>&1 | tail -5
echo ""

# 3. Cloud mints/verifies real Kernel-compatible proof artifacts
echo "--- 3. Cloud: kernel-compatible PCCB ---"
cd "$CLOUD_PATH"
python -m venv .venv 2>/dev/null || true
export PATH="$CLOUD_PATH/.venv/bin:$PATH"
pip install -e ".[dev]" -q 2>/dev/null
python -m pytest tests/contract/test_kernel_bridge.py tests/contract/test_ed25519_cloud.py -v 2>&1 | tail -10
echo ""

# 4. Cross-repo PCCB action hash/canonicalization agreement
echo "--- 4. Cross-repo PCCB conformance ---"
cd "$PERMIT_PATH"
export ACTENON_CLOUD_PATH="$CLOUD_PATH"
uv run pytest tests/test_cross_repo_conformance.py -v 2>&1 | tail -10
echo ""

echo "=============================================="
echo "  Cross-Repo Proof Loop: COMPLETE"
echo "=============================================="
