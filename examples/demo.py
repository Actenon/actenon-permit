"""The Actenon-Permit demo: a scripted agent exercising the full 7-step arc.

This file is a thin wrapper around ``actenon_permit._demo.run_demo`` so the
SPEC's repo layout (``examples/demo.py``) is preserved. The canonical
implementation lives in the package so that ``permit demo`` works after
``pip install actenon-permit``.

Run directly:

    python examples/demo.py --auto-approve

Or via the CLI:

    permit demo --auto-approve
"""

from __future__ import annotations

from actenon_permit._demo import DEMO_POLICY, run_demo

__all__ = ["DEMO_POLICY", "run_demo"]


if __name__ == "__main__":
    import sys

    run_demo(auto_approve="--auto-approve" in sys.argv)
