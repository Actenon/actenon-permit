#!/usr/bin/env python3
"""Fail if a pytest JUnit report contains a skip that is not allow-listed.

A skipped test is work CI claims but did not do. The only accepted skips are the ones listed
here, each with the reason it is accepted.

usage: assert_no_unexpected_skips.py REPORT.xml [REPORT.xml ...]
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET

# (classname, test name) -> why the skip is accepted
ALLOWED_SKIPS = {
    ("tests.test_real_agent", "test_real_llm_agent_through_gateway"):
        "needs the external z-ai LLM CLI, which CI does not have; it drives a live model",
    ("tests.test_cross_repo_conformance", "test_permit_and_cloud_produce_identical_action_hashes"):
        "needs a checkout of the private actenon-cloud repository, which public CI cannot clone",
    ("tests.test_cross_repo_conformance", "test_cloud_pccb_verifies_with_kernel_verifier"):
        "needs a checkout of the private actenon-cloud repository, which public CI cannot clone",
}


def main(paths: list[str]) -> int:
    if not paths:
        print(__doc__)
        return 2
    executed = 0
    unexpected: list[str] = []
    for path in paths:
        for case in ET.parse(path).getroot().iter("testcase"):
            key = (case.get("classname", ""), case.get("name", ""))
            skipped = case.find("skipped")
            if skipped is None:
                executed += 1
            elif key not in ALLOWED_SKIPS:
                unexpected.append(f"{key[0]}::{key[1]}: {skipped.get('message', '')}")
    print(f"executed test cases: {executed}; unexpected skips: {len(unexpected)}")
    for line in unexpected:
        print(f"UNEXPECTED SKIP {line}")
    if executed == 0:
        print("FAIL: no test case executed")
        return 1
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
