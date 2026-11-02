# Findings — `actenon-permit`

## Staged Version Bump — `actenon-permit 2.0.0rc1` (Candidate Stage; `RELEASE_BLOCKED`)

- `pyproject.toml` is staged at `2.0.0rc1` ahead of the `v2.0.0rc1` / `v2.0.0` release tag and PyPI publication (`v1.4.0` remains the latest tagged/published release on PyPI).
- Tagging `v2.0.0rc1` is blocked until upstream `actenon-protocol==1.6.0` and `actenon-kernel==1.3.0` are published on PyPI, `[tool.uv.sources]` is removed, and real-agent acceptance is completed.

```version-waiver
{
  "package": "actenon-permit",
  "staged_version": "2.0.0rc1",
  "published_version": "1.4.0",
  "status": "RELEASE_BLOCKED",
  "owner": "rossbuckley1990-hash",
  "reason": "Staged candidate awaiting upstream PyPI publication of actenon-protocol 1.6.0 and actenon-kernel 1.3.0, uv.sources removal, and real-agent acceptance.",
  "expires_at": "2026-11-08"
}
```
