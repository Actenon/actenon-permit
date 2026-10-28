# Findings — `actenon-permit`

## Staged Version Bump — `actenon-permit 2.0.0rc1` (Coordinated Unicorn Release)

- `pyproject.toml` is staged at `2.0.0rc1` ahead of the `v2.0.0rc1` / `v2.0.0` release tag and PyPI publication (`v1.5.0` remains the latest tagged/published release on PyPI).
- Tagging `v2.0.0rc1` is intentionally deferred until all repositories in the coordinated release graph (`actenon-protocol`, `actenon-kernel`, `actenon-scan`, `sdk-go`, `sdk-rust`, `actenon-permit`, `actenon-airlock`) pass cross-repo verification on `main`, so `ASSERT B` (`newest_tag == pypi_latest`) and `ASSERT C` (`pyproject_version` documented in `FINDINGS.md`) remain coherent throughout staging.
