.PHONY: install test lint verify-claims

install:
	uv sync --extra dev

test:
	uv run pytest

lint:
	uv run ruff check .
	uv run ruff format --check .

# Machine-verify every claim the README makes about the package itself.
# Fails on any drift between docs and reality (Fable 5 Part 3A/G).
verify-claims:
	@echo "==> Verifying Python badge in sync"
	@uv run python scripts/sync_badges.py --check
	@echo "==> Verifying README install instructions"
	@uv run python scripts/check_readme_installs.py
	@echo "==> Verifying ecosystem table"
	@uv run python -m actenon_protocol.ecosystem --check README.md --repo actenon-permit
	@echo "==> Verifying protocol version pin"
	@uv run python -c "import tomllib; \
		d=tomllib.load(open('pyproject.toml','rb')); \
		deps=d['project']['dependencies']; \
		assert any('actenon-protocol' in x and '1.1.0' in x for x in deps), \
			f'actenon-protocol >= 1.1.0 not pinned: {deps}'; \
		print('OK: actenon-protocol >= 1.1.0 pinned')"
	@echo "==> Verifying pytest-asyncio is a runtime dep"
	@uv run python -c "import tomllib; \
		d=tomllib.load(open('pyproject.toml','rb')); \
		deps=d['project']['dependencies']; \
		assert any('pytest-asyncio' in x for x in deps), \
			f'pytest-asyncio not in runtime deps (Fable 5 Part 3G): {deps}'; \
		print('OK: pytest-asyncio is a runtime dep')"
	@echo "==> All claims verified."
