"""Allow `python -m actenon_permit ...` as an alias for `permit ...`."""

from .cli import app

if __name__ == "__main__":
    app()
