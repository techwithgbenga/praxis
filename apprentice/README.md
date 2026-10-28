# Praxis apprentice runtime

Python 3.12+, managed with [`uv`](https://docs.astral.sh/uv/). See
[`docs/APPRENTICE.md`](../docs/APPRENTICE.md) for the design and
[`docs/IMPLEMENTATION_PLAN.md`](../docs/IMPLEMENTATION_PLAN.md) milestone M4 for
what lands here and when. Nothing is implemented yet (M0 skeleton only).

```bash
uv sync --group dev
uv run ruff check .
uv run mypy
uv run pytest
```
