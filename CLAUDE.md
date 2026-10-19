# Project Name

<!-- TODO: Brief one-line description of what this project does -->

## Commands

```bash
# Install / sync dependencies
uv sync

# Run all tests
uv run pytest

# Format + lint + type check
uv run ruff format src/ tests/ && uv run ruff check src/ tests/ && uv run mypy src/

# Lint (with auto-fix)
uv run ruff check --fix src/ tests/

# Format
uv run ruff format src/ tests/

# Type check
uv run mypy src/
```

## Architecture

<!-- TODO: Describe the high-level architecture -->

## Development

- `AGENTS.md` is a symlink to `CLAUDE.md` — they are the same file.
- DO NOT skip updating `CLAUDE.md`/`AGENTS.md` and `README.md` when changes require it.
