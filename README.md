# Amyntor

Amyntor is a defensive incident-snapshot triage project. The repository currently
contains only its Python engineering foundation; dataset acquisition, product code,
modeling, APIs, and integrations remain intentionally unimplemented.

## Requirements

- `uv`
- Python 3.12 or newer (managed automatically by `uv` when needed)

The project uses a standard Python `src` layout. Importable code belongs under
`src/amyntor/`; tests belong under `tests/`. Logical areas described in the
architecture will become subpackages of `amyntor` only when their implementation
stage requires them.

## Development

Create or update the locked development environment:

```bash
uv sync --locked
```

Run all foundation checks:

```bash
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest
```

If Windows Application Control blocks Pytest's generated executable launcher, run
the equivalent `uv run python -m pytest` command.

The current test suite checks the installation and metadata contract only. Product,
dataset, and ML tests will be introduced with the stages that implement those
behaviors.

## Dependencies

Amyntor currently has no runtime dependencies. Development dependencies are kept in
the `dev` dependency group and pinned transitively by `uv.lock`:

| Dependency | Purpose | License |
| --- | --- | --- |
| Ruff | Linting and formatting | MIT |
| Pyright | Static type checking | MIT |
| Pytest | Test discovery and execution | MIT |
| uv_build | Build the pure-Python package | Apache-2.0 OR MIT |

These tools support CPython 3.12+ on the intended Windows, Linux, and macOS
development environments. No runtime, ML, training, API, database, provider, or
observability package is needed at this stage.
