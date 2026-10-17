# Amyntor

Amyntor is a defensive incident-snapshot triage project. The repository currently
contains its Python engineering foundation and G1 GUIDE acquisition tooling;
schema validation, processing, modeling, APIs and integrations remain unimplemented.

## Requirements

- `uv`
- Python 3.12 or newer (managed automatically by `uv` when needed)

The project uses a standard Python `src` layout. Importable code belongs under
`src/amyntor/`; tests belong under `tests/`. Logical areas described in the
architecture will become subpackages of `amyntor` only when their implementation
stage requires them.

Planned execution strategy: develop and test locally; run larger GUIDE inspection,
preprocessing, training and evaluation on Kaggle when needed, using the same
`src/amyntor/` code and `configs/`. Future notebooks only invoke package commands.
Configure input/output paths explicitly; do not hard-code machine or Kaggle paths.
GUIDE must pass G1–G8 before training in any environment. Final permitted Dataset,
selected Model/cards and an inference Space/demo are planned for Hugging Face.
No remote pipelines, notebooks or publication integrations exist yet. See
[architecture and ADR-017](docs/architecture.md) and the
[implementation plan](docs/implementation-plan.md).

See [G1 acquisition commands and evidence](docs/acquisition.md). Training remains
blocked; acquisition does not inspect schemas or pass G2–G8.
GUIDE version 1 has been acquired and hashed locally. The next task after review
is **schema acceptance / G2 only**; it has not begun.

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

The current test suite checks installation/metadata and bounded acquisition using
opaque synthetic artifacts, without network access. Product, schema and ML tests
will accompany their implementation stages.

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
