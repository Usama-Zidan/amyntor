# Amyntor

Amyntor is a defensive incident-snapshot triage project. It is built in stages,
and right now the repository only covers the data side: the Python engineering
foundation, GUIDE dataset acquisition, schema validation and reconstruction
tooling. There is no model, API or integration code yet, and training is not
allowed until the data gates are cleared.

## Status

Data validation runs as a series of gates (G1 to G8). GUIDE has to pass all of
them before any training happens, in any environment.

| Gate | What it covers | State |
| --- | --- | --- |
| G1 | GUIDE acquisition | Passed |
| G2 | Streaming schema validation (full lexical scan) | Passed |
| G3 | Reconstruction | Passed. Corrected v2 is saved and was verified from a fresh Kaggle notebook |
| G4 | Full Kaggle validation | Passed. Quick Save output retention confirmed |
| G5 | Leakage and dependency analysis | Tooling done, checked on synthetic data only. Real validation is still pending |
| G6 to G8 | | Not started |

Notes:

- Historical v1 of the G3 output is untouched. Its cancelled Version 2 is not
  accepted. The accepted corrected v2 is a different saved version, and its
  numeric ID is deliberately left unpinned.
- No full local reconstruction or G4 scan was run. Those ran on Kaggle.
- The next step is reviewing a bounded Kaggle benchmark for G5 before approving
  the full G5 run.
- No splits, encoders or models exist yet.

## Requirements

- `uv`
- Python 3.12 or newer (`uv` will fetch it if needed)

The project uses a standard `src` layout. Importable code goes in `src/amyntor/`
and tests go in `tests/`. Subpackages for the planned architecture will only be
added once the stage that needs them is implemented.

## Execution strategy

Develop and test locally. Run the heavy work (GUIDE processing, reconstruction,
and later training and evaluation) on Kaggle, using the same `src/amyntor/` code
and `configs/` as local runs. Notebooks should only call package commands.
Input and output paths are always passed in explicitly, so nothing is hard-coded
to a machine or to Kaggle.

A thin G3 entry point and a storage preflight support the Kaggle workflow. There
is no notebook processing pipeline and no publishing integration yet.

The plan is to publish the final permitted dataset, the selected model with its
cards, and an inference demo Space on Hugging Face.

## Development

Create or update the locked environment:

```bash
uv sync --locked
```

Run all checks:

```bash
uv run ruff check .
uv run ruff format --check .
uv run pyright
uv run pytest
```

If Windows Application Control blocks Pytest's generated launcher, use
`uv run python -m pytest` instead.

The current tests cover installation and metadata, bounded acquisition with opaque
synthetic artifacts, and streaming schema checks and disk-backed incident
fixtures. They need no network access and never scan the full corpus. Product and
ML tests will be added alongside their stages.

## Dependencies

There are no runtime dependencies yet. Development tools live in the `dev`
dependency group and are pinned through `uv.lock`:

| Dependency | Purpose | License |
| --- | --- | --- |
| Ruff | Linting and formatting | MIT |
| Pyright | Static type checking | MIT |
| Pytest | Test discovery and execution | MIT |
| uv_build | Builds the pure-Python package | Apache-2.0 OR MIT |

All of them support CPython 3.12+ on Windows, Linux and macOS. No ML, training,
API, database, provider or observability packages are needed at this stage.