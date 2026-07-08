# aauth-edocs

An implementation of the [AAuth protocol](https://github.com/dickhardt/AAuth)
(draft-hardt-oauth-aauth-protocol-09) for **internal eDocs experimentation** —
not production. Spec texts are vendored in `docs/specs/`; the roadmap and the
simplifications we deliberately made are in `IMPLEMENTATION_PLAN.md`.

Import package is `aauth_edocs` (the PyPI name `aauth` belongs to a separate
exploratory implementation, which we optionally test against).

```bash
uv sync
uv run pytest
```

Optional cross-implementation checks against the PyPI `aauth` library:

```bash
uv sync --group interop
uv run pytest tests/interop/
```
