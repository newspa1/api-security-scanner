# apisec-scanner

A lightweight scanner that tests REST APIs against the [OWASP API Security
Top 10](https://owasp.org/API-Security/editions/2023/en/0x11-t10/). Point it
at an OpenAPI/Swagger spec and a running instance of the API; it replays
each endpoint with adversarial variations and reports what it finds.

## Why this exists

Most open-source API scanners either wrap a generic fuzzer or focus on
schema validation. This project instead targets the specific, well-known
attack patterns in the OWASP API Top 10 — each check encodes *how* a real
exploit for that category works, not just "send garbage and see what
breaks."

## Status

| Check | OWASP ID | Status |
|---|---|---|
| Broken Authentication (JWT `alg=none`) | API2:2023 | ✅ implemented |
| Broken Object Level Authorization (BOLA) | API1:2023 | ⏳ stub — Week 2 |
| Mass Assignment | API3:2023 | ⏳ stub — Week 3 |
| Excessive Data Exposure | API3:2023 | ⏳ stub — Week 3-4 |

> Mass Assignment and Excessive Data Exposure intentionally share OWASP id
> API3:2023 ("Broken Object Property Level Authorization") — OWASP merged
> what were two separate 2019 categories into one in the 2023 revision (read
> vs write facets of the same missing property-level authorization). This
> scanner reports them as two distinct checks under that shared id,
> distinguished by `title`.

See each module in `src/apisec/checks/` for the implementation plan —
every stub has a docstring describing the exact approach.

## Quickstart

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

apisec --spec examples/openapi.yaml --target http://localhost:8000 \
  --auth-header "Bearer eyJhbGciOi..."
```

Run the tests:

```bash
pytest
```

## Architecture

```
src/apisec/
  spec_loader.py   # OpenAPI 3.x -> list[Endpoint]
  scanner.py        # orchestrates: for each endpoint, run every check
  report.py         # rich table + JSON export
  checks/
    base.py         # Check protocol + Finding dataclass
    broken_auth.py   # API2 — JWT alg=none (reference implementation)
    bola.py           # API1 — stub
    mass_assignment.py         # API3 (write facet) — stub
    excessive_data_exposure.py # API3 (read facet) — stub
```

Adding a new check means implementing the `Check` protocol (`id`, `title`,
`run(endpoint, base_url, session) -> list[Finding]`) and registering it in
`checks/__init__.py`.

## Roadmap

**MVP (weeks 1-6)**
- [x] Repo scaffold, spec loader, CLI, reference check (JWT `alg=none`)
- [ ] Implement BOLA check (needs two-user auth support in `scanner.py`)
- [ ] Implement Mass Assignment check
- [ ] Implement Excessive Data Exposure check
- [ ] Build `demo_vulnerable_api/` (FastAPI app with one bug per check) to
      validate each check catches its target vulnerability

**Stretch (weeks 7-10)**
- [ ] GitHub Action so the scanner can run in CI against a preview deploy
- [ ] Simple web dashboard for scan results
- [ ] Record a demo: scan `demo_vulnerable_api`, walk through each finding

## License

MIT
