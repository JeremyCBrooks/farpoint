# AGENTS.md

This file provides guidance to AI coding agents working with code in this repository.

farpoint maps an organisation's external attack surface, starting from its root domains. README.md covers
usage, options and output files. ARCHITECTURE.md covers the methodology of each stage, a system diagram, and
how to extend farpoint. Read the relevant ARCHITECTURE.md section before you change a stage.

## Commands

farpoint needs Python 3.11+ and is managed with uv. No linter or formatter is configured.

```bash
uv sync                                          # install (add --group corpus for farpoint.corpus)
uv run pytest                                    # offline suite; network tests are deselected by default
uv run pytest tests/test_assess.py::test_name    # a single test
uv run pytest -m network                         # smoke tests against real DNS, example.com and NVD
uv run farpoint example.com                      # passive scan into ./out
uv run python -m farpoint.guess out              # offline evaluation of the guesser on an inventory
```

If `uv run pytest` fails with "uv trampoline failed to canonicalize script path" (seen in Git Bash on
Windows), use `uv run python -m pytest` instead.

## Engineering rules

- **TDD.** Write a failing test first, check that it fails for the right reason, then make it pass.
- **Every test must add value.** A test checks behaviour that a user or a later stage depends on, and it
  goes through the public entry point (`assess.derive`, `Pipeline.run`, a source's `collect`, and so on).
  Don't write tautologies (asserting that a fake returns what it was told to return), tests that restate
  the implementation, or tests that exist only for coverage. A test must be able to fail when the
  behaviour breaks.
- **SOLID and DRY.** Reuse the existing seams and helpers instead of adding parallel ones. Stages depend on
  the protocols below, not on concrete network classes. Keep shared logic in one place: hostname and IP
  handling lives in `names.py`, and registered-domain boundaries live in `suffixes.py`.

## Architecture invariants

- **`Inventory.add` (`models.py`) is the only way a hostname enters the inventory.** It normalises names,
  routes lookalikes to their own table, drops out-of-scope names and removes duplicates. Sources only
  yield `Observation`s. Never bypass `add`.
- **`Pipeline.run` (`pipeline.py`) runs the stages in a fixed order.** Each stage expresses its work as jobs
  keyed by `(name, target)` and hands them to `_fan_out`. Workers only do I/O. All inventory changes
  happen on the main thread, between results.
- **All network access sits behind small protocols:** `sources.base.Source`, `lookup` and `posture.Dns`,
  `enrich.Enricher`, `related.Probes` and `probe.Prober`. `cli.py` is the only place where the real
  implementations are wired in. Only `probe.py` contacts the organisation's own hosts, and only for
  in-scope names that currently resolve to public addresses. Keep it that way: any new active behaviour
  needs its own opt-in flag and a "not passive" note in README.md.
- **`assess.derive` is a pure function of the merged report.** When a check's result is unknown, it must
  never produce a finding that a control is missing.
- **`assets.json` is the source of truth.** `output.py` regenerates every other output file from it after
  the merge, and all writes are atomic.
- **Scan code waits with `runtime.sleep`, not `time.sleep`,** and reports with `runtime.status()` and
  `runtime.count_request()`. That keeps cancellation and the progress display working. The standalone
  `corpus.py` tool is the only exception.

## Testing conventions

- No offline test touches the network. Use the existing fakes:
  - `conftest.fake_http(routes)` is an `httpx.MockTransport` routed by `host/path`. Unknown URLs get a 404.
  - `conftest.when_params` serves a response only when the request has the expected query parameters.
  - The stage test files have `Fake*` classes for the DNS, prober and related-domain protocols.
- The autouse `sleeps` fixture records sleeps instead of sleeping and advances a fake clock. To test
  backoff and rate limits, assert on the recorded sleeps.
- Mark any test that needs the real internet with `@pytest.mark.network`.

## Extending

Recognising a new technology, tenant platform, takeover signature or end-of-life date is a data change in
`src/farpoint/data/*.json`, not a code change. For new sources and findings, see "Extending farpoint" in
ARCHITECTURE.md. When behaviour, options or outputs change, update README.md and ARCHITECTURE.md to match.
