# depwatch — HANDOFF

Go CLI that detects **dependency confusion**: scans an org's internal package
inventory against public registries (npm, PyPI, crates.io), distinguishes a harmless
name collision from an actual squat, persists history, and alerts.

Module `github.com/yourpwnguy/depwatch`, Go 1.24. Source of truth: `docs/idea.md`.

## Architecture (do not restructure)

```
cmd/depwatch → internal/cli → internal/app → internal/domain
                                           → internal/registry | storage | alerting
```

- `domain` imports **no** internal package; it is pure and deterministic (no clock, no
  I/O, no globals). All security logic lives there.
- `Registry` is an interface (npm/pypi/crates); `Store` and `AlertSender` are concrete.
- `app` owns concurrency: bounded worker pool, one job per (package × registry), pairs
  a package only with its own ecosystem's registry unless `ScanOptions.AllRegistries`.
- Secrets never on disk: Slack webhook read from env var (`alerts.slack.webhook_env`).

## Package layout

```
internal/
  domain/        Pure types + security logic (no deps)
    model.go       Types: PackageInfo, ScanEntry, Signal, RiskLevel, ThreatLevel
    analyze.go     Analyze() → Assessment (two-scale signal analysis)
    detect.go      DetectCollision() (exact + namespace)
    threat.go      ThreatLevel, weights, classify, riskFromThreat
    progress.go    ProgressEvent, ScanPhase (app→cli event contract)
  registry/      HTTP adapters for public registries
    registry.go    Registry interface, getJSON, clean(), backoff
    npm.go         npm packument + downloads adapter
    pypi.go        PyPI JSON adapter with deterministic sourceURL
    crates.go      crates.io adapter (custom User-Agent)
    limiter.go     Token-bucket rate limiter (per-registry)
  storage/       SQLite persistence (append-only)
    sqlite.go      Store, Open, schema, scanEntry, collectEntries
    events.go      RecordEvent, Latest, History
    alerts.go      AddAlert, UnresolvedAlerts
  config/        YAML configuration loading + validation
    config.go      Config types, Load, InternalPackages, EnabledRegistryNames
    defaults.go    applyDefaults
    validate.go    Validate
  alerting/      External notification sinks
    slack.go       Slack webhook delivery
  app/           Orchestration layer
    app.go         App, Scan, Package, History, Alerts, CI
    worker.go      scanPipeline, worker, scanOne
  cli/           Cobra command tree + output rendering
    root.go        Root command, buildApp, buildAppForConfig
    scan.go        Scan command (human/json/live modes)
    monitor.go     Monitor command (interval loop)
    package.go     Package investigation command
    ci.go          CI gating command
    history.go     History display
    alerts.go      Alert listing
    inventory.go   Inventory display
    export.go      JSON export
    output/
      report.go    Shared rendering primitives (columns, evidence, summary)
      human.go     Static report (WriteReport, WriteHistory, WriteAlerts, WriteInventory)
      live.go      Animated scan view (LiveScan)
      json.go      Machine-readable JSON (WriteJSON, WriteAlertsJSON)
```

## Two-scale assessment (core feature)

`RiskLevel` (INFO→CRITICAL) answers "how severe is a collision of this shape" and
drives the existing alert + CI thresholds. `ThreatLevel` (BENIGN / SUSPICIOUS /
DANGEROUS) answers "is this plausibly an attacker's squat".

`domain.Analyze(collision, prev, now, org) Assessment{Signals, Risk, Threat, Score}`

- Scoring uses small **named integer weights** in `domain/threat.go` so any verdict is
  re-derivable by hand from the printed signals. No floats, no tuning.
- Signals are **two-sided** and both kinds are output: aggravating
  (`NEWLY_REGISTERED`, `RECENTLY_REGISTERED`, `YOUNG_PACKAGE`, `NO_SOURCE_REPOSITORY`,
  `UNVERIFIED_PUBLISHER`, `NO_DOWNLOADS`, `LOW_REPUTATION`, `ORG_SPECIFIC_NAME`,
  `PUBLISHED_AFTER_MONITORING`, `RISK_ESCALATED`) and mitigating (`LONG_ESTABLISHED`,
  `ESTABLISHED_PACKAGE`, `WIDELY_USED`, `ESTABLISHED_USAGE`, `SOURCE_PUBLISHED`,
  `NAMED_PUBLISHER`, `GENERIC_NAME`). Mitigators are what make "legitimate" explainable.
- Generic dictionary names (`crypto`, `utils`, …) lower confidence; org-shaped names
  (`@acme/x`, `acme-billing`) escalate.
- `Threat` is **derived every scan**, so SQLite needs no new column. Do not add one.
- `NEW`/`KNOWN`/`CHANGED` history logic stays in `app/worker.go` — unchanged.

Deliberate call: a decade-old package with repo + publisher stays BENIGN even under an
org-specific name (it predates the internal package). Change only if asked.

## Output (single shared renderer)

`internal/cli/output/report.go` holds all primitives; `human.go` (static) and
`live.go` (animated) both use them, so views cannot drift.

Table: `PACKAGE(34) REGISTRY(10) RISK(9) THREAT(11) SIGNALS`, then an indented
evidence tree. `-f/--full` adds `public` / `source` / `history` branches.

```
⚠   crypto                             pypi       INFO      benign      5 signals
      │ public    1.4.1  ·  4307d old  ·  Christopher Simpkins
      │ source    github.com/chrissimpkins/crypto
      │ evidence  HIGH exact name collision
      │           LOW  generic name
      └ history   first seen 2026-08-30 09:25  ·  known
```

- **Padding rule (critical):** `fmt`'s `%-Ns` counts runes, so a lipgloss-styled string
  never pads. Always pad the **plain** text *then* style it (`registryCell`, `gutter`,
  the RISK cell). Violating this visibly breaks column alignment.
- Registry brand colors: npm `160`, pypi `74`, crates `208`. Colors only render on a
  TTY (lipgloss strips them when piped) — verify with `script`, not a pipe.
- `scan` on a TTY uses `LiveScan`: all rows listed up front, redrawn **in place** on
  normal stdout via `\033[<n>A` + `\033[J`. **No alternate screen** (explicitly
  rejected). Non-TTY / `--format json` fall back to `WriteReport` / `WriteJSON`.
- Live view has personality: animated doki mascot, gold braille spinner, pulse dot,
  `[done/total] · N in flight · N found · elapsed`, plain-language stages, closing verdict.

## Completed

All commands work: `scan` (`-f`, `--ecosystem`, `--format`), `monitor`, `package`
(`-f`), `history`, `alerts`, `inventory`, `export`, `ci`. `gofmt`/`go vet` clean;
5/5 test packages pass. `./depwatch` binary is current.

Bugs found and fixed (keep the regression tests):
1. Scoped npm names start with `@`, so splitting a `pkg@reg` key on the first `@` gave
   an empty PACKAGE column. `liveState` now stores `pkg`/`reg` explicitly; `splitKey`
   deleted. Guarded by `TestLiveScan_ScopedPackage`.
2. PyPI returns literal `"UNKNOWN"`/`"None"` for missing author/repo. Normalized at the
   registry boundary by `clean()` in `registry/registry.go`.
3. PyPI repository was chosen by **randomized map iteration**, making the threat verdict
   non-deterministic. `sourceURL()` now prefers `Source`/`Repository`/`Code` labels then
   sorted fallback.
4. Absent download counts must never read as "zero installs" (PyPI/crates omit the
   metric). Download rules apply only to positive counts, or a known-zero on npm.

## Changes since last session

Surgical improvements for production readiness:
- **Config split**: `config.go` (189 lines) → `config.go` (types + Load), `defaults.go`,
  `validate.go` — clearer separation of concerns
- **Storage split**: `sqlite.go` (206 lines) → `sqlite.go` (schema + shared scanEntry),
  `events.go` (RecordEvent/Latest/History), `alerts.go` (AddAlert/UnresolvedAlerts)
- **Monitor fix**: `buildAppForConfig()` eliminates the `&cobra.Command{}` hack
- **Documentation**: thorough docs on all packages, types, functions, algorithms, edge
  cases, security considerations, and architectural decisions
- **Makefile**: version stamping, lint, race, check target, self-documenting help
- **CI/CD**: GitHub Actions for lint + test + build + release
- **Linting**: `.golangci.yml` with v2 schema, misspell, bodyclose, unconvert
- **Release**: `.goreleaser.yaml` for cross-platform builds
- **README**: production-quality with badges, usage examples, architecture overview

## Constraints

KISS. Prefer extending over rewriting. Keep files small and documented (comments
explain *why*, not restating code). Do not add dashboards, auth, or infra. Keep
registry adapters, SQLite schema, CLI shape, concurrency, and output structure intact
unless genuinely required.

## Key files

- `internal/domain/threat.go` — ThreatLevel, weights, `IsGenericName`, `IsOrgSpecificName`, `classify`, `riskFromThreat`
- `internal/domain/analyze.go` — `Analyze` → `Assessment`
- `internal/domain/{model.go,detect.go,progress.go}` — types, `DetectCollision`, `ProgressEvent`
- `internal/domain/{threat_test.go,detect_test.go}` — 10 threat cases + detection
- `internal/cli/output/{report.go,human.go,live.go,json.go}` — shared primitives, static, live, JSON
- `internal/app/{app.go,worker.go}` — orchestration, pool, `scanOne`, event emission
- `internal/registry/{registry.go,npm.go,pypi.go,crates.go,limiter.go}`
- `internal/{storage/sqlite.go,storage/events.go,storage/alerts.go}`
- `internal/{config/config.go,config/defaults.go,config/validate.go}`
- `internal/alerting/slack.go`
- `ui_mock.py` — UI prototype reference

## Next steps

1. `monitor` deliberately has no `-f` (would flood cron logs); add only if requested.
2. Normal (non-`-f`) mode prints a blank line only after packages that have evidence,
   which makes spacing ragged. User chose to **keep this behavior** (conditional gap).
3. No tests exist for `internal/cli` or `internal/config`; `output` has live-render
   tests only. Consider a `WriteReport` golden test.
4. `PUBLISHED_AFTER_MONITORING` uses `prev.FirstSeen` as a proxy because inventory
   creation dates aren't stored. Persisting a real internal-first-seen date would
   sharpen it (needs a schema migration — get approval first).
5. Verify UI changes on a real TTY via
   `timeout 90 script -qec "./depwatch scan" /tmp/out.txt`; piping hides colors and
   the in-place redraw.
