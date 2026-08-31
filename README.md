<p align="center">
  <img src="https://raw.githubusercontent.com/yourpwnguy/depwatch/main/assets/doki.png" width="100">
</p>

<h1 align="center">depwatch</h1>

<p align="center">Dependency confusion monitor for internal package registries</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/yourpwnguy/depwatch"><img src="https://pkg.go.dev/badge/github.com/yourpwnguy/depwatch.svg" alt="Go Reference"></a>
  <a href="https://github.com/yourpwnguy/depwatch/releases"><img src="https://img.shields.io/github/v/release/yourpwnguy/depwatch" alt="Release"></a>
  <a href="https://github.com/yourpwnguy/depwatch/actions"><img src="https://img.shields.io/github/actions/workflow/status/yourpwnguy/depwatch/ci.yml?branch=main" alt="CI"></a>
</p>

---

depwatch scans your internal package inventory against public registries (npm, PyPI, crates.io) and detects dependency confusion. It tells you not just "this name exists publicly" but whether it looks like a real threat or just a coincidence.

## Scan Output

```
  /\_/\   depwatch  dependency confusion monitor
 ( o.o )  v0.1.0   scanning internal packages against public registries
  > ^ <

  org         acme-corp
  registries  crates · npm · pypi
  inventory   7 internal packages
  workers     8 concurrent lookups
  store       depwatch.db

    PACKAGE                            REGISTRY   RISK      THREAT      SIGNALS
✓   threading                          pypi       INFO      —           clean
•   crypto                             pypi       INFO      benign      5 signals
      │ evidence  HIGH exact name collision
      │           LOW  generic name
      │           LOW  long established  ·  4308d old
      │           LOW  named publisher  ·  Christopher Simpkins
      └           LOW  source published

✓   @acme/auth-core                    npm        INFO      —           clean
•   requests                           pypi       INFO      benign      4 signals
      │ evidence  HIGH exact name collision
      │           LOW  long established  ·  5676d old
      │           MED  unverified publisher
      └           LOW  source published

✓   @acme/scheduler                    npm        INFO      —           clean
✓   @acme/data-pipeline                npm        INFO      —           clean
✓   acme_crypto                        crates     INFO      —           clean

7 packages · 2 collisions · 0 critical
```

With `--full`, each collision shows the public package details:

```
•   crypto                             pypi       INFO      benign      5 signals
      │ public    1.4.1  ·  4308d old  ·  Christopher Simpkins
      │ source    github.com/chrissimpkins/crypto
      │ evidence  HIGH exact name collision
      │           LOW  generic name
      │           LOW  long established  ·  4308d old
      │           LOW  named publisher  ·  Christopher Simpkins
      │           LOW  source published
      └ history   first seen 2026-08-31 07:02  ·  known
```

## Features

- Two-scale risk assessment: RiskLevel (INFO to CRITICAL) for alerting, ThreatLevel (BENIGN/SUSPICIOUS/DANGEROUS) for analysis
- Explainable signals: every finding shows what triggered it
- Deterministic verdicts: named integer weights, no floats, no tuning; any verdict is re-derivable by hand
- Registry-aware pairing: npm names checked against npm, PyPI against PyPI
- Live animated scan with doki mascot, no alternate screen
- History tracking across runs with NEW/KNOWN/CHANGED status
- CI gating: `depwatch ci` exits non-zero on policy breach
- Slack alerts via environment variable (secrets never on disk)
- Multiple output formats: human, JSON, live

## Installation

```bash
go install github.com/yourpwnguy/depwatch/cmd/depwatch@v0.1.0
```

Or download from [Releases](https://github.com/yourpwnguy/depwatch/releases).

## Quick Start

1. Create `depwatch.yaml` in your project root:

```yaml
# depwatch configuration
#
# Secrets are intentionally absent: the Slack webhook URL is supplied via the
# environment variable named below (DEPWATCH_SLACK_WEBHOOK), never written here.

organization: acme-corp

# Internal packages grouped by ecosystem. Only ecosystems whose registry is enabled
# below are scanned -- a package listed under a disabled ecosystem is ignored.
ecosystems:
  npm:
    - "@acme/scheduler"
    - "@acme/auth-core"
    - "@acme/data-pipeline"
  pypi:
    - requests
    - crypto
    - threading
  crates:
    - acme_crypto

database:
  path: depwatch.db

scan:
  workers: 8 # concurrent (package x registry) lookups
  timeout: 10s # per-request timeout
  retries: 3 # retries on transient HTTP errors / 429

# Enable the public registries to check your internal names against.
registries:
  npm:
    enabled: true
  pypi:
    enabled: true
  crates:
    enabled: true

alerts:
  slack:
    enabled: false
    webhook_env: DEPWATCH_SLACK_WEBHOOK

thresholds:
  alert: high # notify when a collision reaches at least this risk
  block_ci: critical # CI fails when a collision reaches at least this risk
```

2. Run a scan:

```bash
depwatch scan
```

## Usage

```
depwatch scan          Scan all internal packages against public registries
depwatch package NAME  Investigate a single package across all registries
depwatch history NAME  Show stored scan history for a package
depwatch alerts        List unresolved alerts
depwatch inventory     Show the configured internal package inventory
depwatch export FILE   Export a full scan as JSON to a file
depwatch ci            Run a scan for CI and exit non-zero on policy breach
depwatch monitor       Continuously monitor packages on an interval
```

### Flags

| Command | Flag | Description |
|---------|------|-------------|
| `scan` | `-f, --full` | Show full evidence block for every lookup |
| `scan` | `--ecosystem` | Restrict scan to one ecosystem (npm, pypi, crates) |
| `scan` | `--format` | Output format: `human` or `json` |
| `monitor` | `--interval` | Scan interval (minimum 30s, default 1h) |
| `ci` | -- | Exits non-zero when any entry meets `block_ci` threshold |
| all | `-c, --config` | Config file path |

### CI Integration

```yaml
- name: Dependency confusion check
  run: depwatch ci
```

`depwatch ci` runs a full scan and exits with code 2 when any collision meets the `block_ci` threshold.

## How It Works

### Detection

depwatch compares your internal package names against public registry metadata. Two collision types:

- **Exact** -- byte-identical names (case-sensitive)
- **Namespace** -- same scope prefix, different leaf (e.g. `@acme/auth` vs `@acme/utils`)

### Risk Assessment

Every collision produces a set of signals. Aggravating signals argue "this looks like a squat": newly registered, no source repo, org-specific name. Mitigating signals argue "this looks legitimate": long-established, widely used, named publisher. The aggregate score maps to a ThreatLevel and a RiskLevel.

### Architecture

```
cmd/depwatch -> internal/cli -> internal/app -> internal/domain
                                             -> internal/registry
                                             -> internal/storage
                                             -> internal/alerting
```

- **domain** -- pure types and security logic, no I/O
- **registry** -- HTTP adapters for npm, PyPI, crates.io with per-registry rate limiting
- **storage** -- append-only SQLite persistence
- **alerting** -- Slack webhook delivery
- **app** -- bounded worker pool orchestration
- **cli** -- cobra command tree and output rendering

## Configuration

See `depwatch.yaml` above for a complete annotated example. Key sections:

| Section | Purpose |
|---------|---------|
| `organization` | Company name for org-specific name detection |
| `ecosystems` | Internal packages grouped by ecosystem |
| `registries` | Which public registries to enable |
| `scan.workers` | Concurrent lookups (default: 8) |
| `scan.timeout` | Per-request HTTP timeout (default: 10s) |
| `thresholds.alert` | Minimum risk for notifications (default: HIGH) |
| `thresholds.block_ci` | Minimum risk for CI failure (default: CRITICAL) |
| `alerts.slack.webhook_env` | Env var holding the Slack webhook URL |

The Slack webhook URL is read from an environment variable, never stored on disk.

## Development

```bash
make build     # compile with version info
make test      # run all tests
make test-race # run tests with race detector
make lint      # run golangci-lint
make check     # full CI gate (fmt + vet + lint + test-race + build)
make bench     # run benchmarks
make clean     # remove build artifacts
```

## License

MIT
