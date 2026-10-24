# Usage — injdetect

## Install

```shell
pip install -e .
```

## Commands

```shell
injdetect --help
```

## Examples

### List the rule catalog

```shell
injdetect rules
```

### Scan a file

```shell
injdetect scan suspect.txt
```

### Scan from stdin

```shell
cat message.txt | injdetect scan -
```

### CI gate on high severity only

```shell
injdetect scan corpus/ --min-severity high --json-out
```

## Severity and scoring

| severity | score weight | typical rule |
|---|---|---|
| high | 40 | instruction override, fake end-of-prompt marker |
| medium | 20 | persona jailbreak, forced affirmation, extraction, delimiter escape |
| low | 5 | encoded blob, zero-width characters |

`score` is the capped (100) sum. `--min-severity` filters which findings are
displayed and counted. Exit behavior: a file exits 1 only when its worst remaining
finding is **medium** or **high**; low-only files exit 0 (they are still displayed
unless filtered out), and a file with no findings at/above the floor reports
`clean` and exits 0.

## Validation gates

- **install**: `pip install -e . (fresh venv)`
- **unit tests**: `pytest -q`
- **CLI smoke**: `injdetect --help; injdetect rules`
- **demo run**: `logs/2026-10-24/run_demos.py -> results/demo-output.txt`
- **secret scan**: `no tokens/keys/.env in tree`

## Exit codes

- `0` — success / no findings at or above threshold
- `1` — findings present, or validation cases failed
- `2` — usage error, unreadable input, or rejected target
