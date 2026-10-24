# Architecture — injdetect

## Overview

`injdetect` (llm-security) is a single-package Python CLI: a `src/injdetect/` package
with a pure logic module and a Click command layer, console-script entry point
`injdetect = injdetect.cli:main`, and no runtime services.

### `src/injdetect/patterns.py`

Rule table: compiled regex + severity + taxonomy per technique family (instruction override, fake role boundary, persona jailbreak, forced affirmation, prompt extraction, delimiter escape, encoded payload, obfuscation markers, guardrail evasion). scan() adds +/-30 char context; score() caps a weighted sum at 100.

### `src/injdetect/cli.py`

Click group: `rules` (catalog, --json-out) and `scan` (files or '-', severity floor filter, exit 0/1/2), --json-out emits full reports.


## Design decisions

- **Logic/rendering separation.** Every decision (parse, match, lint, plan, score)
  lives in a pure module with no console output, so tests assert on data rather than
  on terminal formatting.
- **Exit codes as the CI contract.** 0 = clean/success, 1 = findings or failed
  validation, 2 = usage or read error. `--json-out` switches stdout to machine-readable
  JSON without changing exit codes.
- **Small dependency surface.** Only `click` (CLI) and `rich` (tables); everything
  else is the Python standard library. Fewer dependencies, fewer surprises.

## Data flow

```
input (token / file / URL + flags)
   -> Click command validates arguments
   -> pure module computes findings/verdicts/summary
   -> renderer prints table or JSON
   -> process exits 0 / 1 / 2
```

## Testing strategy

tests/test_i.py proves every rule fires, benign developer prose stays clean, score caps at 100, and CLI exit codes 0/1/2 behave.
