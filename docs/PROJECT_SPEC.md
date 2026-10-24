# PROJECT SPEC — injdetect

| Field | Value |
|---|---|
| Name | `injdetect` |
| Category | llm-security |
| Target user | Teams building on LLMs who need an auditable first-pass input filter |
| Problem | Injection-shaped input and embedded instructions in documents reach models unfiltered, and ad-hoc regexes lack taxonomy coverage. |
| Solution | Nine structural detection rules mapped to OWASP LLM01/LLM07 and MITRE ATLAS AML.T0051/T0054, with context, scoring, and CI exit codes. |
| Core workflow | list rules -> scan files or stdin -> gate on --min-severity in CI |
| Stack | Python >=3.10, click, rich |
| Test strategy | tests/test_i.py proves every rule fires, benign developer prose stays clean, score caps at 100, and CLI exit codes 0/1/2 behave. |
| Demo strategy | `logs/2026-10-24/run_demos.py` runs the real workflow and captures `results/demo-output.txt` with asserted exit codes |
| Safety | Defensive only. Sample strings are defanged structural skeletons, never weaponized payloads. Fully offline. SECURITY.md documents authorized, responsible use. |
| Definition of done | install + pytest + CLI smoke + demo transcript + secret scan all pass; docs (README, ARCHITECTURE, USAGE, CHANGELOG, CONTRIBUTING, SECURITY) present; pushed with green CI |

## Must-have features

- injdetect rules
- injdetect scan suspect.txt
- Exit-code contract (0/1/2) usable from CI
- `--json-out` machine-readable output

## Nice-to-have (deferred)

- See README Roadmap.
