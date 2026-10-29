# Bad Code

An AI red-team toolkit focused on **indirect prompt injection** against tool-using agents, with a self-contained local arena where attacks and defenses co-evolve. Every attack that breaks a target ships with the defense that would have stopped it.

> **Authorized targets only.** Bad Code runs against a local arena you control (`arene_locale.py`), and against models/endpoints you own or are explicitly authorized to test. Do not point it at systems you don't own. It exists to *harden* agents, not to attack third parties.

## What it is

The core idea: an agent that reads untrusted content (a document, an e-mail, a web page) can be steered by instructions hidden in that content into misusing its tools, leaking data through an allowed channel, or acting against its principal. Bad Code reproduces those failures on a local, offline target and measures them, so the matching defense can be written and checked.

- **Local arena** (`arene_locale.py`, `attaquant.py`): a hardened target (an agent that handles an inbox with an allowed egress channel) and an attack harness. Payloads are parameterised by *framing × channel × encoding*; each verified break records the DLP or guard extension that blocks it. Fully offline.
- **Engine** (garak-style): probes and attack generators (`badcode_injection_doc.py`, `badcode_exploit_indirect.py`, `badcode_crescendo.py`, `badcode_tap.py`, `badcode_transformations.py`), detectors and an LLM judge (`badcode_detecteur.py`, `badcode_juge.py`, `badcode_oracle.py`), a taxonomy, a seed corpus, campaigns, replay, scoring and reports.
- **Defense notes**: `DEFENSE-REALISTE.md`, `FICHE-CONSTAT-confused-deputy.md`, `FICHE-AUDIT-HTTP.md`, `BAD-CODE-CE-QUI-MARCHE.md` — what breaks, why, and the realistic countermeasure.

## Run

Pure Python (3.12+), **no third-party dependencies**.

```sh
python3 -m unittest discover -p "test_*.py"   # 107 tests, offline
python3 arene_locale.py                        # the local attack/defense arena
```

Attacks against a real model need an OpenAI-compatible endpoint you own (set via the connector's env var); the arena, the detectors and the scoring run fully offline.

## Scope and ethics

Bad Code is dual-use security research. It is meant for a local arena you control and for models or endpoints you own or are authorized to assess. The example personas and companies in the scenarios are fictional. Use it to find and close injection paths in your own agents.

## License

Source-available under the **PolyForm Noncommercial License 1.0.0** ([`LICENSE`](LICENSE)). Read, run and modify it for any noncommercial purpose; commercial use requires written permission from the author.
