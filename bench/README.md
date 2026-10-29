# Benchmarks

Everything here regenerates its own numbers; nothing is hand-typed.

| What | Command | Output |
|---|---|---|
| Speed, memory, corpus P/R on a pinned django checkout, 4 tools | `bench/fetch-tools.sh && bench/run.sh` | `results/latest.{json,md}`, `web/src/lib/benchmark.json` |
| Recall on gitleaks' own rule fixtures | `python3 bench/gitleaks_fixtures.py` (needs `bench/work/gitleaks-src`, a v8.30.1 checkout) | `results/gitleaks-fixtures.json` |
| Independent labeled dataset (Samsung CredData, ~54k labeled lines) | see below | `results/creddata.{json,md}` |
| Second independent dataset: ProwlBench (24,603 snippets; data file only, pinned `53d6fc1e`) | `curl -o bench/work/prowlbench/prowlbench.jsonl https://raw.githubusercontent.com/Lercas/prowlbench/53d6fc1e/prowlbench.jsonl && python3 bench/prowlbench_eval.py` | `results/prowlbench.{json,md}` |
| False-positive gate (CI) | `bench/fp-sweep.sh` | exit code |

## CredData
```
git clone --depth 1 https://github.com/Samsung/CredData bench/work/creddata
python3 -m venv bench/work/creddata/.venv && bench/work/creddata/.venv/bin/pip install pybase62==1.0.0
cd bench/work/creddata && GIT_LFS_SKIP_SMUDGE=1 .venv/bin/python ../../creddata_prepare.py   # ~5 min, 241 MB
cd ../../.. && python3 bench/creddata_eval.py
```
`creddata_prepare.py` runs CredData's own download/obfuscate code but skips repos whose pinned commit is gone
(4 of 337 at the time of writing; listed in `dropped_repos.json`). Scoring is line-level on labeled rows only;
findings on unlabeled lines are reported separately. Gitleaks' fixture generator emits secrets from tiny extended
alphabets (about a third of characters are `_`, `-`, `=`), which the label-like-value filter rejects; real tokens
rarely look like that, so treat the fixture number as a lower bound.

## Independence and tuning policy
- Nothing is tuned on a dataset's held-out part or on a dataset used only for confirmation (ProwlBench was never inspected before its first scored run).
- Before any external "best" claim: re-run `creddata_eval.py` (held-out), `prowlbench_eval.py`, and add a third source. SecretBench (NC State) needs an emailed request and a data-protection agreement; not yet obtained.
