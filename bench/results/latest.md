# Benchmark (2026-10-29, Sentris 2292df8)

Workload: https://github.com/django/django 5.1.4, 6827 files, 42.0 MB (working tree, no .git). Hardware: Apple M1, 8 cores, 8 GB, macOS-27.0.1-arm64-arm-64bit-Mach-O.
Corpus: 408 positives / 262 negatives. Authored by the Sentris project; recall favours Sentris' own rule list. Treat as a regression gauge, not a neutral ranking.

| Tool | Version | Median ms | Min ms | Peak RSS MB | Corpus recall | Corpus FP rate | Command |
|---|---|---:|---:|---:|---:|---:|---|
| Sentris | 0.1.0 | 324 | 306 | 39.0 | 100.0% | 0.0% | `sentris scan <dir> -f json` |
| Gitleaks | 8.30.1 | 12013 | 11671 | 80.6 | 64.7% | 12.6% | `gitleaks dir <dir> --no-banner -l error -r <report>` |

Not run: TruffleHog, Kingfisher (not installed when this was generated).
