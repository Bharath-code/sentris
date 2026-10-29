# Benchmark (2026-10-29, Sentris 85932de)

Workload: https://github.com/django/django 5.1.4, 6827 files, 42.0 MB (working tree, no .git). Hardware: Apple M1, 8 cores, 8 GB, macOS-27.0.1-arm64-arm-64bit-Mach-O.
Corpus: 568 positives / 299 negatives. Authored by the Sentris project; recall favours Sentris' own rule list. Treat as a regression gauge, not a neutral ranking.

| Tool | Version | Median ms | Min ms | Peak RSS MB | Corpus recall | Corpus FP rate | Command |
|---|---|---:|---:|---:|---:|---:|---|
| Sentris | 0.1.0 | 188 | 166 | 24.6 | 100.0% | 0.0% | `sentris scan <dir> -f json` |
| Kingfisher | 2.15.0 | 1031 | 970 | 130.0 | 54.2% | 2.3% | `kingfisher scan <dir> --no-validate --format json` |
| Gitleaks | 8.30.1 | 2032 | 1612 | 107.5 | 71.1% | 9.7% | `gitleaks dir <dir> --no-banner -l error -r <report>` |
| TruffleHog | 3.99.7 | 2084 | 1784 | 230.6 | 27.1% | 2.7% | `trufflehog filesystem <dir> --no-update --no-verification --json` |
