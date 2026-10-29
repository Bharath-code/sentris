# Benchmark (2026-10-29, Sentris 9cadf20)

Workload: https://github.com/django/django 5.1.4, 6827 files, 42.0 MB (working tree, no .git). Hardware: Apple M1, 8 cores, 8 GB, macOS-27.0.1-arm64-arm-64bit-Mach-O.
Corpus: 432 positives / 278 negatives. Authored by the Sentris project; recall favours Sentris' own rule list. Treat as a regression gauge, not a neutral ranking.

| Tool | Version | Median ms | Min ms | Peak RSS MB | Corpus recall | Corpus FP rate | Command |
|---|---|---:|---:|---:|---:|---:|---|
| Sentris | 0.1.0 | 181 | 176 | 41.4 | 100.0% | 0.0% | `sentris scan <dir> -f json` |
| Kingfisher | 2.15.0 | 1051 | 1022 | 127.9 | 50.7% | 2.2% | `kingfisher scan <dir> --no-validate --format json` |
| Gitleaks | 8.30.1 | 1574 | 1533 | 108.0 | 66.7% | 11.9% | `gitleaks dir <dir> --no-banner -l error -r <report>` |
| TruffleHog | 3.99.7 | 1640 | 1624 | 261.0 | 32.9% | 1.8% | `trufflehog filesystem <dir> --no-update --no-verification --json` |
