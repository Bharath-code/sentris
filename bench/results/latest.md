# Benchmark (2026-10-29, Sentris 6180294)

Workload: https://github.com/django/django 5.1.4, 6827 files, 42.0 MB (working tree, no .git). Hardware: Apple M1, 8 cores, 8 GB, macOS-27.0.1-arm64-arm-64bit-Mach-O.
Corpus: 460 positives / 286 negatives. Authored by the Sentris project; recall favours Sentris' own rule list. Treat as a regression gauge, not a neutral ranking.

| Tool | Version | Median ms | Min ms | Peak RSS MB | Corpus recall | Corpus FP rate | Command |
|---|---|---:|---:|---:|---:|---:|---|
| Sentris | 0.1.0 | 215 | 208 | 143.9 | 100.0% | 0.0% | `sentris scan <dir> -f json` |
| Kingfisher | 2.15.0 | 1031 | 998 | 129.7 | 52.2% | 2.1% | `kingfisher scan <dir> --no-validate --format json` |
| Gitleaks | 8.30.1 | 1582 | 1557 | 109.9 | 67.0% | 11.5% | `gitleaks dir <dir> --no-banner -l error -r <report>` |
| TruffleHog | 3.99.7 | 1587 | 1570 | 241.5 | 32.6% | 2.8% | `trufflehog filesystem <dir> --no-update --no-verification --json` |
