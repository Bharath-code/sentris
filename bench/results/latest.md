# Benchmark (2026-10-29, Sentris 7b466b6)

Workload: https://github.com/django/django 5.1.4, 6827 files, 42.0 MB (working tree, no .git). Hardware: Apple M1, 8 cores, 8 GB, macOS-27.0.1-arm64-arm-64bit-Mach-O.
Corpus: 484 positives / 306 negatives. Authored by the Sentris project; recall favours Sentris' own rule list. Treat as a regression gauge, not a neutral ranking.

| Tool | Version | Median ms | Min ms | Peak RSS MB | Corpus recall | Corpus FP rate | Command |
|---|---|---:|---:|---:|---:|---:|---|
| Sentris | 0.1.0 | 174 | 158 | 23.5 | 100.0% | 0.0% | `sentris scan <dir> -f json` |
| Kingfisher | 2.15.0 | 1010 | 994 | 129.8 | 49.6% | 2.3% | `kingfisher scan <dir> --no-validate --format json` |
| Gitleaks | 8.30.1 | 1546 | 1517 | 110.4 | 66.1% | 11.8% | `gitleaks dir <dir> --no-banner -l error -r <report>` |
| TruffleHog | 3.99.7 | 1573 | 1568 | 250.7 | 31.0% | 2.6% | `trufflehog filesystem <dir> --no-update --no-verification --json` |
