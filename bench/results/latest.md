# Benchmark (2026-10-29, Sentris 56f1427)

Workload: https://github.com/django/django 5.1.4, 6827 files, 42.0 MB (working tree, no .git). Hardware: Apple M1, 8 cores, 8 GB, macOS-27.0.1-arm64-arm-64bit-Mach-O.
Corpus: 460 positives / 286 negatives. Authored by the Sentris project; recall favours Sentris' own rule list. Treat as a regression gauge, not a neutral ranking.

| Tool | Version | Median ms | Min ms | Peak RSS MB | Corpus recall | Corpus FP rate | Command |
|---|---|---:|---:|---:|---:|---:|---|
| Sentris | 0.1.0 | 152 | 149 | 19.8 | 100.0% | 0.0% | `sentris scan <dir> -f json` |
| Kingfisher | 2.15.0 | 1042 | 1017 | 128.0 | 52.2% | 2.1% | `kingfisher scan <dir> --no-validate --format json` |
| TruffleHog | 3.99.7 | 1471 | 1461 | 241.8 | 32.6% | 2.8% | `trufflehog filesystem <dir> --no-update --no-verification --json` |
| Gitleaks | 8.30.1 | 1480 | 1460 | 107.3 | 67.0% | 11.5% | `gitleaks dir <dir> --no-banner -l error -r <report>` |
