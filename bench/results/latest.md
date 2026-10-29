# Benchmark (2026-10-30, Sentris b2de0e3)

Workload: https://github.com/django/django 5.1.4, 6827 files, 42.0 MB (working tree, no .git). Hardware: Apple M1, 8 cores, 8 GB, macOS-27.0.1-arm64-arm-64bit-Mach-O.
Corpus: 588 positives / 316 negatives. Authored by the Sentris project; recall favours Sentris' own rule list. Treat as a regression gauge, not a neutral ranking.

| Tool | Version | Median ms | Min ms | Peak RSS MB | Corpus recall | Corpus FP rate | Command |
|---|---|---:|---:|---:|---:|---:|---|
| Sentris | 0.1.0 | 445 | 392 | 24.8 | 100.0% | 0.0% | `sentris scan <dir> -f json` |
| Betterleaks | 1.9.0 | 1550 | 1528 | 126.3 | 78.1% | 14.2% | `betterleaks dir <dir> --no-banner -l error -r <report>` |
| Kingfisher | 2.15.0 | 1643 | 1592 | 130.7 | 53.1% | 2.2% | `kingfisher scan <dir> --no-validate --format json` |
| TruffleHog | 3.99.7 | 2828 | 2756 | 241.2 | 26.2% | 2.5% | `trufflehog filesystem <dir> --no-update --no-verification --json` |
| Gitleaks | 8.30.1 | 2861 | 2744 | 113.2 | 69.4% | 9.2% | `gitleaks dir <dir> --no-banner -l error -r <report>` |
