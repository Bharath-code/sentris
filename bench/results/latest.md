# Benchmark (2026-10-29, Sentris bc850e0)

Workload: https://github.com/django/django 5.1.4, 6827 files, 42.0 MB (working tree, no .git). Hardware: Apple M1, 8 cores, 8 GB, macOS-27.0.1-arm64-arm-64bit-Mach-O.
Corpus: 492 positives / 299 negatives. Authored by the Sentris project; recall favours Sentris' own rule list. Treat as a regression gauge, not a neutral ranking.

| Tool | Version | Median ms | Min ms | Peak RSS MB | Corpus recall | Corpus FP rate | Command |
|---|---|---:|---:|---:|---:|---:|---|
| Sentris | 0.1.0 | 164 | 156 | 23.2 | 100.0% | 0.0% | `sentris scan <dir> -f json` |
| Kingfisher | 2.15.0 | 1321 | 1116 | 125.8 | 48.8% | 2.3% | `kingfisher scan <dir> --no-validate --format json` |
| Gitleaks | 8.30.1 | 1540 | 1469 | 107.8 | 66.7% | 9.7% | `gitleaks dir <dir> --no-banner -l error -r <report>` |
| TruffleHog | 3.99.7 | 1591 | 1496 | 251.2 | 30.5% | 2.7% | `trufflehog filesystem <dir> --no-update --no-verification --json` |
