# CredData benchmark

54672 labeled rows (15241 true, 39431 false). Line-level; precision uses labeled false rows only.

| Tool | Precision | Recall | F1 | TP | Labeled FP | Hits on unlabeled lines | Time s | Peak MB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Sentris | 0.965 | 0.492 | 0.652 | 7497 | 274 | 203 | 0.9 | 91.3 |
| Gitleaks | 0.857 | 0.455 | 0.594 | 6934 | 1155 | 264 | 11.0 | 216.1 |
| Kingfisher | 0.952 | 0.070 | 0.131 | 1073 | 54 | 26 | 2.5 | 211.9 |
| TruffleHog | 0.676 | 0.024 | 0.046 | 365 | 175 | 260 | 73.0 | 340.1 |
