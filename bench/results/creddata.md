# CredData benchmark

54672 labeled rows. Line-level; precision uses labeled false rows only. `heldout` = odd repo ids, not used for tuning after the split was introduced.

## all

| Tool | Precision | Recall | F1 | Macro F1 (per repo) | TP | Labeled FP | Hits on unlabeled lines |
|---|---:|---:|---:|---:|---:|---:|---:|
| Sentris | 0.966 | 0.548 | 0.699 | 0.436 | 8349 | 292 | 211 |
| Gitleaks | 0.857 | 0.455 | 0.594 | 0.333 | 6934 | 1155 | 264 |
| Kingfisher | 0.952 | 0.070 | 0.131 | 0.111 | 1073 | 54 | 26 |
| TruffleHog | 0.676 | 0.024 | 0.046 | 0.055 | 365 | 175 | 260 |

## dev

| Tool | Precision | Recall | F1 | Macro F1 (per repo) | TP | Labeled FP | Hits on unlabeled lines |
|---|---:|---:|---:|---:|---:|---:|---:|
| Sentris | 0.971 | 0.665 | 0.789 | 0.448 | 7071 | 209 | 91 |
| Gitleaks | 0.851 | 0.554 | 0.671 | 0.336 | 5898 | 1036 | 188 |
| Kingfisher | 0.962 | 0.071 | 0.132 | 0.114 | 753 | 30 | 18 |
| TruffleHog | 0.671 | 0.018 | 0.035 | 0.045 | 190 | 93 | 123 |

## heldout

| Tool | Precision | Recall | F1 | Macro F1 (per repo) | TP | Labeled FP | Hits on unlabeled lines |
|---|---:|---:|---:|---:|---:|---:|---:|
| Sentris | 0.939 | 0.278 | 0.428 | 0.424 | 1278 | 83 | 120 |
| Gitleaks | 0.897 | 0.225 | 0.360 | 0.331 | 1036 | 119 | 76 |
| Kingfisher | 0.930 | 0.070 | 0.129 | 0.109 | 320 | 24 | 8 |
| TruffleHog | 0.681 | 0.038 | 0.072 | 0.066 | 175 | 82 | 137 |

