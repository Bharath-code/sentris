# CredData benchmark

54672 labeled rows. Line-level; precision uses labeled false rows only. `heldout` = odd repo ids, not used for tuning after the split was introduced.

## all

| Tool | Precision | Recall | F1 | Macro F1 (per repo) | TP | Labeled FP | Hits on unlabeled lines |
|---|---:|---:|---:|---:|---:|---:|---:|
| Sentris | 0.954 | 0.622 | 0.753 | 0.584 | 9486 | 455 | 265 |
| Betterleaks | 0.812 | 0.565 | 0.667 | 0.574 | 8616 | 1991 | 1529 |
| Gitleaks | 0.857 | 0.455 | 0.594 | 0.333 | 6934 | 1155 | 264 |
| Kingfisher | 0.952 | 0.070 | 0.131 | 0.111 | 1073 | 54 | 26 |
| TruffleHog | 0.676 | 0.024 | 0.046 | 0.055 | 365 | 175 | 260 |

## dev

| Tool | Precision | Recall | F1 | Macro F1 (per repo) | TP | Labeled FP | Hits on unlabeled lines |
|---|---:|---:|---:|---:|---:|---:|---:|
| Sentris | 0.960 | 0.730 | 0.829 | 0.614 | 7761 | 322 | 118 |
| Betterleaks | 0.848 | 0.653 | 0.738 | 0.593 | 6947 | 1243 | 1041 |
| Gitleaks | 0.851 | 0.554 | 0.671 | 0.336 | 5898 | 1036 | 188 |
| Kingfisher | 0.962 | 0.071 | 0.132 | 0.114 | 753 | 30 | 18 |
| TruffleHog | 0.671 | 0.018 | 0.035 | 0.045 | 190 | 93 | 123 |

## heldout

| Tool | Precision | Recall | F1 | Macro F1 (per repo) | TP | Labeled FP | Hits on unlabeled lines |
|---|---:|---:|---:|---:|---:|---:|---:|
| Sentris | 0.928 | 0.375 | 0.534 | 0.555 | 1725 | 133 | 147 |
| Betterleaks | 0.691 | 0.363 | 0.475 | 0.555 | 1669 | 748 | 488 |
| Gitleaks | 0.897 | 0.225 | 0.360 | 0.331 | 1036 | 119 | 76 |
| Kingfisher | 0.930 | 0.070 | 0.129 | 0.109 | 320 | 24 | 8 |
| TruffleHog | 0.681 | 0.038 | 0.072 | 0.066 | 175 | 82 | 137 |

