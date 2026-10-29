# ProwlBench (independent-ish benchmark)

24603 labeled snippets. Case-level. Built by a competing scanner's author; `origin=real` is CredData-derived, hence the second block. Negatives exist only in tier T4, so per-tier/source precision outside `all` is not meaningful (use recall there).

## all

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.954 | 0.642 | 0.767 | 10620 | 517 | 5932 |
| Gitleaks | 0.931 | 0.411 | 0.571 | 6811 | 504 | 9741 |
| Kingfisher | 0.944 | 0.325 | 0.484 | 5382 | 322 | 11170 |
| TruffleHog | 0.940 | 0.302 | 0.457 | 4994 | 319 | 11558 |

## excluding_credata_derived

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.939 | 0.762 | 0.841 | 7828 | 510 | 2441 |
| Kingfisher | 0.942 | 0.508 | 0.660 | 5218 | 321 | 5051 |
| Gitleaks | 0.916 | 0.503 | 0.649 | 5164 | 473 | 5105 |
| TruffleHog | 0.939 | 0.478 | 0.633 | 4907 | 319 | 5362 |

## tier=T1_structured

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 1.000 | 0.844 | 0.915 | 5934 | 0 | 1099 |
| Gitleaks | 1.000 | 0.649 | 0.787 | 4561 | 0 | 2472 |
| Kingfisher | 1.000 | 0.604 | 0.753 | 4247 | 0 | 2786 |
| TruffleHog | 1.000 | 0.601 | 0.751 | 4225 | 0 | 2808 |

## tier=T2_generic_context

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 1.000 | 0.599 | 0.749 | 2108 | 0 | 1411 |
| Gitleaks | 1.000 | 0.354 | 0.523 | 1246 | 0 | 2273 |
| Kingfisher | 1.000 | 0.010 | 0.019 | 34 | 0 | 3485 |
| TruffleHog | 1.000 | 0.004 | 0.007 | 13 | 0 | 3506 |

## tier=T3_freeform_multilingual

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 1.000 | 0.430 | 0.601 | 2578 | 0 | 3422 |
| Kingfisher | 1.000 | 0.183 | 0.310 | 1101 | 0 | 4899 |
| Gitleaks | 1.000 | 0.167 | 0.287 | 1004 | 0 | 4996 |
| TruffleHog | 1.000 | 0.126 | 0.224 | 756 | 0 | 5244 |

## tier=T4_hard_negative

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.000 | 0.000 | 0.000 | 0 | 517 | 0 |
| Gitleaks | 0.000 | 0.000 | 0.000 | 0 | 504 | 0 |
| TruffleHog | 0.000 | 0.000 | 0.000 | 0 | 319 | 0 |
| Kingfisher | 0.000 | 0.000 | 0.000 | 0 | 322 | 0 |

## source=code

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.957 | 0.671 | 0.789 | 4490 | 204 | 2203 |
| Gitleaks | 0.943 | 0.401 | 0.562 | 2681 | 163 | 4012 |
| Kingfisher | 0.941 | 0.212 | 0.346 | 1420 | 89 | 5273 |
| TruffleHog | 0.914 | 0.175 | 0.294 | 1173 | 110 | 5520 |

## source=confluence

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.965 | 0.632 | 0.764 | 1670 | 61 | 973 |
| Kingfisher | 0.953 | 0.442 | 0.604 | 1168 | 58 | 1475 |
| Gitleaks | 0.936 | 0.427 | 0.587 | 1129 | 77 | 1514 |
| TruffleHog | 0.964 | 0.410 | 0.575 | 1083 | 41 | 1560 |

## source=jira

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.980 | 0.639 | 0.774 | 1911 | 39 | 1079 |
| Gitleaks | 0.960 | 0.419 | 0.583 | 1252 | 52 | 1738 |
| Kingfisher | 0.969 | 0.394 | 0.560 | 1178 | 38 | 1812 |
| TruffleHog | 0.975 | 0.350 | 0.515 | 1046 | 27 | 1944 |

## source=log

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.896 | 0.517 | 0.656 | 1272 | 148 | 1186 |
| Gitleaks | 0.855 | 0.351 | 0.497 | 862 | 146 | 1596 |
| TruffleHog | 0.902 | 0.325 | 0.478 | 800 | 87 | 1658 |
| Kingfisher | 0.899 | 0.305 | 0.456 | 750 | 84 | 1708 |

## source=slack

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.952 | 0.722 | 0.821 | 1277 | 65 | 491 |
| TruffleHog | 0.943 | 0.505 | 0.657 | 892 | 54 | 876 |
| Gitleaks | 0.931 | 0.502 | 0.652 | 887 | 66 | 881 |
| Kingfisher | 0.942 | 0.490 | 0.645 | 866 | 53 | 902 |

## origin=augmented

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.978 | 0.759 | 0.855 | 4882 | 109 | 1550 |
| TruffleHog | 0.980 | 0.537 | 0.694 | 3455 | 70 | 2977 |
| Kingfisher | 0.992 | 0.522 | 0.684 | 3355 | 27 | 3077 |
| Gitleaks | 0.991 | 0.512 | 0.675 | 3295 | 31 | 3137 |

## origin=curated

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.000 | 0.000 | 0.000 | 0 | 0 | 52 |
| Gitleaks | 0.000 | 0.000 | 0.000 | 0 | 0 | 52 |
| TruffleHog | 0.000 | 0.000 | 0.000 | 0 | 0 | 52 |
| Kingfisher | 0.000 | 0.000 | 0.000 | 0 | 0 | 52 |

## origin=real

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.997 | 0.444 | 0.615 | 2792 | 7 | 3491 |
| Gitleaks | 0.982 | 0.262 | 0.414 | 1647 | 31 | 4636 |
| Kingfisher | 0.994 | 0.026 | 0.051 | 164 | 1 | 6119 |
| TruffleHog | 1.000 | 0.014 | 0.027 | 87 | 0 | 6196 |

## origin=synthetic

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.880 | 0.778 | 0.826 | 2946 | 401 | 839 |
| Kingfisher | 0.864 | 0.492 | 0.627 | 1863 | 294 | 1922 |
| Gitleaks | 0.809 | 0.494 | 0.613 | 1869 | 442 | 1916 |
| TruffleHog | 0.854 | 0.384 | 0.529 | 1452 | 249 | 2333 |

