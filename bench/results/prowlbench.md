# ProwlBench (independent-ish benchmark)

24603 labeled snippets. Case-level. Built by a competing scanner's author; `origin=real` is CredData-derived, hence the second block. Negatives exist only in tier T4, so per-tier/source precision outside `all` is not meaningful (use recall there).

## all

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.955 | 0.678 | 0.793 | 11215 | 530 | 5337 |
| Betterleaks | 0.931 | 0.540 | 0.684 | 8946 | 666 | 7606 |
| Gitleaks | 0.931 | 0.411 | 0.571 | 6811 | 504 | 9741 |
| Kingfisher | 0.944 | 0.325 | 0.484 | 5382 | 322 | 11170 |
| TruffleHog | 0.940 | 0.302 | 0.457 | 4994 | 319 | 11558 |

## excluding_credata_derived

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.939 | 0.773 | 0.848 | 7934 | 519 | 2335 |
| Betterleaks | 0.906 | 0.593 | 0.717 | 6090 | 633 | 4179 |
| Kingfisher | 0.942 | 0.508 | 0.660 | 5218 | 321 | 5051 |
| Gitleaks | 0.916 | 0.503 | 0.649 | 5164 | 473 | 5105 |
| TruffleHog | 0.939 | 0.478 | 0.633 | 4907 | 319 | 5362 |

## tier=T1_structured

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 1.000 | 0.844 | 0.915 | 5936 | 0 | 1097 |
| Gitleaks | 1.000 | 0.649 | 0.787 | 4561 | 0 | 2472 |
| Betterleaks | 1.000 | 0.641 | 0.781 | 4508 | 0 | 2525 |
| Kingfisher | 1.000 | 0.604 | 0.753 | 4247 | 0 | 2786 |
| TruffleHog | 1.000 | 0.601 | 0.751 | 4225 | 0 | 2808 |

## tier=T2_generic_context

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 1.000 | 0.700 | 0.823 | 2462 | 0 | 1057 |
| Betterleaks | 1.000 | 0.657 | 0.793 | 2313 | 0 | 1206 |
| Gitleaks | 1.000 | 0.354 | 0.523 | 1246 | 0 | 2273 |
| Kingfisher | 1.000 | 0.010 | 0.019 | 34 | 0 | 3485 |
| TruffleHog | 1.000 | 0.004 | 0.007 | 13 | 0 | 3506 |

## tier=T3_freeform_multilingual

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 1.000 | 0.469 | 0.639 | 2817 | 0 | 3183 |
| Betterleaks | 1.000 | 0.354 | 0.523 | 2125 | 0 | 3875 |
| Kingfisher | 1.000 | 0.183 | 0.310 | 1101 | 0 | 4899 |
| Gitleaks | 1.000 | 0.167 | 0.287 | 1004 | 0 | 4996 |
| TruffleHog | 1.000 | 0.126 | 0.224 | 756 | 0 | 5244 |

## tier=T4_hard_negative

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.000 | 0.000 | 0.000 | 0 | 530 | 0 |
| Gitleaks | 0.000 | 0.000 | 0.000 | 0 | 504 | 0 |
| Betterleaks | 0.000 | 0.000 | 0.000 | 0 | 666 | 0 |
| TruffleHog | 0.000 | 0.000 | 0.000 | 0 | 319 | 0 |
| Kingfisher | 0.000 | 0.000 | 0.000 | 0 | 322 | 0 |

## source=code

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.960 | 0.735 | 0.832 | 4919 | 206 | 1774 |
| Betterleaks | 0.932 | 0.619 | 0.744 | 4144 | 304 | 2549 |
| Gitleaks | 0.943 | 0.401 | 0.562 | 2681 | 163 | 4012 |
| Kingfisher | 0.941 | 0.212 | 0.346 | 1420 | 89 | 5273 |
| TruffleHog | 0.914 | 0.175 | 0.294 | 1173 | 110 | 5520 |

## source=confluence

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.965 | 0.660 | 0.784 | 1744 | 63 | 899 |
| Betterleaks | 0.946 | 0.526 | 0.676 | 1389 | 79 | 1254 |
| Kingfisher | 0.953 | 0.442 | 0.604 | 1168 | 58 | 1475 |
| Gitleaks | 0.936 | 0.427 | 0.587 | 1129 | 77 | 1514 |
| TruffleHog | 0.964 | 0.410 | 0.575 | 1083 | 41 | 1560 |

## source=jira

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.980 | 0.641 | 0.775 | 1917 | 40 | 1073 |
| Betterleaks | 0.966 | 0.495 | 0.654 | 1479 | 52 | 1511 |
| Gitleaks | 0.960 | 0.419 | 0.583 | 1252 | 52 | 1738 |
| Kingfisher | 0.969 | 0.394 | 0.560 | 1178 | 38 | 1812 |
| TruffleHog | 0.975 | 0.350 | 0.515 | 1046 | 27 | 1944 |

## source=log

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.896 | 0.541 | 0.675 | 1330 | 154 | 1128 |
| Betterleaks | 0.861 | 0.402 | 0.548 | 989 | 160 | 1469 |
| Gitleaks | 0.855 | 0.351 | 0.497 | 862 | 146 | 1596 |
| TruffleHog | 0.902 | 0.325 | 0.478 | 800 | 87 | 1658 |
| Kingfisher | 0.899 | 0.305 | 0.456 | 750 | 84 | 1708 |

## source=slack

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.951 | 0.738 | 0.831 | 1305 | 67 | 463 |
| Betterleaks | 0.930 | 0.535 | 0.679 | 945 | 71 | 823 |
| TruffleHog | 0.943 | 0.505 | 0.657 | 892 | 54 | 876 |
| Gitleaks | 0.931 | 0.502 | 0.652 | 887 | 66 | 881 |
| Kingfisher | 0.942 | 0.490 | 0.645 | 866 | 53 | 902 |

## origin=augmented

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.978 | 0.766 | 0.859 | 4927 | 109 | 1505 |
| Betterleaks | 0.955 | 0.556 | 0.702 | 3573 | 169 | 2859 |
| TruffleHog | 0.980 | 0.537 | 0.694 | 3455 | 70 | 2977 |
| Kingfisher | 0.992 | 0.522 | 0.684 | 3355 | 27 | 3077 |
| Gitleaks | 0.991 | 0.512 | 0.675 | 3295 | 31 | 3137 |

## origin=curated

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.000 | 0.000 | 0.000 | 0 | 0 | 52 |
| Gitleaks | 0.000 | 0.000 | 0.000 | 0 | 0 | 52 |
| Betterleaks | 0.000 | 0.000 | 0.000 | 0 | 0 | 52 |
| TruffleHog | 0.000 | 0.000 | 0.000 | 0 | 0 | 52 |
| Kingfisher | 0.000 | 0.000 | 0.000 | 0 | 0 | 52 |

## origin=real

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.997 | 0.522 | 0.685 | 3281 | 11 | 3002 |
| Betterleaks | 0.989 | 0.455 | 0.623 | 2856 | 33 | 3427 |
| Gitleaks | 0.982 | 0.262 | 0.414 | 1647 | 31 | 4636 |
| Kingfisher | 0.994 | 0.026 | 0.051 | 164 | 1 | 6119 |
| TruffleHog | 1.000 | 0.014 | 0.027 | 87 | 0 | 6196 |

## origin=synthetic

| Tool | Precision | Recall | F1 | TP | FP | FN |
|---|---:|---:|---:|---:|---:|---:|
| Sentris | 0.880 | 0.794 | 0.835 | 3007 | 410 | 778 |
| Betterleaks | 0.844 | 0.665 | 0.744 | 2517 | 464 | 1268 |
| Kingfisher | 0.864 | 0.492 | 0.627 | 1863 | 294 | 1922 |
| Gitleaks | 0.809 | 0.494 | 0.613 | 1869 | 442 | 1916 |
| TruffleHog | 0.854 | 0.384 | 0.529 | 1452 | 249 | 2333 |

