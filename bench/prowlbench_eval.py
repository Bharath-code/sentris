#!/usr/bin/env python3
"""Case-level precision/recall of each scanner on ProwlBench (github.com/Lercas/prowlbench, 24,603 labeled snippets).

Independence caveats: built by the author of a competing scanner; its `origin=real` cases are derived from CredData,
so results are reported for all cases AND for the subset with origin != real. Only the data file is used
(bench/work/prowlbench/prowlbench.jsonl, pinned commit in bench/README.md); none of its code is executed.
Scoring: a case is predicted positive when the tool reports any finding in that snippet (written as <id>.txt).
"""
import json, platform, re, shutil, subprocess, tempfile, time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "bench" / "work" / "prowlbench" / "prowlbench.jsonl"
CASES = ROOT / "bench" / "work" / "prowlbench" / "cases"
IS_MAC = platform.system() == "Darwin"
ID = re.compile(r"pb-\d{5}\.txt")


def timed(cmd):
    wrapper = ["/usr/bin/time", "-l"] if IS_MAC else ["/usr/bin/time", "-v"]
    t0 = time.perf_counter()
    p = subprocess.run(wrapper + cmd, capture_output=True, text=True, cwd=ROOT)
    m = re.search(r"(\d+)\s+maximum resident set size", p.stderr) if IS_MAC else re.search(r"Maximum resident set size \(kbytes\): (\d+)", p.stderr)
    return time.perf_counter() - t0, (int(m.group(1)) / (1 if IS_MAC else 1024) / 2**20 if m else 0), p.stdout


def tools(report):
    t = {"Sentris": [str(ROOT / "target/release/sentris"), "scan", str(CASES), "-f", "json"]}
    for name, exe, args in (("Gitleaks", "gitleaks", ["dir", str(CASES), "--no-banner", "-l", "error", "-r", report]),
                            ("Betterleaks", "betterleaks", ["dir", str(CASES), "--no-banner", "-l", "error", "-r", report]),
                            ("TruffleHog", "trufflehog", ["filesystem", str(CASES), "--no-update", "--no-verification", "--json"]),
                            ("Kingfisher", "kingfisher", ["scan", str(CASES), "--no-validate", "--format", "json"])):
        path = ROOT / "bench" / ".tools" / exe
        if path.exists():
            t[name] = [str(path)] + args
    return t


def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0
    r = tp / (tp + fn) if tp + fn else 0
    return {"precision": round(p, 3), "recall": round(r, 3), "f1": round(2 * p * r / (p + r), 3) if p + r else 0, "tp": tp, "fp": fp, "fn": fn}


def main():
    cases = [json.loads(l) for l in DATA.read_text().splitlines()]
    if CASES.exists():
        shutil.rmtree(CASES)
    CASES.mkdir(parents=True)
    for c in cases:
        (CASES / f"{c['id']}.txt").write_text(c["text"] + "\n", encoding="utf-8")
    report = tempfile.mktemp(suffix=".json")
    groups = {"all": lambda c: True, "excluding_credata_derived": lambda c: c["origin"] != "real"}
    for axis in ("tier", "source", "origin"):
        for v in sorted({c[axis] for c in cases}):
            groups[f"{axis}={v}"] = (lambda a, val: lambda c: c[a] == val)(axis, v)
    out = {"dataset": "ProwlBench", "cases": len(cases), "tools": {}}
    for name, cmd in tools(report).items():
        Path(report).unlink(missing_ok=True)
        wall, rss, stdout = timed(cmd)
        text = stdout + (Path(report).read_text() if Path(report).exists() else "")
        flagged = set(ID.findall(text))
        res = {}
        for g, keep in groups.items():
            tp = fp = fn = 0
            for c in cases:
                if not keep(c):
                    continue
                hit = f"{c['id']}.txt" in flagged
                if c["label"] and hit: tp += 1
                elif c["label"]: fn += 1
                elif hit: fp += 1
            res[g] = prf(tp, fp, fn)
        out["tools"][name] = {"seconds": round(wall, 1), "peak_rss_mb": round(rss, 1), "groups": res}
        a, b = res["all"], res["excluding_credata_derived"]
        print(f"{name:<11} all P {a['precision']:.3f} R {a['recall']:.3f} F1 {a['f1']:.3f} | indep P {b['precision']:.3f} R {b['recall']:.3f} F1 {b['f1']:.3f} | {wall:.1f}s {rss:.0f}MB", flush=True)
    (ROOT / "bench" / "results" / "prowlbench.json").write_text(json.dumps(out, indent=2) + "\n")
    names = list(out["tools"])
    md = ["# ProwlBench (independent-ish benchmark)", "", f"{len(cases)} labeled snippets. Case-level. Built by a competing scanner's author; `origin=real` is CredData-derived, hence the second block. Negatives exist only in tier T4, so per-tier/source precision outside `all` is not meaningful (use recall there).", ""]
    for g in groups:
        md += [f"## {g}", "", "| Tool | Precision | Recall | F1 | TP | FP | FN |", "|---|---:|---:|---:|---:|---:|---:|"]
        for n in sorted(names, key=lambda n: -out["tools"][n]["groups"][g]["f1"]):
            r = out["tools"][n]["groups"][g]
            md.append(f"| {n} | {r['precision']:.3f} | {r['recall']:.3f} | {r['f1']:.3f} | {r['tp']} | {r['fp']} | {r['fn']} |")
        md.append("")
    (ROOT / "bench" / "results" / "prowlbench.md").write_text("\n".join(md) + "\n")


if __name__ == "__main__":
    main()
