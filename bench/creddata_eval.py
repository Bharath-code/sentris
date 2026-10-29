#!/usr/bin/env python3
"""Line-level precision/recall of each scanner on Samsung CredData (independent, human-labeled; 297 GitHub repos).

Setup (once): clone https://github.com/Samsung/CredData into bench/work/creddata and run its download_data.py
(see bench/README.md). Metadata rows label suspect lines True/False; a scanner "hits" a row if it reports a
finding on a line in [LineStart, LineEnd] of that file. Findings on lines CredData never labeled are counted
separately because the dataset cannot say whether they are true or false.
"""
import atexit, csv, json, os, platform, re, shutil, subprocess, sys, tempfile, time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CD = ROOT / "bench" / "work" / "creddata"
DATA = CD / "data"
IS_MAC = platform.system() == "Darwin"
BASE = CD  # main() points this at the scanned copy


def load_rows():
    rows = []
    for f in sorted((CD / "meta").glob("*.csv")):
        with open(f, newline="", encoding="utf-8") as fh:
            for r in csv.DictReader(fh):
                if r["GroundTruth"] in ("T", "F") and r["LineStart"].isdigit():
                    rows.append((r["FilePath"], int(r["LineStart"]), int(r["LineEnd"] or r["LineStart"]), r["GroundTruth"] == "T", r["Category"]))
    return rows


def rel(p):
    p = os.path.abspath(p if os.path.isabs(p) else ROOT / p)
    return os.path.relpath(p, BASE)


def stream_json(text):
    dec, i = json.JSONDecoder(), 0
    while True:
        j = text.find("{", i)
        if j < 0:
            return
        try:
            obj, i = dec.raw_decode(text, j)
        except ValueError:
            i = j + 1
            continue
        yield obj


def parse(tool, out, report):
    hits = set()
    if tool == "Sentris":
        for f in json.loads(out)["findings"]:
            hits.add((rel(f["file_path"]), f["line_number"]))
    elif tool in ("Gitleaks", "Betterleaks"):
        for f in json.loads(Path(report).read_text() or "[]"):
            hits.add((rel(f["File"]), f["StartLine"]))
    elif tool == "TruffleHog":
        for line in out.splitlines():
            if line.startswith("{") and "SourceMetadata" in line:
                fs = json.loads(line)["SourceMetadata"]["Data"]["Filesystem"]
                hits.add((rel(fs["file"]), fs.get("line", 0)))
    elif tool == "Kingfisher":
        for obj in stream_json(out):
            for f in obj.get("findings", []) if isinstance(obj.get("findings"), list) else []:
                fi = f["finding"]
                hits.add((rel(fi["path"]), fi["line"]))
    return hits


def timed(cmd):
    wrapper = ["/usr/bin/time", "-l"] if IS_MAC else ["/usr/bin/time", "-v"]
    t0 = time.perf_counter()
    p = subprocess.run(wrapper + cmd, capture_output=True, text=True, cwd=ROOT)
    wall = time.perf_counter() - t0
    m = re.search(r"(\d+)\s+maximum resident set size", p.stderr) if IS_MAC else re.search(r"Maximum resident set size \(kbytes\): (\d+)", p.stderr)
    return wall, (int(m.group(1)) / (1 if IS_MAC else 1024) / 2**20 if m else 0), p.stdout


def tools(report):
    t = {"Sentris": [str(ROOT / "target/release/sentris"), "scan", str(DATA), "-f", "json"]}
    for name, exe, args in (("Gitleaks", "gitleaks", ["dir", str(DATA), "--no-banner", "-l", "error", "-r", report]),
                            ("Betterleaks", "betterleaks", ["dir", str(DATA), "--no-banner", "-l", "error", "-r", report]),
                            ("TruffleHog", "trufflehog", ["filesystem", str(DATA), "--no-update", "--no-verification", "--json"]),
                            ("Kingfisher", "kingfisher", ["scan", str(DATA), "--no-validate", "--format", "json"])):
        path = ROOT / "bench" / ".tools" / exe
        if path.exists():
            t[name] = [str(path)] + args
    return t


def main():
    global BASE, DATA
    if not DATA.exists():
        sys.exit("CredData not prepared: see bench/README.md")
    rows = load_rows()
    # Scan a copy outside any git work tree: scanners that honor .gitignore (Sentris) would otherwise skip about a fifth of the files
    # because CredData's .gitignore and ours match paths under bench/work, while gitleaks-style `dir` scans ignore it.
    BASE = Path(tempfile.mkdtemp(prefix="creddata-"))
    atexit.register(shutil.rmtree, BASE, True)
    shutil.copytree(DATA, BASE / "data")
    DATA = BASE / "data"
    report = tempfile.mktemp(suffix=".json")
    splits = {"all": lambda repo: True, "dev": lambda repo: int(repo, 16) % 2 == 0, "heldout": lambda repo: int(repo, 16) % 2 == 1}
    results = {k: [] for k in splits}
    for name, cmd in tools(report).items():
        Path(report).unlink(missing_ok=True)
        wall, rss, out = timed(cmd)
        hits = parse(name, out, report)
        by_file = defaultdict(set)
        for f, l in hits:
            by_file[f].add(l)
        for split, keep in splits.items():
            tp = fp = n_true = 0
            per_repo = defaultdict(lambda: [0, 0, 0])
            cat_tp, cat_all, covered = defaultdict(int), defaultdict(int), set()
            for path, a, b, truth, cat in rows:
                if not keep(path.split("/")[1]):
                    continue
                flagged = any(a <= l <= b for l in by_file.get(path, ()))
                if flagged:
                    covered.update((path, l) for l in by_file[path] if a <= l <= b)
                repo_stats = per_repo[path.split("/")[1]]
                repo_stats[0] += bool(truth and flagged)
                repo_stats[1] += bool(flagged and not truth)
                repo_stats[2] += bool(truth)
                if truth:
                    n_true += 1
                    cat_all[cat] += 1
                    cat_tp[cat] += flagged
                    tp += flagged
                elif flagged:
                    fp += 1
            unlabeled = len([h for h in hits if keep(h[0].split("/")[1]) and h not in covered]) if split != "all" else len(hits - covered)
            prec = tp / (tp + fp) if tp + fp else 0
            rec = tp / n_true if n_true else 0
            repo_f1 = []
            for rtp, rfp, rtrue in per_repo.values():
                if rtrue:
                    rp = rtp / (rtp + rfp) if rtp + rfp else 0
                    rr = rtp / rtrue
                    repo_f1.append(2 * rp * rr / (rp + rr) if rp + rr else 0)
            macro_f1 = sum(repo_f1) / len(repo_f1) if repo_f1 else 0
            results[split].append({"name": name, "seconds": round(wall, 1), "peak_rss_mb": round(rss, 1), "true_positives": tp, "false_positives_on_labeled": fp,
                                   "true_rows": n_true, "repos_with_true_rows": len(repo_f1), "macro_f1_per_repo": round(macro_f1, 3), "recall": round(rec, 3), "precision": round(prec, 3),
                                   "f1": round(2 * prec * rec / (prec + rec), 3) if prec + rec else 0, "flagged_on_unlabeled_lines": unlabeled,
                                   "recall_by_category": {c: round(cat_tp[c] / cat_all[c], 3) for c in sorted(cat_all)}})
        for split in ("dev", "heldout"):
            r = results[split][-1]
            print(f"{name:<11} {split:<8} P {r['precision']:.3f} R {r['recall']:.3f} F1 {r['f1']:.3f} macroF1 {r['macro_f1_per_repo']:.3f}  (TP {r['true_positives']}, labeled FP {r['false_positives_on_labeled']})", flush=True)
        print(f"{name:<11} {wall:>6.1f}s {rss:>6.1f} MB", flush=True)
    summary = {"dataset": "Samsung/CredData", "labeled_rows": len(rows),
               "split": "repo id (CRC hex) even = dev (inspect and tune on this), odd = heldout (score only)",
               "results": {k: sorted(v, key=lambda r: -r["f1"]) for k, v in results.items()},
               "note": "Line-level match on labeled rows only; CredData's obfuscation replaced real credentials with same-shape fakes. Findings on unlabeled lines are reported but not scored."}
    (ROOT / "bench" / "results" / "creddata.json").write_text(json.dumps(summary, indent=2) + "\n")
    md = ["# CredData benchmark", "", f"{len(rows)} labeled rows. Line-level; precision uses labeled false rows only. `heldout` = odd repo ids, not used for tuning after the split was introduced.", ""]
    for split in ("all", "dev", "heldout"):
        md += [f"## {split}", "", "| Tool | Precision | Recall | F1 | Macro F1 (per repo) | TP | Labeled FP | Hits on unlabeled lines |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
        for r in summary["results"][split]:
            md.append(f"| {r['name']} | {r['precision']:.3f} | {r['recall']:.3f} | {r['f1']:.3f} | {r['macro_f1_per_repo']:.3f} | {r['true_positives']} | {r['false_positives_on_labeled']} | {r['flagged_on_unlabeled_lines']} |")
        md.append("")
    (ROOT / "bench" / "results" / "creddata.md").write_text("\n".join(md) + "\n")


if __name__ == "__main__":
    main()
