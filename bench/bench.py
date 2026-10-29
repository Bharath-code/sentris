#!/usr/bin/env python3
"""Benchmark Sentris against gitleaks / trufflehog / kingfisher on identical inputs.

Workloads: a pinned public checkout (time + peak RSS) and the labeled corpus (recall / false positives).
Output: bench/results/<date>-<host>.json, latest.json and web/src/lib/benchmark.json (what the site renders).
"""
import argparse, datetime, json, os, platform, re, shutil, statistics, subprocess, sys, tempfile, time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "bench"
WORK = BENCH / "work"
IS_MAC = platform.system() == "Darwin"


def env_file():
    pins = {}
    for line in (BENCH / "tools.env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            pins[k] = v
    return pins


def locate(name):
    local = BENCH / ".tools" / name
    return str(local) if local.exists() else shutil.which(name)


def version_of(cmd):
    out = subprocess.run(cmd, capture_output=True, text=True).stdout.strip()
    m = re.search(r"\d+\.\d+\.\d+", out)
    return m.group(0) if m else out[:40]


def tool_specs(pins, report):
    sentris = str(ROOT / "target" / "release" / "sentris")
    specs = [("Sentris", sentris, lambda p: [sentris, "scan", str(p), "-f", "json"], None)]
    gl, th, kf = locate("gitleaks"), locate("trufflehog"), locate("kingfisher")
    if gl:
        specs.append(("Gitleaks", gl, lambda p: [gl, "dir", str(p), "--no-banner", "-l", "error", "-r", report], pins["GITLEAKS_VERSION"]))
    if th:
        specs.append(("TruffleHog", th, lambda p: [th, "filesystem", str(p), "--no-update", "--no-verification", "--json"], pins["TRUFFLEHOG_VERSION"]))
    if kf:
        specs.append(("Kingfisher", kf, lambda p: [kf, "scan", str(p), "--no-validate", "--format", "json"], pins["KINGFISHER_VERSION"]))
    return specs


def timed(cmd):
    wrapper = ["/usr/bin/time", "-l"] if IS_MAC else ["/usr/bin/time", "-v"]
    t0 = time.perf_counter()
    proc = subprocess.run(wrapper + cmd, capture_output=True, text=True, cwd=ROOT)
    wall = (time.perf_counter() - t0) * 1000
    m = re.search(r"(\d+)\s+maximum resident set size", proc.stderr) if IS_MAC else re.search(r"Maximum resident set size \(kbytes\): (\d+)", proc.stderr)
    rss = int(m.group(1)) * (1 if IS_MAC else 1024) if m else 0
    return wall, rss, proc.stdout


def split_lines(src, dest):
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    names = []
    for i, line in enumerate(src.read_text().splitlines()):
        if line.strip():
            name = f"{i:04d}.txt"
            (dest / name).write_text(line + "\n")
            names.append(name)
    return names


def flagged(names, output):
    return sum(1 for n in names if n in output)


def hardware():
    info = {"os": platform.platform(), "machine": platform.machine()}
    if IS_MAC:
        q = lambda k: subprocess.run(["sysctl", "-n", k], capture_output=True, text=True).stdout.strip()
        info.update(cpu=q("machdep.cpu.brand_string"), cores=int(q("hw.ncpu")), ram_gb=round(int(q("hw.memsize")) / 2**30))
    else:
        cpu = re.search(r"model name\s*:\s*(.+)", Path("/proc/cpuinfo").read_text())
        info.update(cpu=cpu.group(1) if cpu else "unknown", cores=os.cpu_count(), ram_gb=round(os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES") / 2**30))
    return info


def markdown(d):
    w, h = d["workload"], d["hardware"]
    lines = [
        f"# Benchmark ({d['date']}, Sentris {d['sentris_commit']})", "",
        f"Workload: {w['repo']} {w['tag']}, {w['files']} files, {w['mb']} MB (working tree, no .git). Hardware: {h['cpu']}, {h['cores']} cores, {h['ram_gb']} GB, {h['os']}.",
        f"Corpus: {d['corpus']['positives']} positives / {d['corpus']['negatives']} negatives. {d['corpus']['note']}", "",
        "| Tool | Version | Median ms | Min ms | Peak RSS MB | Corpus recall | Corpus FP rate | Command |", "|---|---|---:|---:|---:|---:|---:|---|",
    ]
    for r in d["results"]:
        lines.append(f"| {r['name']} | {r['version']} | {r['ms_median']} | {r['ms_min']} | {r['peak_rss_mb']} | {r['recall']:.1%} | {r['false_positive_rate']:.1%} | `{r['command']}` |")
    if d["skipped_tools"]:
        lines += ["", f"Not run: {', '.join(d['skipped_tools'])} (not installed when this was generated)."]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=5)
    args = ap.parse_args()
    pins = env_file()
    repo = WORK / "repo"
    pos_names = split_lines(WORK / "corpus" / "positives.txt", WORK / "corpus_pos")
    neg_names = split_lines(WORK / "corpus" / "negatives.txt", WORK / "corpus_neg")
    n_files = sum(len(f) for _, _, f in os.walk(repo))
    n_bytes = sum((Path(d) / f).stat().st_size for d, _, fs in os.walk(repo) for f in fs)
    report = tempfile.mktemp(suffix=".json")

    results, skipped = [], []
    specs = tool_specs(pins, report)
    for want in ("Gitleaks", "TruffleHog", "Kingfisher"):
        if not any(s[0] == want for s in specs):
            skipped.append(want)

    for name, binary, build, pinned in specs:
        version = version_of([binary, "--version"] if name != "TruffleHog" else [binary, "--version"])
        timed(build(repo))  # warm-up: page cache + any lazy init
        walls, rss = [], []
        for _ in range(args.runs):
            w, r, _ = timed(build(repo))
            walls.append(w)
            rss.append(r)

        def detect(path, names):
            Path(report).unlink(missing_ok=True)
            _, _, out = timed(build(path))
            extra = Path(report).read_text() if Path(report).exists() else ""
            return flagged(names, out + extra)

        tp, fp = detect(WORK / "corpus_pos", pos_names), detect(WORK / "corpus_neg", neg_names)
        results.append({
            "name": name, "version": version, "pinned_version_match": pinned is None or version == pinned,
            "ms_median": round(statistics.median(walls)), "ms_min": round(min(walls)), "runs": args.runs,
            "peak_rss_mb": round(max(rss) / 2**20, 1),
            "recall": round(tp / len(pos_names), 3), "false_positive_rate": round(fp / len(neg_names), 3),
            "corpus_true_positives": tp, "corpus_false_positives": fp,
            "command": " ".join([os.path.basename(binary)] + build("<dir>")[1:]).replace(report, "<report>"),
        })
        print(f"{name:<11} {version:<8} {results[-1]['ms_median']:>7} ms  {results[-1]['peak_rss_mb']:>7} MB  recall {tp}/{len(pos_names)}  FP {fp}/{len(neg_names)}", flush=True)

    sh = lambda *a: subprocess.run(a, capture_output=True, text=True, cwd=ROOT).stdout.strip()
    out = {
        "date": datetime.date.today().isoformat(),
        "hardware": hardware(),
        "workload": {"repo": pins["REPO_URL"], "tag": pins["REPO_TAG"], "files": n_files, "mb": round(n_bytes / 2**20, 1)},
        "corpus": {"positives": len(pos_names), "negatives": len(neg_names),
                   "note": "Authored by the Sentris project; recall favours Sentris' own rule list. Treat as a regression gauge, not a neutral ranking."},
        "sentris_commit": sh("git", "rev-parse", "--short", "HEAD"), "sentris_dirty": bool(sh("git", "status", "--porcelain", "--", "src", "Cargo.toml", "Cargo.lock")),
        "skipped_tools": skipped,
        "results": sorted(results, key=lambda r: r["ms_median"]),
    }
    text = json.dumps(out, indent=2) + "\n"
    results_dir = BENCH / "results"
    results_dir.mkdir(exist_ok=True)
    (results_dir / f"{out['date']}-{platform.node().split('.')[0]}.json").write_text(text)
    (results_dir / "latest.json").write_text(text)
    (results_dir / "latest.md").write_text(markdown(out))
    (ROOT / "web" / "src" / "lib" / "benchmark.json").write_text(text)
    if skipped:
        print(f"\nskipped (not installed; run bench/fetch-tools.sh): {', '.join(skipped)}", file=sys.stderr)


if __name__ == "__main__":
    main()
