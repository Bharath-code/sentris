#!/usr/bin/env python3
"""Recall of Sentris vs gitleaks on gitleaks' OWN rule fixtures (pinned v8.30.1 source).

Reads cmd/generate/config/rules/*.go (never executes it): evaluates the common fixture forms
(GenerateSampleSecrets / literal tps lists with secrets.NewSecret(<regex>) sampled from the regex) in Python,
writes one file per fixture, and counts how many each scanner flags. Rules whose fixtures use constructs this
evaluator does not understand are listed as skipped, so coverage is explicit.
"""
import json, os, random, re, shutil, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "bench" / "work" / "gitleaks-src" / "cmd" / "generate" / "config"
OUT = ROOT / "bench" / "work" / "gl_fixtures"
rng = random.Random(8301)

HELPERS = {  # utils/patterns.go
    "Numeric": "[0-9]{%s}", "Hex": "[a-f0-9]{%s}", "AlphaNumeric": "[a-z0-9]{%s}",
    "AlphaNumericExtendedShort": "[a-z0-9_-]{%s}", "AlphaNumericExtended": "[a-z0-9=_\\-]{%s}",
    "AlphaNumericExtendedLong": "[a-z0-9\\/=_\\+\\-]{%s}",
}
HEX8 = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


class Unsupported(Exception):
    pass


def go_string(src, i):
    q = src[i]
    if q == "`":
        j = src.index("`", i + 1)
        return src[i + 1:j], j + 1
    out, j = [], i + 1
    while src[j] != '"':
        if src[j] == "\\":
            esc = src[j + 1]
            out.append({"n": "\n", "t": "\t", '"': '"', "\\": "\\"}.get(esc, "\\" + esc))
            j += 2
        else:
            out.append(src[j]); j += 1
    return "".join(out), j + 1


def split_args(s):
    args, depth, cur, i = [], 0, [], 0
    while i < len(s):
        c = s[i]
        if c in "\"`":
            lit, j = go_string(s, i); cur.append(s[i:j]); i = j; continue
        if c in "([{": depth += 1
        if c in ")]}": depth -= 1
        if c == "," and depth == 0:
            args.append("".join(cur).strip()); cur = []
        else:
            cur.append(c)
        i += 1
    if "".join(cur).strip():
        args.append("".join(cur).strip())
    return args


def balanced(src, start):  # src[start] == '('
    depth, i = 0, start
    while True:
        c = src[i]
        if c in "\"`":
            _, i = go_string(src, i); continue
        if c == "(": depth += 1
        if c == ")":
            depth -= 1
            if depth == 0: return src[start + 1:i], i + 1
        i += 1


def eval_regex_expr(expr):
    """Go expression producing a regex string -> regex source."""
    parts, i, out = [], 0, []
    expr = expr.strip()
    while i < len(expr):
        c = expr[i]
        if c in " \t\n+": i += 1; continue
        if c in "\"`":
            lit, i = go_string(expr, i); out.append(lit); continue
        m = re.match(r"utils\.(\w+)\(([^)]*)\)", expr[i:])
        if m:
            name, arg = m.groups()
            if name == "Hex8_4_4_4_12": out.append(HEX8)
            elif name in HELPERS:
                size = arg.strip().strip('"') or None
                if size is None: raise Unsupported("helper without size")
                out.append(HELPERS[name] % size)
            else: raise Unsupported(name)
            i += m.end(); continue
        raise Unsupported(expr[i:i + 30])
    return "".join(out)


def sample(rx):
    pos = 0

    def parse_alt():
        nonlocal pos
        branches = [parse_seq()]
        while pos < len(rx) and rx[pos] == "|":
            pos += 1; branches.append(parse_seq())
        return rng.choice(branches)

    def parse_seq():
        nonlocal pos
        res = []
        while pos < len(rx) and rx[pos] not in "|)":
            res.append(parse_quant())
        return "".join(res)

    def parse_quant():
        nonlocal pos
        atom = parse_atom()
        if pos < len(rx):
            c = rx[pos]
            lo = hi = 1
            if c == "{":
                m = re.match(r"\{(\d+)(,(\d*))?\}", rx[pos:])
                if m:
                    lo = int(m.group(1)); hi = int(m.group(3)) if m.group(3) else (lo if not m.group(2) else lo + 8)
                    pos += m.end()
                else: return atom() if callable(atom) else atom
            elif c in "?*+":
                lo, hi = {"?": (0, 1), "*": (0, 3), "+": (1, 4)}[c]; pos += 1
            else:
                return atom() if callable(atom) else atom
            n = rng.randint(lo, hi) if hi - lo <= 1 else hi if lo == hi else rng.randint(lo, hi)
            return "".join(atom() if callable(atom) else atom for _ in range(n))
        return atom() if callable(atom) else atom

    def parse_class():
        nonlocal pos
        pos += 1
        if rx[pos] == "^": raise Unsupported("negated class")
        chars = []
        while rx[pos] != "]":
            c = rx[pos]
            if c == "\\":
                e = rx[pos + 1]; pos += 2
                if e == "w": chars += list("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
                elif e == "d": chars += list("0123456789")
                else: chars.append(e)
                continue
            if pos + 2 < len(rx) and rx[pos + 1] == "-" and rx[pos + 2] != "]":
                chars += [chr(x) for x in range(ord(c), ord(rx[pos + 2]) + 1)]; pos += 3
            else:
                chars.append(c); pos += 1
        pos += 1
        return lambda: rng.choice(chars)

    def parse_atom():
        nonlocal pos
        c = rx[pos]
        if c == "(":
            pos += 1
            if rx.startswith("?:", pos): pos += 2
            elif rx.startswith("?i)", pos): pos += 3; return ""
            elif rx.startswith("?P<", pos) or rx.startswith("?<", pos): pos = rx.index(">", pos) + 1
            elif rx.startswith("?", pos): raise Unsupported("group flags")
            g = parse_alt(); pos += 1
            return lambda g=g: g
        if c == "[": return parse_class()
        if c == "\\":
            e = rx[pos + 1]; pos += 2
            if e == "w": return lambda: rng.choice("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
            if e == "d": return lambda: rng.choice("0123456789")
            if e in "bB": return ""
            return e
        if c in "^$": pos += 1; return ""
        if c == ".": pos += 1; return lambda: rng.choice("abcdefghijklmnop")
        pos += 1
        return c

    out = parse_alt()
    if pos != len(rx): raise Unsupported("trailing regex")
    return out


def eval_secret_expr(expr):
    """Go string expression -> concrete string (literals, NewSecret(regex), helpers)."""
    expr, i, out = expr.strip(), 0, []
    while i < len(expr):
        c = expr[i]
        if c in " \t\n+": i += 1; continue
        if c in "\"`":
            lit, i = go_string(expr, i); out.append(lit); continue
        m = re.match(r"secrets\.NewSecret\(", expr[i:])
        if m:
            inner, j = balanced(expr, i + m.end() - 1)
            out.append(sample(eval_regex_expr(inner))); i = j; continue
        m = re.match(r"utils\.(\w+)\(([^)]*)\)", expr[i:])
        if m:
            out.append(sample(eval_regex_expr(m.group(0)))); i += m.end(); continue
        raise Unsupported(expr[i:i + 30])
    return "".join(out)


def templates():
    src = (SRC / "utils" / "generate.go").read_text()
    body = src[src.index("samples := map[string]string{"):]
    body = body[:body.index("\n\t}\n")]
    found, i = [], 0
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("//") or not line.startswith('"'): continue
        key, j = go_string(line, 0)
        rest = line[j:].lstrip()[1:].strip().rstrip(",")
        if rest and rest[0] in "\"`":
            found.append((key, go_string(rest, 0)[0]))
    return found


def fixtures():
    tmpls = templates()
    cases, skipped = [], {}
    for path in sorted((SRC / "rules").glob("*.go")):
        src = path.read_text()
        for rid in re.findall(r'RuleID:\s+"([^"]+)"', src):
            pass
        rid = (re.search(r'RuleID:\s+"([^"]+)"', src) or [None, path.stem])[1]
        for m in re.finditer(r"utils\.GenerateSampleSecrets\(", src):
            args, _ = balanced(src, m.end() - 1)
            a = split_args(args)
            try:
                ident = go_string(a[0], 0)[0]
                for _ in range(1):
                    secret = eval_secret_expr(a[1])
                    for key, t in tmpls:
                        cases.append((rid, key, t.replace("{i}", ident).replace("{I}", ident.upper()).replace("{s}", secret)))
            except (Unsupported, ValueError, IndexError) as e:
                skipped.setdefault(rid, str(e)[:40])
    return cases, skipped


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, cwd=ROOT)


def main():
    cases, skipped = fixtures()
    if OUT.exists(): shutil.rmtree(OUT)
    OUT.mkdir(parents=True)
    names = {}
    tmpl_of = {}
    for i, (rid, key, text) in enumerate(cases):
        n = f"{i:05d}.txt"; (OUT / n).write_text(text + "\n"); names[n] = rid; tmpl_of[n] = key
    sentris = ROOT / "target" / "release" / "sentris"
    gl = ROOT / "bench" / ".tools" / "gitleaks"
    gl = str(gl) if gl.exists() else "gitleaks"
    report = str(OUT.parent / "gl_fixtures_report.json")
    outs = {
        "Sentris": run([str(sentris), "scan", str(OUT), "-f", "json"]).stdout,
        "Gitleaks": run([gl, "dir", str(OUT), "--no-banner", "-l", "error", "-r", report]).stdout + (Path(report).read_text() if Path(report).exists() else ""),
    }
    hit = {t: {n for n in names if n in o} for t, o in outs.items()}
    per_rule = {}
    for n, rid in names.items():
        r = per_rule.setdefault(rid, {"fixtures": 0, "Sentris": 0, "Gitleaks": 0})
        r["fixtures"] += 1
        for t in hit: r[t] += n in hit[t]
    per_template = {}
    for n, key in tmpl_of.items():
        t = per_template.setdefault(key, {"fixtures": 0, "Sentris": 0, "Gitleaks": 0})
        t["fixtures"] += 1
        for tool in hit: t[tool] += n in hit[tool]
    summary = {
        "per_template": per_template,
        "rules_covered": len(per_rule), "rules_skipped": skipped, "fixtures": len(names),
        "recall": {t: round(len(h) / len(names), 3) for t, h in hit.items()},
        "per_rule": per_rule,
        "caveat": "Fixtures are generated from gitleaks' own regexes and keyed contexts (GenerateSampleSecrets), so they favour gitleaks by construction.",
    }
    (ROOT / "bench" / "results" / "gitleaks-fixtures.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"fixtures {len(names)} from {len(per_rule)} rules ({len(skipped)} rules skipped)")
    print("recall:", summary["recall"])
    worst = sorted(((r["Gitleaks"] - r["Sentris"]) / r["fixtures"], k) for k, r in per_rule.items())[::-1][:25]
    print("largest Sentris gaps:", [(k, round(g, 2)) for g, k in worst if g > 0])


if __name__ == "__main__":
    main()
