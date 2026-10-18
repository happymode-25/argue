#!/usr/bin/env python3
"""argue -- an argument cartographer.

Take a written argument, turn it into a claim/evidence graph, and find the
holes: claims nothing supports, evidence that supports nothing, circular
support, attacks that are never answered, and parts of the argument that are
not connected to the whole.

The argument is written in a small, explicit line format (see README) rather
than guessed from prose. That is deliberate: a tool that invents your premises
for you cannot be trusted to audit them. You state the structure; argue maps
it, checks it, and keeps a hash-chained record of every review.

Single file, Python 3.9+, standard library only.

    python argue.py selftest
    python argue.py check argument.arg
    python argue.py render argument.arg --out map.html
    python argue.py review argument.arg --note "v2 after review"
    python argue.py verify
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import sys
import tempfile
import textwrap
from datetime import datetime

TOOL = "argue"
VERSION = "1.0.0"
GENESIS = "0" * 64

KINDS = ("claim", "evidence", "assumption", "counter", "warrant")
LABELS = ("supports", "attacks")

RULE_SEVERITY = {
    "unknown-reference": "error",
    "self-loop": "error",
    "cyclic-support": "error",
    "unsupported-claim": "error",
    "attack-on-non-claim": "warn",
    "assumption-only": "warn",
    "dangling-evidence": "warn",
    "orphan-node": "warn",
    "one-sided": "warn",
    "unreferenced-counter": "warn",
}

ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]*$")
NODE_RE = re.compile(r"^([A-Za-z][A-Za-z0-9_-]*)\s*:\s*([a-z]+)\s*:\s*(.+)$")


class ArgueError(Exception):
    """A refusal: bad input, bad store, bad record. Always exits non-zero."""


def fail(message: str):
    raise ArgueError(message)


# --------------------------------------------------------------------------
# canonical hashing (identical discipline to the rest of the family)
# --------------------------------------------------------------------------

def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record_hash(rec: dict) -> str:
    body = {k: v for k, v in rec.items() if k != "hash"}
    return sha256_hex(canonical(body))


def now_iso(now=None) -> str:
    if now:
        return now
    return datetime.now().isoformat(timespec="seconds")


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------

def parse_doc(text: str):
    """Parse the argument format into (nodes, edges). Raises ArgueError."""
    nodes = {}
    edges = []
    for lineno, raw in enumerate(text.splitlines(), start=1):
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        m = NODE_RE.match(s)
        if m:
            nid, kind, body = m.group(1), m.group(2).lower(), m.group(3).strip()
            if kind not in KINDS:
                fail("line %d: unknown kind %r (expected one of %s)"
                     % (lineno, kind, ", ".join(KINDS)))
            if not body:
                fail("line %d: node %r has empty text" % (lineno, nid))
            if nid in nodes:
                fail("line %d: duplicate node id %r" % (lineno, nid))
            nodes[nid] = {"id": nid, "kind": kind, "text": body, "line": lineno}
            continue
        if "->" in s:
            left, _, right = s.partition("->")
            src = left.strip()
            dst = right.strip()
            label = "supports"
            if ":" in dst:
                dst, _, lab = dst.partition(":")
                dst = dst.strip()
                lab = lab.strip().lower()
                if lab not in LABELS:
                    fail("line %d: unknown edge label %r (expected %s)"
                         % (lineno, lab, " or ".join(LABELS)))
                label = lab
            if not ID_RE.match(src):
                fail("line %d: bad source id %r" % (lineno, src))
            if not ID_RE.match(dst):
                fail("line %d: bad target id %r" % (lineno, dst))
            edges.append({"src": src, "dst": dst, "label": label, "line": lineno})
            continue
        fail("line %d: cannot parse %r (expected 'ID : kind : text' or 'ID -> ID')"
             % (lineno, s))
    return nodes, edges


def support_cycles(nodes: dict, edges: list):
    """Return strongly-connected components of size > 1 in the supports graph."""
    succ = {i: [] for i in nodes}
    for e in edges:
        if (e["label"] == "supports" and e["src"] in nodes
                and e["dst"] in nodes and e["src"] != e["dst"]):
            succ[e["src"]].append(e["dst"])

    index, low, on_stack, stack = {}, {}, set(), []
    counter = [0]
    comps = []

    def strong(v):
        index[v] = low[v] = counter[0]
        counter[0] += 1
        stack.append(v)
        on_stack.add(v)
        for w in succ[v]:
            if w not in index:
                strong(w)
                low[v] = min(low[v], low[w])
            elif w in on_stack:
                low[v] = min(low[v], index[w])
        if low[v] == index[v]:
            comp = []
            while True:
                w = stack.pop()
                on_stack.discard(w)
                comp.append(w)
                if w == v:
                    break
            if len(comp) > 1:
                comps.append(sorted(comp))

    for v in nodes:
        if v not in index:
            strong(v)
    comps.sort()
    return comps


def F(rule: str, nodes_, line: int, message: str) -> dict:
    return {"rule": rule, "severity": RULE_SEVERITY[rule],
            "nodes": list(nodes_), "line": line, "message": message}


def analyze(nodes: dict, edges: list):
    findings = []

    for e in edges:
        if e["src"] not in nodes or e["dst"] not in nodes:
            missing = e["src"] if e["src"] not in nodes else e["dst"]
            findings.append(F("unknown-reference", [missing], e["line"],
                              "line %d: edge references unknown node %r"
                              % (e["line"], missing)))
            continue
        if e["src"] == e["dst"]:
            findings.append(F("self-loop", [e["src"]], e["line"],
                              "line %d: %s -> %s is a self-loop"
                              % (e["line"], e["src"], e["dst"])))
        if e["label"] == "attacks" and nodes[e["dst"]]["kind"] != "claim":
            findings.append(F("attack-on-non-claim", [e["dst"]], e["line"],
                              "line %d: attack targets %r, which is a %s, not a claim"
                              % (e["line"], e["dst"], nodes[e["dst"]]["kind"])))

    for comp in support_cycles(nodes, edges):
        findings.append(F("cyclic-support", comp, nodes[comp[0]]["line"],
                          "circular support: %s" % " -> ".join(comp + [comp[0]])))

    insup = {i: [] for i in nodes}
    inatk = {i: [] for i in nodes}
    outdeg = {i: 0 for i in nodes}
    indeg = {i: 0 for i in nodes}
    for e in edges:
        if e["src"] in nodes:
            outdeg[e["src"]] += 1
        if e["dst"] in nodes:
            indeg[e["dst"]] += 1
        if e["src"] in nodes and e["dst"] in nodes:
            if e["label"] == "supports":
                insup[e["dst"]].append(e)
            else:
                inatk[e["dst"]].append(e)

    for i, n in nodes.items():
        kind = n["kind"]
        if kind == "claim":
            if not insup[i]:
                findings.append(F("unsupported-claim", [i], n["line"],
                                  "claim %r has no supporting evidence or argument" % i))
            elif all(nodes[e["src"]]["kind"] == "assumption" for e in insup[i]):
                findings.append(F("assumption-only", [i], n["line"],
                                  "claim %r rests only on assumptions" % i))
            if insup[i] and not inatk[i]:
                findings.append(F("one-sided", [i], n["line"],
                                  "claim %r considers no counter-evidence" % i))
        if kind == "evidence" and outdeg[i] == 0 and indeg[i] > 0:
            findings.append(F("dangling-evidence", [i], n["line"],
                              "evidence %r supports nothing" % i))
        if kind == "counter" and outdeg[i] == 0:
            findings.append(F("unreferenced-counter", [i], n["line"],
                              "counter %r attacks nothing" % i))
        if indeg[i] == 0 and outdeg[i] == 0:
            findings.append(F("orphan-node", [i], n["line"],
                              "%s %r is not connected to the argument" % (kind, i)))

    findings.sort(key=lambda f: (0 if f["severity"] == "error" else 1,
                                 f["rule"], f["nodes"][0] if f["nodes"] else "",
                                 f["line"]))
    return findings, build_summary(nodes, edges, findings)


def build_summary(nodes: dict, edges: list, findings: list) -> dict:
    kinds = {k: 0 for k in KINDS}
    for n in nodes.values():
        kinds[n["kind"]] += 1
    sup = sum(1 for e in edges if e["label"] == "supports")
    atk = sum(1 for e in edges if e["label"] == "attacks")
    counts = {}
    for e in edges:
        if (e["label"] == "supports" and e["dst"] in nodes
                and nodes[e["dst"]]["kind"] == "claim"):
            counts[e["dst"]] = counts.get(e["dst"], 0) + 1
    load_bearing = None
    if counts:
        load_bearing = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
    return {
        "nodes": len(nodes), "edges": len(edges),
        "claims": kinds["claim"], "evidence": kinds["evidence"],
        "assumptions": kinds["assumption"], "counters": kinds["counter"],
        "warrants": kinds["warrant"],
        "support_edges": sup, "attack_edges": atk,
        "errors": sum(1 for f in findings if f["severity"] == "error"),
        "warnings": sum(1 for f in findings if f["severity"] == "warn"),
        "load_bearing": load_bearing,
    }


def analyze_text(text: str):
    nodes, edges = parse_doc(text)
    findings, summary = analyze(nodes, edges)
    return nodes, edges, findings, summary


def exit_code(findings: list, strict: bool) -> int:
    if any(f["severity"] == "error" for f in findings):
        return 1
    if strict and findings:
        return 1
    return 0


# --------------------------------------------------------------------------
# the review ledger (hash-chained)
# --------------------------------------------------------------------------

def resolve_store(explicit):
    if explicit:
        return pathlib.Path(explicit)
    env = os.environ.get("ARGUE_STORE")
    if env:
        return pathlib.Path(env)
    return pathlib.Path.home() / ".argue" / "ledger.jsonl"


def load_records(store: pathlib.Path) -> list:
    if not store.exists():
        return []
    records = []
    with open(store, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except ValueError:
                fail("store %s: line %d is not valid JSON" % (store, lineno))
    return records


def append_record(store: pathlib.Path, rec: dict) -> dict:
    records = load_records(store)
    prev = records[-1]["hash"] if records else GENESIS
    rec = dict(rec)
    rec["seq"] = len(records)
    rec["prev"] = prev
    rec["hash"] = record_hash(rec)
    store.parent.mkdir(parents=True, exist_ok=True)
    with open(store, "a", encoding="utf-8") as fh:
        fh.write(canonical(rec) + "\n")
    return rec


def verify_chain(records: list) -> list:
    problems = []
    expected_prev = GENESIS
    for i, rec in enumerate(records):
        if rec.get("seq") != i:
            problems.append("record %d: seq is %r, expected %d"
                            % (i, rec.get("seq"), i))
        if rec.get("prev") != expected_prev:
            problems.append("record %d: prev link is broken" % i)
        if rec.get("hash") != record_hash(rec):
            problems.append("record %d: content hash mismatch" % i)
        expected_prev = rec.get("hash")
    return problems


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

KIND_COLOR = {
    "claim": "#7aa2f7",
    "evidence": "#9ece6a",
    "assumption": "#e0af68",
    "counter": "#f7768e",
    "warrant": "#bb9af7",
}


def _esc(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def _ranks(nodes: dict, edges: list):
    pred = {i: [] for i in nodes}
    for e in edges:
        if (e["src"] in nodes and e["dst"] in nodes
                and e["src"] != e["dst"]):
            pred[e["dst"]].append(e["src"])
    memo, stack = {}, set()

    def rank(n):
        if n in memo:
            return memo[n]
        if n in stack:
            return 0
        stack.add(n)
        best = 0
        for p in pred[n]:
            best = max(best, 1 + rank(p))
        stack.discard(n)
        memo[n] = best
        return best

    for n in nodes:
        rank(n)
    return memo


def render_html(nodes: dict, edges: list, findings: list, summary: dict, title: str) -> str:
    flagged = set()
    for f in findings:
        for n in f["nodes"]:
            flagged.add(n)

    if not nodes:
        body = ("<p class='empty'>Nothing to map. Add nodes like "
                "<code>C1: claim: ...</code> and edges like "
                "<code>E1 -&gt; C1</code>.</p>")
    else:
        col_w, row_h, box_w, box_h = 240, 74, 180, 46
        ranks = _ranks(nodes, edges)
        columns = {}
        for nid in sorted(nodes):
            columns.setdefault(ranks[nid], []).append(nid)
        pos = {}
        for col, ids in columns.items():
            for row, nid in enumerate(ids):
                pos[nid] = (60 + col * col_w, 60 + row * row_h)

        def center(nid, side):
            x, y = pos[nid]
            return (x + (box_w if side == "right" else 0), y + box_h / 2)

        parts = []
        for e in edges:
            if e["src"] not in pos or e["dst"] not in pos:
                continue
            x1, y1 = center(e["src"], "right")
            x2, y2 = center(e["dst"], "left")
            color = "#f7768e" if e["label"] == "attacks" else "#9ece6a"
            dash = ' stroke-dasharray="5,4"' if e["label"] == "attacks" else ""
            parts.append(
                "<path d='M%d,%d C%d,%d %d,%d %d,%d' fill='none' stroke='%s' "
                "stroke-width='1.6'%s marker-end='url(#%s)'/>"
                % (x1, y1, x1 + 40, y1, x2 - 40, y2, x2, y2, color, dash,
                   "arrow-attack" if e["label"] == "attacks" else "arrow-support"))
        for nid in sorted(nodes):
            x, y = pos[nid]
            n = nodes[nid]
            stroke = "#f7768e" if nid in flagged else "#3b4261"
            parts.append(
                "<rect x='%d' y='%d' width='%d' height='%d' rx='8' "
                "fill='#1f2335' stroke='%s' stroke-width='2'/>"
                % (x, y, box_w, box_h, stroke))
            parts.append("<text x='%d' y='%d' fill='%s' font-size='12' "
                         "font-family='ui-monospace,monospace'>%s</text>"
                         % (x + 12, y + 20, KIND_COLOR[n["kind"]],
                            _esc("%s : %s" % (nid, n["kind"]))))
            label = n["text"] if len(n["text"]) <= 22 else n["text"][:21] + "\u2026"
            parts.append("<text x='%d' y='%d' fill='#c0caf5' font-size='12' "
                         "font-family='system-ui,sans-serif'>%s</text>"
                         % (x + 12, y + 37, _esc(label)))
        width = 60 + (max(columns) + 1) * col_w
        height = 60 + max(len(v) for v in columns.values()) * row_h
        body = (
            "<svg viewBox='0 0 %d %d' width='100%%' style='max-width:%dpx'>"
            "<defs>"
            "<marker id='arrow-support' markerWidth='10' markerHeight='10' "
            "refX='9' refY='3' orient='auto'><path d='M0,0 L9,3 L0,6' "
            "fill='none' stroke='#9ece6a'/></marker>"
            "<marker id='arrow-attack' markerWidth='10' markerHeight='10' "
            "refX='9' refY='3' orient='auto'><path d='M0,0 L9,3 L0,6' "
            "fill='none' stroke='#f7768e'/></marker>"
            "</defs>%s</svg>" % (width, height, width, "".join(parts)))

    if findings:
        rows = "".join(
            "<li><span class='sev %s'>%s</span> <code>%s</code> %s</li>"
            % (f["severity"], f["severity"], _esc(f["rule"]), _esc(f["message"]))
            for f in findings)
        finding_html = "<ul class='findings'>%s</ul>" % rows
    else:
        finding_html = "<p class='ok'>No findings. The argument is connected, acyclic, supported, and considers counter-evidence.</p>"

    return """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>%s</title>
<style>
:root { color-scheme: dark; }
body { margin:0; background:#1a1b26; color:#c0caf5;
  font-family:system-ui,-apple-system,Segoe UI,sans-serif; }
header { padding:28px 32px 8px; }
h1 { margin:0 0 6px; font-size:22px; }
.sub { color:#565f89; font-size:14px; }
main { padding:16px 32px 40px; }
.cards { display:flex; flex-wrap:wrap; gap:10px; margin:16px 0; }
.card { background:#1f2335; border:1px solid #3b4261; border-radius:8px;
  padding:10px 14px; min-width:96px; }
.card .n { font-size:20px; font-weight:600; }
.card .l { color:#565f89; font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
.findings { list-style:none; padding:0; }
.findings li { background:#1f2335; border:1px solid #3b4261; border-radius:8px;
  padding:10px 14px; margin:8px 0; font-size:14px; }
.sev { font-weight:700; text-transform:uppercase; font-size:11px; margin-right:8px; }
.sev.error { color:#f7768e; }
.sev.warn { color:#e0af68; }
.ok { color:#9ece6a; }
.empty { color:#565f89; }
code { background:#16161e; padding:1px 5px; border-radius:4px; }
</style></head><body>
<header>
  <h1>%s</h1>
  <div class="sub">%d nodes &middot; %d edges &middot; %d errors &middot; %d warnings</div>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="n">%d</div><div class="l">claims</div></div>
    <div class="card"><div class="n">%d</div><div class="l">evidence</div></div>
    <div class="card"><div class="n">%d</div><div class="l">assumptions</div></div>
    <div class="card"><div class="n">%d</div><div class="l">counters</div></div>
  </div>
  %s
  %s
</main></body></html>
""" % (_esc(title), _esc(title), summary["nodes"], summary["edges"],
       summary["errors"], summary["warnings"], summary["claims"],
       summary["evidence"], summary["assumptions"], summary["counters"],
       body, finding_html)


# --------------------------------------------------------------------------
# commands (each returns an exit code)
# --------------------------------------------------------------------------

def read_doc(path: str):
    if path == "-":
        data = sys.stdin.buffer.read()
        return data.decode("utf-8"), "<stdin>", sha256_bytes(data)
    p = pathlib.Path(path)
    if not p.exists():
        fail("no such file: %s" % path)
    data = p.read_bytes()
    return data.decode("utf-8"), p.name, sha256_bytes(data)


def report_text(name, nodes, edges, findings, summary) -> str:
    out = []
    out.append("document: %s" % name)
    out.append("nodes: %d (%d claim, %d evidence, %d assumption, %d counter, %d warrant)"
               % (summary["nodes"], summary["claims"], summary["evidence"],
                  summary["assumptions"], summary["counters"], summary["warrants"]))
    out.append("edges: %d (%d supports, %d attacks)"
               % (summary["edges"], summary["support_edges"], summary["attack_edges"]))
    if not findings:
        out.append("")
        out.append("no findings")
    else:
        for sev in ("error", "warn"):
            group = [f for f in findings if f["severity"] == sev]
            if not group:
                continue
            out.append("")
            out.append("%ss (%d)" % (sev, len(group)))
            for f in group:
                out.append("  [%s] %s" % (f["rule"], f["message"]))
    if summary["load_bearing"]:
        lb = summary["load_bearing"]
        out.append("")
        out.append("load-bearing claim: %s (%r)" % (lb, nodes[lb]["text"]))
    return "\n".join(out)


def cmd_check(path, as_json, strict):
    text, name, _ = read_doc(path)
    nodes, edges, findings, summary = analyze_text(text)
    if as_json:
        print(json.dumps({
            "document": name,
            "nodes": [nodes[k] for k in sorted(nodes)],
            "edges": edges,
            "findings": findings,
            "summary": summary,
        }, indent=2, sort_keys=True))
    else:
        print(report_text(name, nodes, edges, findings, summary))
    return exit_code(findings, strict)


def cmd_graph(path, as_json):
    text, name, _ = read_doc(path)
    nodes, edges = parse_doc(text)
    if as_json:
        print(json.dumps({"document": name,
                          "nodes": [nodes[k] for k in sorted(nodes)],
                          "edges": edges}, indent=2, sort_keys=True))
        return 0
    print("document: %s" % name)
    for nid in sorted(nodes):
        n = nodes[nid]
        print("  %-6s %-11s %s" % (nid, n["kind"], n["text"]))
    print("")
    for e in edges:
        arrow = "attacks" if e["label"] == "attacks" else "supports"
        print("  %s -> %s (%s)" % (e["src"], e["dst"], arrow))
    return 0


def cmd_render(path, out, title):
    text, name, _ = read_doc(path)
    nodes, edges, findings, summary = analyze_text(text)
    html = render_html(nodes, edges, findings, summary, title or name)
    out_path = pathlib.Path(out)
    if out_path.parent and str(out_path.parent) not in ("", "."):
        out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(html)
    print("wrote map to %s" % out)
    return 0


def cmd_review(path, note, store, now):
    text, name, doc_hash = read_doc(path)
    nodes, edges, findings, summary = analyze_text(text)
    rec = append_record(store, {
        "ts": now_iso(now), "tool": TOOL, "version": VERSION, "kind": "review",
        "doc": name, "doc_hash": doc_hash,
        "nodes": summary["nodes"], "edges": summary["edges"],
        "errors": summary["errors"], "warnings": summary["warnings"],
        "note": note or "",
    })
    print("reviewed %s" % name)
    print("  doc hash %s" % doc_hash[:12])
    print("  findings %d errors, %d warnings" % (summary["errors"], summary["warnings"]))
    print("  recorded as seq %d" % rec["seq"])
    return 0


def cmd_history(as_json, store):
    records = load_records(store)
    if as_json:
        print(json.dumps(records, indent=2, sort_keys=True))
        return 0
    if not records:
        print("no reviews recorded")
        return 0
    for r in records:
        print("%4d  %s  %s  (%d err, %d warn)  %s"
              % (r["seq"], r["ts"], r["doc"], r.get("errors", 0),
                 r.get("warnings", 0), r.get("note", "")))
    return 0


def cmd_verify(as_json, store):
    records = load_records(store)
    problems = verify_chain(records)
    if as_json:
        print(json.dumps({"ok": not problems, "records": len(records),
                          "problems": problems}, indent=2, sort_keys=True))
        return 0 if not problems else 1
    if not problems:
        print("chain intact: %d records" % len(records))
        return 0
    print("chain broken: %d problems" % len(problems))
    for p in problems:
        print("  - %s" % p)
    return 1


# --------------------------------------------------------------------------
# selftest
# --------------------------------------------------------------------------

class Checks:
    def __init__(self):
        self.total = 0
        self.failed = []

    def ok(self, condition, name):
        self.total += 1
        if not condition:
            self.failed.append(name)

    def eq(self, got, want, name):
        self.total += 1
        if got != want:
            self.failed.append("%s (got %r, want %r)" % (name, got, want))

    def report(self):
        if not self.failed:
            print("all checks passed: %d" % self.total)
            return 0
        print("FAIL: %d of %d checks failed" % (len(self.failed), self.total))
        for name in self.failed:
            print("  - %s" % name)
        return 1


def _doc(*lines) -> str:
    return "\n".join(lines) + "\n"


CLEAN = _doc(
    "C1: claim: The migration ships by Nov 1.",
    "E1: evidence: The last two migrations shipped on time.",
    "X1: counter: The vendor is already two weeks late.",
    "E1 -> C1",
    "X1 -> C1 : attacks",
)

WARN_ONLY = _doc(
    "C1: claim: c",
    "E1: evidence: e",
    "E1 -> C1",
)

WITH_ERROR = _doc(
    "C1: claim: c",
    "E1: evidence: e",
)

BAD_KIND = _doc("C1: nonsense: x")


def cmd_selftest():
    c = Checks()

    # --- parsing -----------------------------------------------------------
    nodes, edges = parse_doc(_doc(
        "C1: claim: c", "E1: evidence: e", "A1: assumption: a",
        "X1: counter: x", "W1: warrant: w"))
    c.eq([nodes[k]["kind"] for k in ("C1", "E1", "A1", "X1", "W1")],
         ["claim", "evidence", "assumption", "counter", "warrant"],
         "all five node kinds parse")

    _, edges = parse_doc(_doc("E1: evidence: e", "C1: claim: c", "E1 -> C1"))
    c.eq(edges[0]["label"], "supports", "edge defaults to supports")
    _, edges = parse_doc(_doc("E1: evidence: e", "C1: claim: c", "E1 -> C1 : attacks"))
    c.eq(edges[0]["label"], "attacks", "explicit attacks label parses")

    n2, e2 = parse_doc("# comment\n\n  \nC1: claim: c\n")
    c.eq((len(n2), len(e2)), (1, 0), "blank and comment lines are skipped")

    n3, _ = parse_doc(_doc("C1: claim: ratio 3:1 holds"))
    c.eq(n3["C1"]["text"], "ratio 3:1 holds", "colons inside text are preserved")

    n4, _ = parse_doc(_doc("# hi", "C1: claim: c"))
    c.eq(n4["C1"]["line"], 2, "line numbers are recorded")

    for bad, name in [
        (_doc("C1: claim: a", "C1: claim: b"), "duplicate id is refused"),
        (_doc("C1: nonsense: x"), "unknown kind is refused"),
        (_doc("C1: claim:"), "empty text is refused"),
        (_doc("this is not a line"), "malformed line is refused"),
        (_doc("1Bad: claim: x"), "bad id is refused"),
        (_doc("E1: evidence: e", "C1: claim: c", "E1 -> C1 : maybe"), "unknown label is refused"),
    ]:
        try:
            parse_doc(bad)
            c.ok(False, name)
        except ArgueError:
            c.ok(True, name)

    # --- analysis ----------------------------------------------------------
    def find(text):
        n, e, f, s = analyze_text(text)
        return f

    def rules(text):
        return sorted(f["rule"] for f in find(text))

    c.ok("unknown-reference" in rules(_doc(
        "C1: claim: c", "E1: evidence: e", "E1 -> C1", "Z -> C1")),
        "unknown reference detected")

    c.ok("self-loop" in rules(_doc("C1: claim: c", "C1 -> C1")),
        "self loop detected")

    cyc = _doc("P: claim: p", "Q: claim: q", "P -> Q", "Q -> P")
    c.ok("cyclic-support" in rules(cyc), "circular support detected")
    c.ok("cyclic-support" not in rules(_doc(
        "P: claim: p", "Q: claim: q", "P -> Q")),
        "a DAG raises no cycle")

    c.ok("unsupported-claim" in rules(WITH_ERROR), "unsupported claim detected")
    c.ok("unsupported-claim" not in rules(CLEAN), "supported claim not flagged")
    c.ok("assumption-only" in rules(_doc(
        "C1: claim: c", "A1: assumption: a", "A1 -> C1")),
        "assumption-only claim detected")
    c.ok("assumption-only" not in rules(_doc(
        "C1: claim: c", "E1: evidence: e", "A1: assumption: a",
        "E1 -> C1", "A1 -> C1")),
        "evidence-supported claim is not assumption-only")

    c.ok("dangling-evidence" in rules(_doc(
        "C1: claim: c", "E1: evidence: e", "E2: evidence: unused",
        "E1 -> C1", "E1 -> E2")),
        "dangling evidence detected")

    c.ok("orphan-node" in rules(_doc(
        "C1: claim: c", "E1: evidence: e", "E1 -> C1", "O1: evidence: lonely")),
        "orphan node detected")
    orphan_only = rules(_doc("C1: claim: c", "E1: evidence: e",
                             "E1 -> C1", "O1: evidence: lonely"))
    c.ok("dangling-evidence" not in orphan_only,
        "an orphan is not also reported as dangling")

    c.ok("one-sided" in rules(WARN_ONLY), "one-sided claim detected")
    c.ok("one-sided" not in rules(CLEAN), "attacked claim is not one-sided")

    c.ok("attack-on-non-claim" in rules(_doc(
        "C1: claim: c", "E1: evidence: e", "E2: evidence: e2",
        "E1 -> C1", "E2 -> C1", "C1 -> E1 : attacks")),
        "attack on a non-claim detected")

    c.ok("unreferenced-counter" in rules(_doc(
        "C1: claim: c", "E1: evidence: e", "X1: counter: x",
        "E1 -> C1")),
        "unreferenced counter detected")
    c.ok("unreferenced-counter" not in rules(CLEAN),
        "connected counter is not unreferenced")

    # --- summary -----------------------------------------------------------
    nodes, edges, findings, summary = analyze_text(CLEAN)
    c.eq((summary["claims"], summary["evidence"], summary["counters"]),
         (1, 1, 1), "summary counts nodes by kind")
    c.eq((summary["support_edges"], summary["attack_edges"]), (1, 1),
         "summary counts edges by label")
    c.eq((summary["errors"], summary["warnings"]), (0, 0),
         "a clean argument has no findings")
    c.eq(summary["load_bearing"], "C1", "load-bearing claim identified")

    _, _, findings, summary = analyze_text(WARN_ONLY)
    c.eq((summary["errors"], summary["warnings"]), (0, 1),
         "warn-only argument reports one warning")

    # --- exit codes --------------------------------------------------------
    def safe_code(text, strict=False):
        try:
            _, _, findings, _ = analyze_text(text)
        except ArgueError:
            return 2
        return exit_code(findings, strict)

    c.eq(safe_code(CLEAN), 0, "clean document exits 0")
    c.eq(safe_code(WITH_ERROR), 1, "document with an error exits 1")
    c.eq(safe_code(WARN_ONLY), 0, "warn-only exits 0 by default")
    c.eq(safe_code(WARN_ONLY, strict=True), 1, "warn-only exits 1 under --strict")
    c.eq(safe_code(BAD_KIND), 2, "unparseable document exits 2")

    # --- chain -------------------------------------------------------------
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="argue-selftest-"))
    try:
        store = tmp / "ledger.jsonl"
        first = append_record(store, {"ts": "2026-01-01T00:00:00", "kind": "review",
                                      "doc": "a.arg", "errors": 0, "warnings": 0})
        c.eq(first["seq"], 0, "first record has seq 0")
        c.eq(first["prev"], GENESIS, "first record links to genesis")
        second = append_record(store, {"ts": "2026-01-01T00:01:00", "kind": "review",
                                       "doc": "b.arg", "errors": 1, "warnings": 2})
        c.eq(second["prev"], first["hash"], "second record links to the first hash")
        c.eq(verify_chain(load_records(store)), [], "clean chain verifies")

        tampered = load_records(store)
        tampered[0]["errors"] = 9
        c.ok(any("hash" in p for p in verify_chain(tampered)),
             "editing a record is caught")

        deleted = load_records(store)
        del deleted[0]
        c.ok(len(verify_chain(deleted)) > 0, "deleting the oldest record is caught")
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

    # --- render ------------------------------------------------------------
    nodes, edges, findings, summary = analyze_text(CLEAN)
    html = render_html(nodes, edges, findings, summary, "demo")
    c.ok("<svg" in html, "render emits an svg")
    c.ok("http://" not in html and "https://" not in html,
         "render contains no external URLs")
    c.ok("<script" not in html, "render contains no script")
    empty_html = render_html({}, [], [], {"nodes": 0, "edges": 0, "claims": 0,
                                          "evidence": 0, "assumptions": 0,
                                          "counters": 0, "errors": 0,
                                          "warnings": 0}, "empty")
    c.ok("Nothing to map" in empty_html, "render handles an empty document")

    return c.report()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def extract_now(argv):
    now = None
    out = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--now":
            if i + 1 >= len(argv):
                fail("--now needs a value")
            now = argv[i + 1]
            i += 2
            continue
        if a.startswith("--now="):
            now = a.split("=", 1)[1]
            i += 1
            continue
        out.append(a)
        i += 1
    return now, out


def build_parser():
    p = argparse.ArgumentParser(prog="argue", description="Map and check an argument.")
    p.add_argument("--version", action="version", version="%s %s" % (TOOL, VERSION))

    sub = p.add_subparsers(dest="command")

    def add(name, help_):
        sp = sub.add_parser(name, help=help_)
        sp.add_argument("--store", default=None)
        sp.add_argument("--version", action="version",
                        version="%s %s" % (TOOL, VERSION))
        return sp

    sp = add("check", "Check an argument file for structural problems.")
    sp.add_argument("doc")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--strict", action="store_true",
                    help="treat warnings as failures")

    sp = add("graph", "Print the nodes and edges.")
    sp.add_argument("doc")
    sp.add_argument("--json", action="store_true")

    sp = add("render", "Write a self-contained HTML map of the argument.")
    sp.add_argument("doc")
    sp.add_argument("--out", required=True)
    sp.add_argument("--title", default=None)

    sp = add("review", "Analyse a document and record it in the review ledger.")
    sp.add_argument("doc")
    sp.add_argument("--note", default="")

    sp = add("history", "List recorded reviews.")
    sp.add_argument("--json", action="store_true")

    sp = add("verify", "Verify the review ledger hash chain.")
    sp.add_argument("--json", action="store_true")

    add("selftest", "Run the built-in checks.")
    return p


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    now, argv = extract_now(argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_usage(sys.stderr)
        return 2
    store = resolve_store(getattr(args, "store", None))
    try:
        if args.command == "check":
            return cmd_check(args.doc, args.json, args.strict)
        if args.command == "graph":
            return cmd_graph(args.doc, args.json)
        if args.command == "render":
            return cmd_render(args.doc, args.out, args.title)
        if args.command == "review":
            return cmd_review(args.doc, args.note, store, now)
        if args.command == "history":
            return cmd_history(args.json, store)
        if args.command == "verify":
            return cmd_verify(args.json, store)
        if args.command == "selftest":
            return cmd_selftest()
        fail("unknown command %r" % args.command)
    except ArgueError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
