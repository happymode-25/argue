"""End-to-end tests for argue.

These drive the real CLI as a subprocess, so they cover the class of bug
unit-level checks cannot see: a flag that never reaches the code, a wrong exit
code, a store that cannot be written, a render that emits a broken document.

    python tests/test_argue.py
    python -m unittest tests.test_argue
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOL = ROOT / "argue.py"

CLEAN = """\
C1: claim: c
E1: evidence: e
X1: counter: x
E1 -> C1
X1 -> C1 : attacks
"""

WITH_ERROR = """\
C1: claim: c
E1: evidence: e
"""

WARN_ONLY = """\
C1: claim: c
E1: evidence: e
E1 -> C1
"""


def run(sub, *args, store=None, stdin=None):
    cmd = [sys.executable, str(TOOL), sub] + [str(a) for a in args]
    if store is not None:
        cmd += ["--store", str(store)]
    env = dict(os.environ)
    env.pop("ARGUE_STORE", None)
    return subprocess.run(cmd, capture_output=True, text=True, input=stdin,
                          env=env, timeout=300)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        self.store = self.dir / "ledger.jsonl"

    def tearDown(self):
        self.tmp.cleanup()

    def doc(self, text, name="a.arg"):
        p = self.dir / name
        p.write_text(text, encoding="utf-8")
        return p


class TestCheck(Base):
    def test_clean_exits_zero(self):
        p = self.doc(CLEAN)
        proc = run("check", p)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("no findings", proc.stdout)

    def test_error_exits_one(self):
        p = self.doc(WITH_ERROR)
        proc = run("check", p)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("unsupported-claim", proc.stdout)

    def test_warn_only_exits_zero(self):
        p = self.doc(WARN_ONLY)
        self.assertEqual(run("check", p).returncode, 0)

    def test_warn_only_strict_exits_one(self):
        p = self.doc(WARN_ONLY)
        self.assertEqual(run("check", p, "--strict").returncode, 1)

    def test_parse_error_exits_two(self):
        p = self.doc("C1: bogus: x")
        proc = run("check", p)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("unknown kind", proc.stderr)

    def test_missing_file_exits_two(self):
        proc = run("check", self.dir / "nope.arg")
        self.assertEqual(proc.returncode, 2)

    def test_json_shape(self):
        p = self.doc(CLEAN)
        data = json.loads(run("check", p, "--json").stdout)
        self.assertEqual(sorted(data), ["document", "edges", "findings", "nodes", "summary"])
        self.assertEqual(data["summary"]["claims"], 1)

    def test_json_findings_named(self):
        p = self.doc(WITH_ERROR)
        data = json.loads(run("check", p, "--json").stdout)
        self.assertIn("unsupported-claim", [f["rule"] for f in data["findings"]])

    def test_reports_load_bearing_claim(self):
        p = self.doc(CLEAN)
        self.assertIn("load-bearing claim: C1", run("check", p).stdout)

    def test_reads_stdin(self):
        proc = run("check", "-", stdin=CLEAN)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("no findings", proc.stdout)

    def test_cyclic_argument_is_an_error(self):
        p = self.doc("P: claim: p\nQ: claim: q\nP -> Q\nQ -> P\n")
        self.assertEqual(run("check", p).returncode, 1)
        self.assertIn("cyclic-support", run("check", p).stdout)


class TestGraph(Base):
    def test_graph_lists_nodes_and_edges(self):
        p = self.doc(CLEAN)
        out = run("graph", p).stdout
        self.assertIn("C1", out)
        self.assertIn("E1 -> C1", out)

    def test_graph_json(self):
        p = self.doc(CLEAN)
        data = json.loads(run("graph", p, "--json").stdout)
        self.assertEqual(len(data["nodes"]), 3)
        self.assertEqual(len(data["edges"]), 2)

    def test_graph_parse_error_exits_two(self):
        p = self.doc("nonsense")
        self.assertEqual(run("graph", p).returncode, 2)


class TestRender(Base):
    def test_render_writes_file(self):
        p = self.doc(CLEAN)
        out = self.dir / "map.html"
        proc = run("render", p, "--out", out)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertTrue(out.exists())

    def test_render_is_self_contained(self):
        p = self.doc(CLEAN)
        out = self.dir / "map.html"
        run("render", p, "--out", out)
        html = out.read_text(encoding="utf-8")
        self.assertIn("<svg", html)
        self.assertNotIn("http://", html)
        self.assertNotIn("https://", html)
        self.assertNotIn("<script", html)

    def test_render_broken_argument_still_writes_and_exits_zero(self):
        p = self.doc(WITH_ERROR)
        out = self.dir / "map.html"
        proc = run("render", p, "--out", out)
        self.assertEqual(proc.returncode, 0)
        self.assertTrue(out.exists())
        self.assertIn("unsupported-claim", out.read_text(encoding="utf-8"))

    def test_render_title(self):
        p = self.doc(CLEAN)
        out = self.dir / "map.html"
        run("render", p, "--out", out, "--title", "My Argument")
        self.assertIn("My Argument", out.read_text(encoding="utf-8"))

    def test_render_empty_argument(self):
        p = self.doc("")
        out = self.dir / "map.html"
        run("render", p, "--out", out)
        self.assertIn("Nothing to map", out.read_text(encoding="utf-8"))


class TestReviewLedger(Base):
    def test_review_appends_and_reports_seq(self):
        p = self.doc(CLEAN)
        proc = run("review", p, "--note", "first", store=self.store)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("recorded as seq 0", proc.stdout)

    def test_review_records_doc_hash(self):
        p = self.doc(CLEAN)
        run("review", p, store=self.store)
        rec = json.loads(self.store.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(len(rec["doc_hash"]), 64)
        self.assertEqual(rec["kind"], "review")

    def test_second_review_is_seq_one(self):
        p = self.doc(CLEAN)
        run("review", p, store=self.store)
        proc = run("review", p, store=self.store)
        self.assertIn("recorded as seq 1", proc.stdout)

    def test_history_lists_reviews(self):
        p = self.doc(WITH_ERROR)
        run("review", p, "--note", "bad doc", store=self.store)
        out = run("history", store=self.store).stdout
        self.assertIn("bad doc", out)

    def test_history_json(self):
        p = self.doc(CLEAN)
        run("review", p, store=self.store)
        data = json.loads(run("history", "--json", store=self.store).stdout)
        self.assertEqual(len(data), 1)

    def test_history_empty(self):
        proc = run("history", store=self.store)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("no reviews", proc.stdout)

    def test_review_deterministic_timestamp(self):
        p = self.doc(CLEAN)
        run("review", p, "--now", "2026-01-01T00:00:00", store=self.store)
        rec = json.loads(self.store.read_text(encoding="utf-8").splitlines()[0])
        self.assertEqual(rec["ts"], "2026-01-01T00:00:00")


class TestVerify(Base):
    def _seed(self, n=2):
        p = self.doc(CLEAN)
        for _ in range(n):
            run("review", p, store=self.store)

    def test_verify_clean(self):
        self._seed()
        proc = run("verify", store=self.store)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("chain intact", proc.stdout)

    def test_verify_empty(self):
        proc = run("verify", store=self.store)
        self.assertEqual(proc.returncode, 0)

    def test_verify_detects_edit(self):
        self._seed()
        text = self.store.read_text(encoding="utf-8").replace('"errors":0', '"errors":9')
        self.store.write_text(text, encoding="utf-8")
        proc = run("verify", store=self.store)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("hash", proc.stdout.lower())

    def test_verify_detects_deleted_middle(self):
        self._seed(3)
        lines = self.store.read_text(encoding="utf-8").splitlines()
        del lines[1]
        self.store.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.assertEqual(run("verify", store=self.store).returncode, 1)

    def test_verify_json(self):
        self._seed()
        data = json.loads(run("verify", "--json", store=self.store).stdout)
        self.assertTrue(data["ok"])
        self.assertEqual(data["problems"], [])


class TestCLI(Base):
    def test_version(self):
        proc = run("--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("argue", proc.stdout)

    def test_subcommand_version(self):
        proc = run("check", "--version")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("1.0.0", proc.stdout)

    def test_help(self):
        self.assertEqual(run("--help").returncode, 0)

    def test_unknown_command_exits_two(self):
        proc = subprocess.run([sys.executable, str(TOOL), "frobnicate"],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)

    def test_no_command_exits_two(self):
        proc = subprocess.run([sys.executable, str(TOOL)],
                              capture_output=True, text=True)
        self.assertEqual(proc.returncode, 2)

    def test_selftest_passes(self):
        proc = run("selftest")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("all checks passed", proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
