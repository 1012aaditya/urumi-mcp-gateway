"""Unit tests for scripts/duo/guardrail.py (!54). Run: python3 -m unittest discover -s scripts/duo"""

from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path[:0] = [HERE, os.path.join(ROOT, "scripts", "canary")]

import guardrail as g  # noqa: E402
from dispatch import DispatchError  # noqa: E402

LIMITS = "apps/gateway/src/core/zz-test-limits.ts"  # fictional: never a real learned rule
CALL = "apps/gateway/src/core/zz-test-call.ts"


def read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


class Candidates(unittest.TestCase):
    def test_new_paths_only_exact_and_sorted(self):
        new, skipped = g.candidates([LIMITS, CALL, LIMITS, "", None])
        self.assertEqual(new, [CALL, LIMITS])
        self.assertEqual(skipped, [])

    def test_already_guarded_out_of_scope_and_unsafe_are_skipped(self):
        new, skipped = g.candidates([
            "apps/gateway/src/auth/session.ts", ".gitlab/ci/x.yml", "charts/platform/a.yaml",
            "scripts/canary/verdict.py", "../etc/passwd", "a b.ts", "x\ny"])
        self.assertEqual(new, [])
        self.assertEqual(len(skipped), 7)
        self.assertTrue(any("already high-risk" in s for s in skipped))
        self.assertTrue(any("unsafe" in s for s in skipped))

    def test_at_most_max_new(self):
        paths = [f"apps/dashboard/src/f{i}.ts" for i in range(5)]
        new, skipped = g.candidates(paths)
        self.assertEqual(len(new), g.MAX_NEW)
        self.assertEqual(len(skipped), 5 - g.MAX_NEW)


class Edits(unittest.TestCase):
    """The three rule statements stay identical and in order after an edit (flows.test.sh rule)."""

    def apply(self, paths, incident, texts=None):
        texts = texts or {p: read(p) for p in (g.RISK_PY, g.CANARY_CI, g.RISK_FLOW)}
        return {
            g.RISK_PY: g.edit_risk_py(texts[g.RISK_PY], paths, incident),
            g.CANARY_CI: g.edit_canary_ci(texts[g.CANARY_CI], paths),
            g.RISK_FLOW: g.edit_flow(texts[g.RISK_FLOW], paths, incident),
        }

    def globs(self, texts):
        import re
        src = texts[g.RISK_PY]
        body = src[src.index("RULES: list"):src.index("\n]\n", src.index("RULES: list"))]
        py = re.findall(r'(?m)^    \("([^"]+)", "', body)
        ci = texts[g.CANARY_CI]
        job = ci[ci.index("\nrelease:human-approval:\n"):]
        lists = []
        for part in job.split("changes:\n")[1:3]:
            lines = []
            for line in part.splitlines():
                if not line.startswith("        - "):
                    break
                lines.append(line[len("        - "):])
            lists.append(lines)
        import re
        flow = texts[g.RISK_FLOW]
        table = flow[flow.index("`**/` matches zero or more directories:"):flow.index('Risk is "high"')]
        rows = re.findall(r"(?m)^ +([^ \n]+) {2,}", table)
        return py, lists, rows

    def test_first_incident_appends_everywhere_in_the_same_order(self):
        texts = self.apply([CALL, LIMITS], 36)
        py, (mr_rule, main_rule), flow = self.globs(texts)
        self.assertEqual(py[-2:], [CALL, LIMITS])
        self.assertEqual(py, mr_rule)
        self.assertEqual(py, main_rule)
        self.assertEqual(py, flow)
        self.assertIn(f'("{LIMITS}", "learned: incident #36")', texts[g.RISK_PY])
        self.assertEqual(texts[g.RISK_PY].count(g.LEARNED_HEADER), 1)

    def test_second_incident_appends_after_the_first(self):
        first = self.apply([LIMITS], 36)
        second = self.apply(["apps/woo-mcp/src/woo-client.ts"], 41, texts=first)
        py, (mr_rule, main_rule), flow = self.globs(second)
        self.assertEqual(py[-2:], [LIMITS, "apps/woo-mcp/src/woo-client.ts"])
        self.assertEqual((py, py, py), (mr_rule, main_rule, flow))
        self.assertEqual(second[g.RISK_PY].count(g.LEARNED_HEADER), 1)

    def test_edited_risk_py_classifies_the_learned_path_high(self):
        texts = self.apply([LIMITS], 36)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "risk_learned.py")
            with open(path, "w", encoding="utf-8") as f:
                f.write(texts[g.RISK_PY])
            import importlib.util
            spec = importlib.util.spec_from_file_location("risk_learned", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            r = mod.classify([LIMITS])
            self.assertEqual(r["risk"], "high")
            self.assertIn("learned: incident #36", r["reasons"][0])
            self.assertEqual(mod.classify(["apps/gateway/src/core/registry.ts"])["risk"], "low")

    def test_ci_edit_refuses_an_unexpected_file(self):
        with self.assertRaises(ValueError):
            g.edit_canary_ci("release:human-approval:\n  script: []\n", [LIMITS])


class FakeApi:
    def __init__(self, routes):
        self.routes, self.calls = routes, []

    def call(self, method, path, body=None, query=None):
        self.calls.append((method, path, body, query))
        for (m, p), resp in self.routes.items():
            if m == method and p == path:
                return resp(body, query) if callable(resp) else resp
        raise DispatchError(f"unexpected {method} {path}")


def file_resp(rel):
    return {"encoding": "base64", "content": base64.b64encode(read(rel).encode()).decode()}


INCIDENT = {"iid": 36, "title": "Incident: canary rolled back f60f974e (pipeline 2973902229)",
            "labels": ["incident", "status::resolved"], "state": "closed"}
FIX = {"iid": 40, "state": "merged", "labels": ["autoheal"],
       "title": "Autoheal: 4 KB cap on paginated tool results fails woo__list_orders (incident #36)",
       "description": "Incident: #36\n\n..."}


def routes(existing=()):
    q = lambda p: "/repository/files/" + p.replace("/", "%2F")  # noqa: E731
    return {
        ("GET", "/issues/36"): INCIDENT,
        ("GET", "/merge_requests"): lambda b, query: list(existing) if "source_branch" in query else [FIX],
        ("GET", "/merge_requests/40/changes"): {"changes": [
            {"old_path": CALL, "new_path": CALL}, {"old_path": LIMITS, "new_path": LIMITS}]},
        ("GET", q(g.RISK_PY)): file_resp(g.RISK_PY),
        ("GET", q(g.CANARY_CI)): file_resp(g.CANARY_CI),
        ("GET", q(g.RISK_FLOW)): file_resp(g.RISK_FLOW),
        ("POST", "/repository/commits"): {"id": "abc"},
        ("POST", "/merge_requests"): {"iid": 55},
        ("POST", "/issues/36/notes"): {"id": 1},
    }


class Learn(unittest.TestCase):
    def test_backfill_opens_one_mr_with_three_files_and_notes_the_incident(self):
        api = FakeApi(routes())
        msg = g.learn(api, 36, None, {"CI_DEFAULT_BRANCH": "main"})
        self.assertEqual(msg, f"guardrail: opened !55 guarding {CALL}, {LIMITS} (incident #36, fix !40)")
        commit = next(c for c in api.calls if c[1] == "/repository/commits")[2]
        self.assertEqual((commit["branch"], commit["start_branch"]), ("guardrail/incident-36", "main"))
        self.assertEqual(sorted(a["file_path"] for a in commit["actions"]),
                         sorted([g.RISK_PY, g.CANARY_CI, g.RISK_FLOW]))
        mr = next(c for c in api.calls if c[0] == "POST" and c[1] == "/merge_requests")[2]
        self.assertIn("learned from incident #36", mr["title"])
        self.assertTrue(mr["description"].startswith("Incident: #36\n"))
        self.assertIn("guardrail,risk::high", mr["labels"])
        note = next(c for c in api.calls if c[1] == "/issues/36/notes")[2]["body"]
        self.assertIn("!55", note)

    def test_existing_mr_means_nothing_to_do(self):
        api = FakeApi(routes(existing=[{"iid": 55}]))
        self.assertIn("already proposes", g.learn(api, 36, None, {}))
        self.assertFalse(any(c[0] == "POST" for c in api.calls))

    def test_not_an_incident(self):
        r = routes()
        r[("GET", "/issues/36")] = {"iid": 36, "title": "Some issue", "labels": []}
        api = FakeApi(r)
        self.assertIn("not a canary incident", g.learn(api, 36, None, {}))
        self.assertFalse(any(c[0] == "POST" for c in api.calls))

    def test_nothing_new_to_guard(self):
        r = routes()
        r[("GET", "/merge_requests/40/changes")] = {"changes": [
            {"old_path": "apps/gateway/src/auth/session.ts", "new_path": "apps/gateway/src/auth/session.ts"}]}
        api = FakeApi(r)
        self.assertIn("nothing new to guard", g.learn(api, 36, None, {}))
        self.assertFalse(any(c[0] == "POST" for c in api.calls))


class Backfill(unittest.TestCase):
    def test_newest_resolved_incident_without_a_guardrail_mr(self):
        r = routes()
        r[("GET", "/issues")] = [{"iid": 36}, {"iid": 30}]
        api = FakeApi(r)
        self.assertIn("opened !55", g.backfill(api, {}))
        self.assertEqual(sum(1 for c in api.calls if c[1] == "/repository/commits"), 1)

    def test_all_done_means_nothing_to_backfill(self):
        r = routes(existing=[{"iid": 55}])
        r[("GET", "/issues")] = [{"iid": 36}]
        api = FakeApi(r)
        self.assertIn("nothing to back-fill", g.backfill(api, {}))
        self.assertFalse(any(c[0] == "POST" for c in api.calls))


class FromRelease(unittest.TestCase):
    def record(self, decision):
        f = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
        json.dump({"decision": decision, "ci": {}}, f)
        f.close()
        self.addCleanup(os.unlink, f.name)
        return f.name

    def test_rollback_learns_nothing(self):
        api = FakeApi({})
        out = list(g.from_release(api, self.record("ROLLBACK"), {"CI_COMMIT_SHA": "a" * 40}))
        self.assertIn("not PROMOTE", out[0])
        self.assertEqual(api.calls, [])

    def test_promote_learns_from_each_merged_autoheal_mr(self):
        r = routes()
        r[("GET", "/repository/commits/" + "a" * 40 + "/merge_requests")] = [FIX, {"iid": 9, "state": "merged", "labels": []}]
        api = FakeApi(r)
        out = list(g.from_release(api, self.record("PROMOTE"), {"CI_COMMIT_SHA": "a" * 40}))
        self.assertEqual(len(out), 1)
        self.assertIn("opened !55", out[0])


class Main(unittest.TestCase):
    def test_no_token_is_a_noop(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self.assertEqual(g.main(["learn", "36"], env={}), 0)
        self.assertIn("DUO_DISPATCH_TOKEN not set", buf.getvalue())

    def test_bad_iid_fails_cleanly(self):
        err = io.StringIO()
        env = {"DUO_DISPATCH_TOKEN": "t", "CI_API_V4_URL": "https://gitlab.example/api/v4", "CI_PROJECT_ID": "1"}
        with contextlib.redirect_stderr(err):
            self.assertEqual(g.main(["learn", "x1"], env=env), 1)
        self.assertIn("incident iid must be a positive integer", err.getvalue())
        self.assertNotIn("'t'", err.getvalue())


if __name__ == "__main__":
    unittest.main()
