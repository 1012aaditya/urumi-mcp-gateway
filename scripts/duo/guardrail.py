#!/usr/bin/env python3
"""Guardrails that learn from incidents (!54; docs/adr/016-learned-guardrails.md). Stdlib only.

After a canary incident is healed, the files the fix had to touch are, by evidence, places where a
change broke production. This script proposes to make every later change to those files high-risk,
so it needs a person's approval (`release:human-approval`) before it is released. It never changes
`main` itself: it opens a merge request, and that MR edits CI files, so the risk gate classifies it
high-risk and a person must approve and merge it. Guardrails are only ever *added*.

  guardrail.py from-release --record verdict.json
      Default-branch pipelines, after `canary` released the commit (PROMOTE or
      PROMOTE_PENDING_APPROVAL): for each merged `autoheal` MR of CI_COMMIT_SHA, learn from its
      incident. Job duo:guardrail-learn.
  guardrail.py learn <incident_iid>
      Learn from one canary incident whose fix MR (labelled `autoheal`, titled
      "... (incident #<iid>)") is merged.
  guardrail.py backfill
      Back-fill incidents healed before this existed: the most recent resolved canary incident
      with no guardrail MR yet (one per run, newest first, up to BACKFILL_SCAN looked at). Manual
      job duo:guardrail-backfill on main (pipeline variables are maintainer-only here).

Learning = the fix MR's changed files that no existing rule covers, at most MAX_NEW paths, each
an exact path (no globs: a guardrail should be no wider than the evidence), never under
scripts/canary/, .gitlab/ or charts/ (already guarded or out of scope). The MR updates the three
places that state the rules and must agree (.gitlab/flows/tests/flows.test.sh):
  scripts/canary/risk.py            RULES                        (what CI enforces)
  .gitlab/ci/canary.gitlab-ci.yml   release:human-approval rules:changes, MR and main rules
  .gitlab/flows/risk-gate.yaml      the risk-gate prompt's RULES table (re-paste the flow after merge)
One branch per incident (guardrail/incident-<iid>); if its MR exists, nothing to do.

Env as scripts/duo/dispatch.py (DUO_DISPATCH_TOKEN never printed; without it: one line, exit 0).
Exit 0 = done or nothing to do, 1 = API or config error, 2 = bad arguments.
"""

from __future__ import annotations

import argparse
import base64
import os
import re
import sys
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "canary"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dispatch  # noqa: E402  (same directory)
import risk  # noqa: E402  (scripts/canary/risk.py)
from dispatch import Api, DispatchError, positive_int  # noqa: E402

RISK_PY = "scripts/canary/risk.py"
CANARY_CI = ".gitlab/ci/canary.gitlab-ci.yml"
RISK_FLOW = ".gitlab/flows/risk-gate.yaml"
MAX_NEW = 3
BACKFILL_SCAN = 20
EXCLUDED = ("scripts/canary/", ".gitlab/", "charts/", ".gitlab-ci.yml")
_SAFE_PATH = re.compile(r"^[A-Za-z0-9._/@+-]{1,200}$")
LEARNED_HEADER = "    # Learned from incidents (scripts/duo/guardrail.py). Exact paths, one incident each."
CI_ANCHOR = "        - .gitlab/ci/**/*\n"
FLOW_ANCHOR_RE = re.compile(r"^( +)\.gitlab/ci/\*\*/\* +CI pipeline definition\n", re.M)
FLOW_LAST_RULE_RE = re.compile(r"^( +)[^ \n]+ {2,}[^\n]*\n(?= +Risk is \"high\")", re.M)


# --- pure edits (unit-tested) -----------------------------------------------------------------


def candidates(paths: list[str]) -> tuple[list[str], list[str]]:
    """(new paths to guard, reasons for the ones skipped)."""
    new, skipped = [], []
    for p in sorted({p.strip() for p in paths if isinstance(p, str) and p.strip()}):
        if not _SAFE_PATH.match(p) or ".." in p.split("/"):
            skipped.append(f"{p[:60]!r}: unsafe path")
        elif p.startswith(EXCLUDED):
            skipped.append(f"{p}: CI, chart and canary files are out of scope")
        elif risk.classify([p])["risk"] == "high":
            skipped.append(f"{p}: already high-risk ({risk.classify([p])['matches'][0]['glob']})")
        else:
            new.append(p)
    if len(new) > MAX_NEW:
        skipped += [f"{p}: over the limit of {MAX_NEW} new paths per incident" for p in new[MAX_NEW:]]
        new = new[:MAX_NEW]
    return new, skipped


def why_text(incident: int) -> str:
    return f"learned: incident #{incident}"


def edit_risk_py(text: str, paths: list[str], incident: int) -> str:
    start = text.index("RULES: list[tuple[str, str]] = [\n")
    end = text.index("\n]\n", start)
    body = text[start:end]
    lines = [f'    ("{p}", "{why_text(incident)}"),' for p in paths]
    if LEARNED_HEADER not in body:
        lines.insert(0, LEARNED_HEADER)
    return text[:end] + "\n" + "\n".join(lines) + text[end:]


def edit_canary_ci(text: str, paths: list[str]) -> str:
    """Append the paths after the last glob of each release:human-approval `changes:` list."""
    job = text.index("\nrelease:human-approval:\n")
    head, tail = text[:job], text[job:]
    if tail.count(CI_ANCHOR) != 2:
        raise ValueError("release:human-approval: expected the CI glob in exactly 2 rules")
    out, rest = "", tail
    for _ in range(2):
        i = rest.index(CI_ANCHOR) + len(CI_ANCHOR)
        block, rest = rest[:i], rest[i:]
        while rest.startswith("        - "):  # skip earlier learned paths
            j = rest.index("\n") + 1
            block, rest = block + rest[:j], rest[j:]
        out += block + "".join(f"        - {p}\n" for p in paths)
    return head + out + rest


def edit_flow(text: str, paths: list[str], incident: int) -> str:
    m = FLOW_LAST_RULE_RE.search(text)
    if not m or not FLOW_ANCHOR_RE.search(text):
        raise ValueError("risk-gate prompt: RULES table not found")
    indent = m.group(1)
    rows = "".join(f"{indent}{p.ljust(33)}  {why_text(incident)}\n" for p in paths)
    return text[: m.end()] + rows + text[m.end():]


def mr_description(incident: int, fix_iid: int, paths: list[str], skipped: list[str]) -> str:
    rows = "\n".join(f"| `{p}` | incident #{incident}, fixed by !{fix_iid} |" for p in paths)
    skip = "\n".join(f"- {s}" for s in skipped) or "- none"
    return (
        f"Incident: #{incident}\n\n"
        "## Guardrail learned from an incident\n\n"
        f"Incident #{incident} was healed by !{fix_iid}. The files that fix had to change broke a "
        "release once, so from now on **any change to them is high-risk**: the risk gate flags it, "
        "and the release waits at `release:human-approval` for a person.\n\n"
        "| Newly guarded path | Evidence |\n| --- | --- |\n" + rows + "\n\n"
        f"Skipped:\n{skip}\n\n"
        "This MR edits CI files, so it is itself high-risk: a person approves and merges it. "
        "Guardrails are only added, never removed, by automation. After merging, re-paste "
        "`.gitlab/flows/risk-gate.yaml` in AI > Flows so the Duo risk gate states the same rules "
        "(CI enforces them either way).\n\n"
        f"guardrail-learn: incident {incident}\n"
    )


# --- GitLab -------------------------------------------------------------------------------------


def raw_file(api: Api, path: str, ref: str) -> str:
    data = api.call("GET", f"/repository/files/{urllib.parse.quote(path, safe='')}", query={"ref": ref})
    if not isinstance(data, dict) or data.get("encoding") != "base64":
        raise DispatchError(f"{path}: unexpected file response")
    return base64.b64decode(data["content"]).decode()


def fix_mr_of(api: Api, incident: int) -> dict | None:
    found = api.call("GET", "/merge_requests", query={
        "state": "merged", "labels": "autoheal", "search": f"(incident #{incident})", "in": "title",
        "per_page": 20})
    mrs = [m for m in found if isinstance(m, dict) and dispatch.incident_iid(m) == incident] \
        if isinstance(found, list) else []
    return mrs[0] if mrs else None


def learn(api: Api, incident: int, fix: dict | None, env: dict) -> str:
    issue = api.call("GET", f"/issues/{incident}")
    title = issue.get("title") if isinstance(issue, dict) else None
    if not isinstance(title, str) or not title.startswith(dispatch.TITLE_PREFIX) \
            or "incident" not in dispatch.labels_of(issue):
        return f"guardrail: #{incident} is not a canary incident; nothing to learn"
    fix = fix or fix_mr_of(api, incident)
    if not fix:
        return f"guardrail: incident #{incident} has no merged autoheal MR; nothing to learn"
    fix_iid = positive_int(fix.get("iid"), "merge request iid")
    branch = f"guardrail/incident-{incident}"
    existing = api.call("GET", "/merge_requests", query={"source_branch": branch, "state": "all"})
    if isinstance(existing, list) and existing:
        return f"guardrail: !{existing[0].get('iid')} already proposes the guardrail for #{incident}"
    changes = api.call("GET", f"/merge_requests/{fix_iid}/changes")
    paths = []
    for c in (changes.get("changes") or []) if isinstance(changes, dict) else []:
        if isinstance(c, dict):
            paths += [c.get("old_path"), c.get("new_path")]
    new, skipped = candidates(paths)
    if not new:
        return f"guardrail: incident #{incident} (fix !{fix_iid}): nothing new to guard ({'; '.join(skipped)})"
    ref = env.get("CI_DEFAULT_BRANCH") or "main"
    files = {
        RISK_PY: edit_risk_py(raw_file(api, RISK_PY, ref), new, incident),
        CANARY_CI: edit_canary_ci(raw_file(api, CANARY_CI, ref), new),
        RISK_FLOW: edit_flow(raw_file(api, RISK_FLOW, ref), new, incident),
    }
    api.call("POST", "/repository/commits", {
        "branch": branch, "start_branch": ref,
        "commit_message": f"guardrail: changes to {', '.join(new)} need approval (incident #{incident})",
        "actions": [{"action": "update", "file_path": p, "content": c} for p, c in files.items()]})
    mr = api.call("POST", "/merge_requests", {
        "source_branch": branch, "target_branch": ref, "remove_source_branch": True,
        "title": f"Guardrail: changes to {', '.join(p.rsplit('/', 1)[-1] for p in new)} now need "
                 f"human approval (learned from incident #{incident})",
        "description": mr_description(incident, fix_iid, new, skipped),
        "labels": "guardrail,risk::high"})
    mr_iid = mr.get("iid") if isinstance(mr, dict) else "?"
    api.call("POST", f"/issues/{incident}/notes", {"body": (
        f"Guardrail proposed in !{mr_iid}: after this incident, changes to "
        + ", ".join(f"`{p}`" for p in new)
        + " will need a person's approval before release.\n\n"
        f"guardrail-learn: incident {incident}")})
    return f"guardrail: opened !{mr_iid} guarding {', '.join(new)} (incident #{incident}, fix !{fix_iid})"


def backfill(api: Api, env: dict) -> str:
    found = api.call("GET", "/issues", query={
        "labels": "incident,status::resolved", "state": "closed", "order_by": "created_at",
        "sort": "desc", "per_page": BACKFILL_SCAN})
    issues = [i for i in found if isinstance(i, dict)] if isinstance(found, list) else []
    seen = []
    for issue in issues:
        iid = positive_int(issue.get("iid"), "incident iid")
        msg = learn(api, iid, None, env)
        if msg.startswith("guardrail: opened"):
            return msg
        seen.append(f"#{iid}: {msg.removeprefix('guardrail: ')}")
    return "guardrail: nothing to back-fill" + (" (" + "; ".join(seen) + ")" if seen else "")


def from_release(api: Api, record_path: str, env: dict):
    record, nothing = dispatch.verified_record(record_path, "guardrail")
    if record is None:
        yield nothing
        return
    sha = str(env.get("CI_COMMIT_SHA") or "").strip()
    if not dispatch._SHA.match(sha):
        raise DispatchError(f"commit sha must be 7 to 40 hex digits, got {sha[:40]!r}")
    mrs = api.call("GET", f"/repository/commits/{sha}/merge_requests")
    fixes = [m for m in mrs if isinstance(m, dict) and m.get("state") == "merged"
             and "autoheal" in dispatch.labels_of(m)] if isinstance(mrs, list) else []
    if not fixes:
        yield f"guardrail: no merged autoheal merge request in {sha[:8]}; nothing to learn"
    for mr in fixes:
        iid = dispatch.incident_iid(mr)
        yield (f"guardrail: !{mr.get('iid')} names no incident; skipped" if iid is None
               else learn(api, iid, mr, env))


def main(argv: list[str] | None = None, env: dict | None = None) -> int:
    env = env if env is not None else dict(os.environ)
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    fr = sub.add_parser("from-release", help="learn from the incidents fixed by this released commit")
    fr.add_argument("--record", required=True, help="the canary job's verdict.json")
    ln = sub.add_parser("learn", help="learn from one healed incident")
    ln.add_argument("incident_iid")
    sub.add_parser("backfill", help="learn from the newest resolved incident with no guardrail MR")
    a = p.parse_args(argv)
    token = env.get("DUO_DISPATCH_TOKEN", "")
    if not token.strip():
        print(dispatch.SKIP_NO_TOKEN)
        return 0
    try:
        api = Api(env.get("CI_API_V4_URL", ""), positive_int(env.get("CI_PROJECT_ID"), "CI_PROJECT_ID"), token)
        if a.cmd == "learn":
            print(learn(api, positive_int(a.incident_iid, "incident iid"), None, env))
        elif a.cmd == "backfill":
            print(backfill(api, env))
        else:
            for line in from_release(api, a.record, env):
                print(line, flush=True)
    except (DispatchError, ValueError) as e:
        print(f"guardrail {a.cmd} failed: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
