"""GitHub Actions helper for GoldenBoot2/Cobalt. Token read from ~/.claude/secrets/github-cobalt-token.txt, never printed.
Usage:
  python -I gh_actions.py run [ref] [config]     start the build
  python -I gh_actions.py status                 latest runs + job steps
  python -I gh_actions.py log <job_id> [lines]   tail of a job log
  python -I gh_actions.py artifacts <run_id>     list artifacts
  python -I gh_actions.py download <artifact_id> <out.zip>
"""
import json, os, sys, urllib.request, urllib.error

REPO = "GoldenBoot2/Cobalt"
WF = "build-android-arm.yml"
TOKEN = open(os.path.join(os.path.expanduser("~"), ".claude", "secrets", "github-cobalt-token.txt")).read().strip()
API = "https://api.github.com/repos/" + REPO


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def fetch_redirected(path):
    """Logs/artifacts redirect to blob storage, which must NOT get the GitHub token."""
    req = urllib.request.Request(API + path, headers={"Authorization": "Bearer " + TOKEN, "User-Agent": "cobalt-build",
                                                      "Accept": "application/vnd.github+json"})
    try:
        urllib.request.build_opener(_NoRedirect).open(req, timeout=60)
        sys.exit("expected a redirect")
    except urllib.error.HTTPError as e:
        if e.code not in (301, 302, 303, 307, 308):
            sys.exit("HTTP %s: %s" % (e.code, e.read().decode(errors="replace")[:400]))
        loc = e.headers["Location"]
    with urllib.request.urlopen(urllib.request.Request(loc, headers={"User-Agent": "cobalt-build"}), timeout=600) as r:
        return r.read()


def call(path, data=None, raw=False):
    req = urllib.request.Request(API + path, data=json.dumps(data).encode() if data is not None else None,
                                 method="POST" if data is not None else "GET",
                                 headers={"Authorization": "Bearer " + TOKEN, "Accept": "application/vnd.github+json",
                                          "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "cobalt-build"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            b = r.read()
            return b if raw else (json.loads(b) if b else {"status": r.status})
    except urllib.error.HTTPError as e:
        sys.exit("HTTP %s: %s" % (e.code, e.read().decode(errors="replace")[:400]))


cmd = sys.argv[1]
if cmd == "run":
    ref = sys.argv[2] if len(sys.argv) > 2 else "25.lts.40"
    cfg = sys.argv[3] if len(sys.argv) > 3 else "gold"
    print(call("/actions/workflows/%s/dispatches" % WF, {"ref": "main", "inputs": {"cobalt_ref": ref, "config": cfg}}))
elif cmd == "status":
    for r in call("/actions/runs?per_page=3")["workflow_runs"]:
        print("run", r["id"], r["status"], r["conclusion"], r["created_at"], r["updated_at"])
        for j in call("/actions/runs/%d/jobs" % r["id"])["jobs"]:
            print("  job", j["id"], j["status"], j["conclusion"])
            for s in j.get("steps", []):
                print("    %-32s %-11s %-9s %s -> %s" % (s["name"][:32], s["status"], s["conclusion"], (s["started_at"] or "")[11:19], (s["completed_at"] or "")[11:19]))
elif cmd == "log":
    n = int(sys.argv[3]) if len(sys.argv) > 3 else 60
    text = fetch_redirected("/actions/jobs/%s/logs" % sys.argv[2]).decode(errors="replace")
    print("\n".join(text.splitlines()[-n:]))
elif cmd == "artifacts":
    for a in call("/actions/runs/%s/artifacts" % sys.argv[2])["artifacts"]:
        print(a["id"], a["name"], a["size_in_bytes"], a["expired"])
elif cmd == "download":
    data = fetch_redirected("/actions/artifacts/%s/zip" % sys.argv[2])
    open(sys.argv[3], "wb").write(data)
    print("saved", len(data))
