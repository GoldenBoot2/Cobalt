"""Waits for a GitHub Actions run: checks every 60 s, prints step changes, and stops as soon as
a step fails or the run completes (exit 0 = success, 1 = failure/cancelled). Token never printed.
Usage: python -I -u gh_wait.py <run_id> [seconds]"""
import json, os, sys, time, urllib.request

REPO = "GoldenBoot2/Cobalt"
TOKEN = open(os.path.join(os.path.expanduser("~"), ".claude", "secrets", "github-cobalt-token.txt")).read().strip()
run = sys.argv[1]
every = int(sys.argv[2]) if len(sys.argv) > 2 else 60


def get(path):
    req = urllib.request.Request("https://api.github.com/repos/%s%s" % (REPO, path),
                                 headers={"Authorization": "Bearer " + TOKEN, "Accept": "application/vnd.github+json",
                                          "User-Agent": "cobalt-build"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


seen = {}
errors = 0
while True:
    try:
        r = get("/actions/runs/" + run)
        failed = None
        for j in get("/actions/runs/%s/jobs" % run)["jobs"]:
            for s in j.get("steps", []):
                state = (s["status"], s["conclusion"])
                if seen.get(s["name"]) != state:
                    seen[s["name"]] = state
                    print(time.strftime("%H:%M:%S"), s["name"], s["status"], s["conclusion"] or "", flush=True)
                if s["conclusion"] == "failure":
                    failed = "%s (job %s)" % (s["name"], j["id"])
        errors = 0
        if failed:
            print("STEP FAILED:", failed, flush=True)
            sys.exit(1)
        if r["status"] == "completed":
            print("RUN DONE:", r["conclusion"], flush=True)
            sys.exit(0 if r["conclusion"] == "success" else 1)
    except SystemExit:
        raise
    except Exception as e:
        errors += 1
        print(time.strftime("%H:%M:%S"), "poll error", e, flush=True)
        if errors >= 10:
            sys.exit("too many poll errors")
    time.sleep(every)
