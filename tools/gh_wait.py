"""Waits for a GitHub Actions run to finish (polls every 5 min), printing step changes. Token never printed.
Usage: python -I -u gh_wait.py <run_id>"""
import json, os, sys, time, urllib.request

REPO = "GoldenBoot2/Cobalt"
TOKEN = open(os.path.join(os.path.expanduser("~"), ".claude", "secrets", "github-cobalt-token.txt")).read().strip()
run = sys.argv[1]


def get(path):
    req = urllib.request.Request("https://api.github.com/repos/%s%s" % (REPO, path),
                                 headers={"Authorization": "Bearer " + TOKEN, "Accept": "application/vnd.github+json",
                                          "User-Agent": "cobalt-build"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


seen = {}
while True:
    try:
        r = get("/actions/runs/" + run)
        for j in get("/actions/runs/%s/jobs" % run)["jobs"]:
            for s in j.get("steps", []):
                state = (s["status"], s["conclusion"])
                if seen.get(s["name"]) != state:
                    seen[s["name"]] = state
                    print(time.strftime("%H:%M:%S"), s["name"], s["status"], s["conclusion"] or "", flush=True)
        if r["status"] == "completed":
            print("RUN DONE:", r["conclusion"], flush=True)
            break
    except Exception as e:
        print("poll error", e, flush=True)
    time.sleep(300)
