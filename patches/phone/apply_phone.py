"""Phone-only changes to a youtube/cobalt 25.lts checkout (used ONLY by
build-android-phone.yml; the TV build never runs this).

1. User-Agent: Cobalt normally says "Cobalt/25 ... Starboard", which makes YouTube
   serve its TV/desktop pages. Phones need the mobile site (m.youtube.com), so the
   phone build reports a standard Android Chrome mobile User-Agent instead (Chrome's
   reduced format: no real device model or exact version is sent).

Usage: python3 apply_phone.py <cobalt checkout>
"""
import os
import sys

root = sys.argv[1]

UA = ("Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36")


def patch(rel, old, new):
    path = os.path.join(root, rel)
    with open(path, encoding="utf-8", newline="") as f:
        text = f.read()
    if text.count(old) != 1:
        sys.exit("phone patch: expected text found %d times in %s" % (text.count(old), rel))
    with open(path, "w", encoding="utf-8", newline="") as f:
        f.write(text.replace(old, new))
    print("phone patch:", rel)


patch(
    "cobalt/browser/user_agent_string.cc",
    "std::string CreateUserAgentString(const UserAgentPlatformInfo& platform_info) {\n",
    "std::string CreateUserAgentString(const UserAgentPlatformInfo& platform_info) {\n"
    "  // GoldenBoot phone build: mobile Chrome User-Agent, so sites serve their\n"
    "  // phone pages (m.youtube.com) instead of TV/desktop ones.\n"
    "  if (true) return \"" + UA + "\";\n",
)
