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



# 2. Debug channel (phone only): YouTube's mobile script URLs are ~400 characters, which filled the whole
#    report before line:column. Put line:column first, keep only the URL's end, shorten URLs in stacks,
#    and keep longer reports.
patch("cobalt/network/adguard_engine.cc",
      "(e&&e.filename)+':'+(e&&e.lineno)+':'+(e&&e.colno)",
      "(e&&e.lineno)+':'+(e&&e.colno)+' '+String(e&&e.filename).slice(-60)")
patch("cobalt/network/adguard_engine.cc",
      "String(e.stack||'').slice(0,300)",
      "String(e.stack||'').replace(/https?:[^ )]+?(:[0-9]+:[0-9]+)/g,'$1').slice(0,500)")
patch("cobalt/network/adguard_engine.cc",
      "encodeURIComponent(String(m).slice(0,400))",
      "encodeURIComponent(String(m).slice(0,700))")
patch("cobalt/network/adguard_filter.cc",
      "if (q.size() > 600) q.resize(600);",
      "if (q.size() > 1500) q.resize(1500);")

# 3. CSS.supports with ONE argument ("selector(:has(*))", "(display: grid)") is newer than Cobalt, which only
#    takes (property, value) and throws "Invalid number of arguments". YouTube's mobile base script calls it
#    at startup (pqa), so the whole page stopped (black screen). Shim: one argument -> selector test or
#    split into property/value; unknown -> false. Runs first in the page script's polyfills.
#    (No double quotes or backslashes: this text goes inside a C string.)
CSS_SUPPORTS_SHIM = (
    "try{(function(){var C=window.CSS,S=C&&C.supports;if(!S)return;"
    "var f=function(p,v){if(arguments.length>1)return S.call(C,p,v);var s=String(p).trim();"
    "if(s.indexOf('selector(')===0&&s.charAt(s.length-1)===')'){"
    "try{document.querySelector(s.slice(9,-1));return true;}catch(e){return false;}}"
    "if(s.charAt(0)==='('&&s.charAt(s.length-1)===')')s=s.slice(1,-1);"
    "var i=s.indexOf(':');if(i<1)return false;"
    "try{return S.call(C,s.slice(0,i).trim(),s.slice(i+1).trim());}catch(e){return false;}};"
    "try{C.supports=f;}catch(e){}"
    "if(C.supports!==f){try{Object.defineProperty(C,'supports',{value:f,configurable:true,writable:true});}catch(e){}}"
    "if(C.supports!==f&&typeof gbr==='function')gbr('css.supports shim not applied');"
    "})();}catch(e){}"
)
assert '"' not in CSS_SUPPORTS_SHIM and '\\' not in CSS_SUPPORTS_SHIM
with open(os.path.join(root, "cobalt/network/adguard_engine.cc"), encoding="utf-8", newline="") as _f:
    NL = "\r\n" if "const char kPolyfills[] =\r\n" in _f.read() else "\n"   # the engine keeps CRLF
patch("cobalt/network/adguard_engine.cc",
      "const char kPolyfills[] =" + NL,
      "const char kPolyfills[] =" + NL + "    \"" + CSS_SUPPORTS_SHIM + "\\n\"" + NL)

# Cobalt builds with -Werror,-Wunreachable-code, so no early return: CreateUserAgentString now only
# returns the phone string, and Cobalt's own builder is kept under another name (declared first, so
# -Wmissing-prototypes stays quiet; external linkage, so no unused-function warning).
patch(
    "cobalt/browser/user_agent_string.cc",
    "std::string CreateUserAgentString(const UserAgentPlatformInfo& platform_info) {\n",
    "std::string CobaltUserAgentString(const UserAgentPlatformInfo& platform_info);\n"
    "\n"
    "// GoldenBoot phone build: mobile Chrome User-Agent, so sites serve their\n"
    "// phone pages (m.youtube.com) instead of TV/desktop ones.\n"
    "std::string CreateUserAgentString(const UserAgentPlatformInfo& platform_info) {\n"
    "  (void)platform_info;\n"
    "  return \"" + UA + "\";\n"
    "}\n"
    "\n"
    "// Cobalt's original User-Agent builder (not used by the phone build).\n"
    "std::string CobaltUserAgentString(const UserAgentPlatformInfo& platform_info) {\n",
)
