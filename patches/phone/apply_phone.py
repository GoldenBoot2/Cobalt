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

# 4. Page probe (diagnosis, phone only): Cobalt gold has no dev tools, and m.youtube.com stayed black with no
#    errors. At 6 s and 20 s report element count, html/body style + size, and the first 24 elements of the
#    body tree (depth <= 5) with size and display/visibility/opacity/colours, through the debug channel.
PAGE_PROBE = (
    "function gbp(t){try{var d=document,b=d.body,h=d.documentElement,all=d.getElementsByTagName('*');"
    "var cs=function(el){var s=getComputedStyle(el);return s.display+'/'+s.visibility+'/'+s.opacity+'/'"
    "+s.backgroundColor+'/'+s.color;};"
    "var r=function(el){var q=el.getBoundingClientRect();return Math.round(q.width)+'x'+Math.round(q.height)"
    "+'@'+Math.round(q.left)+','+Math.round(q.top);};"
    "gbr('probe '+t+'s n='+all.length+' title='+d.title+' html:'+cs(h)+' '+r(h)+' body:'+(b?cs(b)+' '+r(b)"
    "+' kids='+b.children.length+' text='+String(b.textContent||'').length:'none')+' ce='+(typeof customElements)"
    "+' shadow='+(typeof Element.prototype.attachShadow)+' win='+innerWidth+'x'+innerHeight);"
    "var L=[],w=function(el,dp){if(L.length>=24||dp>5)return;"
    "var c=el.className&&typeof el.className==='string'?'.'+el.className.split(' ').slice(0,2).join('.'):'';"
    "L.push(dp+':'+el.tagName.toLowerCase()+(el.id?'#'+el.id:'')+c+' '+r(el)+' '+cs(el));"
    "for(var i=0;i<el.children.length;i++)w(el.children[i],dp+1);};if(b)w(b,0);"
    "for(var k=0;k<L.length;k+=8)gbr('tree '+t+'s '+k+': '+L.slice(k,k+8).join(' | '));"
    "}catch(e){gbr('probe threw '+gbs(e));}}"
    "setTimeout(function(){gbp(6);},6000);setTimeout(function(){gbp(20);},20000);"
)
assert '"' not in PAGE_PROBE and '\\' not in PAGE_PROBE
patch("cobalt/network/adguard_engine.cc",
      "gbr('no window.fetch');}}catch(e){}\\n\";",
      "gbr('no window.fetch');}}catch(e){}\\n\" \"" + PAGE_PROBE + "\\n\";")

# 5. Probe 2 (diagnosis, phone only): m.youtube.com stops at its loading skeleton with no visible errors.
#    a) window._DumpException set BEFORE YouTube's base script reads it (Closure modules send their errors
#       there): report, then rethrow like YouTube's default.
#    b) at 7 s: which of ~130 browser features are missing, and which YouTube scripts loaded.
#    c) HTTP status of every /youtubei/ fetch answer.
#    d) native: YouTube's own error pings (error_204 / jserror) logged with their query.
PROBE2 = (
    "try{window._DumpException=function(e){gbr('dump: '+gbs(e));throw e;};}catch(e){}"
    "try{var gof2=window.fetch;if(gof2)window.fetch=function(u,o){var p=gof2.apply(this,arguments);"
    "var s=String(u&&u.url||u);if(s.indexOf('youtubei')>=0&&p&&p.then)p.then(function(r){"
    "gbr('resp '+s.split('?')[0].slice(-40)+' '+(r&&r.status));},function(e){gbr('resp fail '+s.slice(-40)+' '+gbs(e));});"
    "return p;};}catch(e){}"
    "function gbh(p){try{var a=p.split('.'),o=window;for(var i=0;i<a.length-1;i++){o=o[a[i]];if(o==null)return false;}"
    "return a[a.length-1] in Object(o);}catch(e){return false;}}"
    "setTimeout(function(){try{var F=('IntersectionObserver ResizeObserver MutationObserver requestIdleCallback "
    "requestAnimationFrame queueMicrotask globalThis structuredClone AbortController AbortSignal.timeout WeakRef "
    "FinalizationRegistry Promise.allSettled Promise.any Promise.prototype.finally Array.prototype.flat "
    "Array.prototype.flatMap Array.prototype.at Array.prototype.includes Array.from Object.fromEntries Object.hasOwn "
    "Object.entries Object.values String.prototype.replaceAll String.prototype.matchAll String.prototype.padStart "
    "String.prototype.at Symbol.asyncIterator BigInt TextEncoder TextDecoder URL URLSearchParams CSS.escape "
    "customElements ShadowRoot Element.prototype.attachShadow Node.prototype.getRootNode Node.prototype.isConnected "
    "HTMLTemplateElement HTMLSlotElement HTMLDialogElement Element.prototype.animate Element.prototype.scrollIntoView "
    "Element.prototype.scrollTo Element.prototype.scrollBy Element.prototype.closest Element.prototype.toggleAttribute "
    "Element.prototype.insertAdjacentElement Element.prototype.insertAdjacentHTML Element.prototype.getAttributeNames "
    "Element.prototype.requestFullscreen Element.prototype.webkitRequestFullscreen document.exitFullscreen "
    "HTMLElement.prototype.inert HTMLElement.prototype.innerText HTMLElement.prototype.dataset "
    "Element.prototype.classList DocumentFragment document.fonts document.visibilityState document.createRange "
    "document.createTreeWalker document.adoptedStyleSheets document.scrollingElement getSelection matchMedia "
    "CustomEvent PointerEvent TouchEvent Touch InputEvent FocusEvent visualViewport localStorage sessionStorage "
    "indexedDB caches navigator.serviceWorker navigator.sendBeacon navigator.userActivation navigator.connection "
    "navigator.mediaSession navigator.clipboard navigator.share navigator.wakeLock performance.now performance.mark "
    "performance.getEntriesByType PerformanceObserver Worker SharedWorker BroadcastChannel MessageChannel "
    "ReadableStream Response.prototype.body Blob File FileReader FormData DOMParser XMLSerializer Proxy Reflect "
    "Intl.DateTimeFormat Intl.NumberFormat Intl.PluralRules Intl.RelativeTimeFormat Intl.Locale Intl.ListFormat "
    "crypto.getRandomValues crypto.randomUUID crypto.subtle history.pushState history.scrollRestoration "
    "HTMLMediaElement HTMLVideoElement MediaSource ManagedMediaSource HTMLCanvasElement WebGLRenderingContext "
    "Image HTMLPictureElement CSSStyleSheet CSSStyleSheet.prototype.replaceSync CSS.supports screen.orientation "
    "createImageBitmap OffscreenCanvas WebAssembly Atomics SharedArrayBuffer Notification fetch Request Headers "
    "IntersectionObserverEntry DOMRect DOMRectReadOnly NodeFilter Range Selection SVGElement HTMLIFrameElement "
    "Event.prototype.composedPath Event.prototype.composed EventTarget getComputedStyle scrollTo scrollY "
    "devicePixelRatio onpopstate onpageshow onvisibilitychange').split(' ');var miss=[];"
    "for(var i=0;i<F.length;i++)if(F[i]&&!gbh(F[i]))miss.push(F[i]);"
    "for(var k=0;k<miss.length;k+=25)gbr('missing '+k+': '+miss.slice(k,k+25).join(' '));"
    "var sc=document.scripts||document.getElementsByTagName('script'),L=[];"
    "for(var j=0;j<sc.length;j++){var s=sc[j].src||'';if(s){var m=s.indexOf('/m=');"
    "L.push(m>=0?s.slice(m+3,m+70):s.slice(-50));}}"
    "gbr('scripts '+L.length+': '+L.join(' | '));}catch(e){gbr('probe2 threw '+gbs(e));}},7000);"
)
assert '"' not in PROBE2 and '\\' not in PROBE2
patch("cobalt/network/adguard_engine.cc",
      "gbr('no window.fetch');}}catch(e){}\\n\" \"",
      "gbr('no window.fetch');}}catch(e){}\\n\" \"" + PROBE2)
patch("cobalt/network/adguard_filter.cc",
      "  if (mode & kModeNoNetwork) return false;",
      "  if (url.path().find(\"error_204\") != std::string::npos ||\r\n"
      "      url.path().find(\"jserror\") != std::string::npos) {  // GoldenBoot phone probe\r\n"
      "    std::string eq = url.query();\r\n"
      "    if (eq.size() > 1500) eq.resize(1500);\r\n"
      "    GB_LOG(\"yt error ping %s: %s\", url.path().c_str(), eq.c_str());\r\n"
      "  }\r\n"
      "  if (mode & kModeNoNetwork) return false;")

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
