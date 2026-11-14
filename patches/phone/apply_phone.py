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

# 6. YouTube data requests (/youtubei/) came back HTTP 400 in Cobalt (att/get, guide) = the page never got data
#    and stayed on its loading skeleton. Tested from the PC: the same JSON body without/with a wrong
#    Content-Type gives 400. Fix: rebuild each /youtubei/ fetch as fetch(url-string, plain init) with method,
#    headers and body copied out of a Request object, body as text, Content-Type application/json if missing.
#    First 6 rebuilt requests are reported (yfix ...). Runs first in kPolyfills = closest to Cobalt's fetch.
FETCH_FIX = (
    "try{(function(){var nf=window.fetch;if(!nf)return;var cnt=0;"
    "window.fetch=function(u,o){var isReq=!!(u&&typeof u==='object'&&u.url);var url=isReq?u.url:String(u);"
    "if(url.indexOf('/youtubei/')<0)return nf.apply(this,arguments);"
    "var init={},k;if(o)for(k in o)init[k]=o[k];var method=String(init.method||(isReq&&u.method)||'GET').toUpperCase();"
    "var hdr={};var addH=function(h){if(!h)return;try{if(Array.isArray(h)){h.forEach(function(p){hdr[String(p[0]).toLowerCase()]=p[1];});}"
    "else if(typeof h.forEach==='function'){h.forEach(function(v,n){hdr[String(n).toLowerCase()]=v;});}"
    "else{for(var n in h)hdr[n.toLowerCase()]=h[n];}}catch(e){}};if(isReq)addH(u.headers);addH(init.headers);"
    "var bp;if(init.body!==undefined&&init.body!==null)bp=Promise.resolve(init.body);"
    "else if(isReq&&method!=='GET'&&method!=='HEAD'&&u.clone)bp=u.clone().text();else bp=Promise.resolve(undefined);"
    "var self=this;return bp.then(function(b){if(b&&typeof b==='object'){"
    "if(typeof b.text==='function')return b.text();"
    "try{if(b instanceof ArrayBuffer)return new TextDecoder().decode(new Uint8Array(b));"
    "if(ArrayBuffer.isView(b))return new TextDecoder().decode(b);}catch(e){}}return b;}).then(function(b){"
    "if(typeof b==='string'&&!hdr['content-type']&&b.charAt(0)==='{')hdr['content-type']='application/json';"
    "if(cnt++<6&&typeof gbr==='function')gbr('yfix '+method+' '+url.split('?')[0].slice(-30)+' req='+(isReq?1:0)"
    "+' ct='+hdr['content-type']+' btype='+(typeof b)+' len='+(b&&b.length)+' head='+(typeof b==='string'?b.slice(0,60):''));"
    "var ni={method:method,headers:hdr,credentials:init.credentials||(isReq&&u.credentials)||'same-origin'};"
    "if(b!==undefined&&b!==null)ni.body=b;if(init.signal)ni.signal=init.signal;return nf.call(self,url,ni);});};"
    "})();}catch(e){}"
)

# 7. Small polyfills for features Cobalt 25 lacks (probe 2 list); each only when missing.
POLYFILLS = (
    "try{(function(){var W=window,D=document,E=W.Element&&Element.prototype,H=W.HTMLElement&&HTMLElement.prototype;"
    "if(!W.requestIdleCallback){W.requestIdleCallback=function(cb){var s=Date.now();return setTimeout(function(){"
    "cb({didTimeout:false,timeRemaining:function(){return Math.max(0,50-(Date.now()-s));}});},1);};"
    "W.cancelIdleCallback=function(i){clearTimeout(i);};}"
    "if(!W.structuredClone)W.structuredClone=function(v){return v===undefined?v:JSON.parse(JSON.stringify(v));};"
    "if(W.CSS&&!CSS.escape)CSS.escape=function(s){var B=String.fromCharCode(92);return String(s).replace(/[^a-zA-Z0-9_-]/g,"
    "function(c){return B+c;});};"
    "if(!W.URLSearchParams){var enc=function(x){return encodeURIComponent(x).split('%20').join('+');},"
    "dec=function(x){try{return decodeURIComponent(String(x).split('+').join(' '));}catch(e){return String(x);}};"
    "var U=function(init){this._l=[];var self=this;if(init==null)return;if(typeof init==='string'){"
    "if(init.charAt(0)==='?')init=init.slice(1);init.split('&').forEach(function(p){if(!p)return;var i=p.indexOf('=');"
    "self._l.push(i<0?[dec(p),'']:[dec(p.slice(0,i)),dec(p.slice(i+1))]);});}"
    "else if(Array.isArray(init)){init.forEach(function(p){self._l.push([String(p[0]),String(p[1])]);});}"
    "else if(init instanceof U){self._l=init._l.slice();}else{for(var k in init)self._l.push([k,String(init[k])]);}};"
    "U.prototype.append=function(n,v){this._l.push([String(n),String(v)]);};"
    "U.prototype.delete=function(n){this._l=this._l.filter(function(p){return p[0]!==String(n);});};"
    "U.prototype.get=function(n){for(var i=0;i<this._l.length;i++)if(this._l[i][0]===String(n))return this._l[i][1];return null;};"
    "U.prototype.getAll=function(n){return this._l.filter(function(p){return p[0]===String(n);}).map(function(p){return p[1];});};"
    "U.prototype.has=function(n){return this.get(n)!==null;};"
    "U.prototype.set=function(n,v){var f=false;n=String(n);this._l=this._l.filter(function(p){if(p[0]!==n)return true;"
    "if(f)return false;f=true;p[1]=String(v);return true;});if(!f)this._l.push([n,String(v)]);};"
    "U.prototype.forEach=function(cb,t){var s=this;this._l.slice().forEach(function(p){cb.call(t,p[1],p[0],s);});};"
    "U.prototype.toString=function(){return this._l.map(function(p){return enc(p[0])+'='+enc(p[1]);}).join('&');};"
    "U.prototype.entries=function(){return this._l.map(function(p){return [p[0],p[1]];})[Symbol.iterator]();};"
    "U.prototype.keys=function(){return this._l.map(function(p){return p[0];})[Symbol.iterator]();};"
    "U.prototype.values=function(){return this._l.map(function(p){return p[1];})[Symbol.iterator]();};"
    "U.prototype[Symbol.iterator]=U.prototype.entries;W.URLSearchParams=U;}"
    "if(H&&!('innerText' in H))Object.defineProperty(H,'innerText',{configurable:true,"
    "get:function(){return this.textContent;},set:function(v){this.textContent=v;}});"
    "if(E){var ins=function(el,pos,nodes){var p=el.parentNode;pos=String(pos).toLowerCase();"
    "if(pos==='beforebegin'){nodes.forEach(function(n){p.insertBefore(n,el);});}"
    "else if(pos==='afterbegin'){var f=el.firstChild;nodes.forEach(function(n){el.insertBefore(n,f);});}"
    "else if(pos==='beforeend'){nodes.forEach(function(n){el.appendChild(n);});}"
    "else if(pos==='afterend'){var s=el.nextSibling;nodes.forEach(function(n){p.insertBefore(n,s);});}};"
    "if(!E.insertAdjacentHTML)E.insertAdjacentHTML=function(pos,html){var t=D.createElement('div');t.innerHTML=html;"
    "var a=[];while(t.firstChild)a.push(t.removeChild(t.firstChild));ins(this,pos,a);};"
    "if(!E.insertAdjacentElement)E.insertAdjacentElement=function(pos,n){ins(this,pos,[n]);return n;};"
    "if(!E.getAttributeNames)E.getAttributeNames=function(){var r=[];for(var i=0;i<this.attributes.length;i++)"
    "r.push(this.attributes[i].name);return r;};"
    "var sx=function(el,a,b,add){var x,y;if(a&&typeof a==='object'){x=a.left;y=a.top;}else{x=a;y=b;}"
    "if(x!=null&&!isNaN(x))el.scrollLeft=(add?el.scrollLeft:0)+Number(x);"
    "if(y!=null&&!isNaN(y))el.scrollTop=(add?el.scrollTop:0)+Number(y);};"
    "if(!E.scrollTo)E.scrollTo=function(a,b){sx(this,a,b,false);};if(!E.scroll)E.scroll=E.scrollTo;"
    "if(!E.scrollBy)E.scrollBy=function(a,b){sx(this,a,b,true);};"
    "if(!E.scrollIntoView)E.scrollIntoView=function(){};}"
    "var se=function(){return D.scrollingElement||D.documentElement||D.body;};"
    "if(!W.scrollTo)W.scrollTo=function(a,b){var el=se();if(el)sx(el,a,b,false);};if(!W.scroll)W.scroll=W.scrollTo;"
    "if(!W.scrollBy)W.scrollBy=function(a,b){var el=se();if(el)sx(el,a,b,true);};"
    "try{if(!('scrollY' in W))Object.defineProperty(W,'scrollY',{configurable:true,get:function(){var el=se();return el?el.scrollTop:0;}});"
    "if(!('scrollX' in W))Object.defineProperty(W,'scrollX',{configurable:true,get:function(){var el=se();return el?el.scrollLeft:0;}});"
    "if(!('pageYOffset' in W))Object.defineProperty(W,'pageYOffset',{configurable:true,get:function(){return W.scrollY;}});"
    "if(!('pageXOffset' in W))Object.defineProperty(W,'pageXOffset',{configurable:true,get:function(){return W.scrollX;}});}catch(e){}"
    "if(W.history&&!history.pushState){var hs=null;history.pushState=function(s){hs=s;};"
    "history.replaceState=function(s){hs=s;};try{if(!('state' in history))Object.defineProperty(history,'state',"
    "{configurable:true,get:function(){return hs;}});}catch(e){}}"
    "if(W.Node&&!Node.prototype.getRootNode)Node.prototype.getRootNode=function(){var n=this;while(n.parentNode)n=n.parentNode;return n;};"
    "if(W.Event&&!Event.prototype.composedPath)Event.prototype.composedPath=function(){var p=[],n=this.target;"
    "while(n){p.push(n);n=n.parentNode;}if(p.length&&p[p.length-1]!==W)p.push(W);return p;};"
    "if(!W.MessageChannel){W.MessageChannel=function(){var mk=function(){return {onmessage:null,"
    "start:function(){},close:function(){},addEventListener:function(t,f){if(t==='message')this.onmessage=f;},"
    "removeEventListener:function(){}};};var a=mk(),b=mk();a.postMessage=function(d){setTimeout(function(){"
    "if(b.onmessage)b.onmessage({data:d});},0);};b.postMessage=function(d){setTimeout(function(){"
    "if(a.onmessage)a.onmessage({data:d});},0);};this.port1=a;this.port2=b;};}"
    "if(W.crypto&&crypto.getRandomValues&&!crypto.randomUUID)crypto.randomUUID=function(){var b=new Uint8Array(16);"
    "crypto.getRandomValues(b);b[6]=(b[6]&15)|64;b[8]=(b[8]&63)|128;var h=[];for(var i=0;i<16;i++){"
    "h.push((b[i]+256).toString(16).slice(1));if(i===3||i===5||i===7||i===9)h.push('-');}return h.join('');};"
    "})();}catch(e){}"
)
for _js in (FETCH_FIX, POLYFILLS):
    assert '"' not in _js and '\\' not in _js
# Inserted right after the CSS.supports shim (both at the start of kPolyfills).
patch("cobalt/network/adguard_engine.cc",
      "const char kPolyfills[] =" + NL,
      "const char kPolyfills[] =" + NL + "    \"" + FETCH_FIX + "\\n\"" + NL + "    \"" + POLYFILLS + "\\n\"" + NL)

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
