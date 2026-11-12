// GoldenBoot: AdGuard filter engine for Cobalt. See adguard_engine.h.

#include "cobalt/network/adguard_engine.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace cobalt {
namespace network {
namespace adguard {

namespace {

// Rule data (read-only, generated). Defines kAdgInfo, kAdgStats, the host
// lists, the network rule table (kAdgNet*), the cosmetic tables (kAdgCos*,
// kAdgGenericCss), the scriptlet functions (kAdgSlCode) and ExtendedCss
// (kAdgExtCss).
#include "cobalt/network/adguard_rules.inc"

// Network rule flags (F_* in adguard_rules.py).
const uint32_t kFlagException = 1;
const uint32_t kFlagImportant = 2;
const uint32_t kFlagThirdParty = 4;
const uint32_t kFlagFirstParty = 8;
const uint32_t kFlagMatchCase = 16;
const uint32_t kFlagPage = 32;

const uint32_t kExceptionRef = 0x80000000u;
const size_t kMaxUrlTokens = 64;

// Sorted '\n'-terminated strings in read-only data; only an offset table is
// built in memory.
class SortedList {
 public:
  explicit SortedList(const char* blob) : blob_(blob) {
    const char* p = blob;
    while (*p) {
      offsets_.push_back(static_cast<uint32_t>(p - blob));
      const char* nl = strchr(p, '\n');
      if (!nl) break;
      p = nl + 1;
    }
  }

  // Index of the entry equal to s[0, n), or -1.
  long Find(const char* s, size_t n) const {
    size_t lo = 0;
    size_t hi = offsets_.size();
    while (lo < hi) {
      size_t mid = lo + (hi - lo) / 2;
      int c = Compare(blob_ + offsets_[mid], s, n);
      if (c == 0) return static_cast<long>(mid);
      if (c < 0) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    return -1;
  }

  bool Contains(const char* s, size_t n) const { return Find(s, n) >= 0; }
  size_t size() const { return offsets_.size(); }

 private:
  // Compares a '\n'-terminated entry with s[0, n).
  static int Compare(const char* e, const char* s, size_t n) {
    for (size_t i = 0; i < n; ++i) {
      unsigned char a = e[i] == '\n' ? 0 : static_cast<unsigned char>(e[i]);
      unsigned char b = static_cast<unsigned char>(s[i]);
      if (a != b) return a < b ? -1 : 1;
    }
    return e[n] == '\n' ? 0 : 1;
  }

  const char* blob_;
  std::vector<uint32_t> offsets_;
};

// Host table written by front_coded() in adguard_rules.py: reversed host names,
// sorted, front-coded in buckets of kFcBucket entries (the first of each bucket
// stored whole). Entry: shared-prefix length, suffix length, suffix bytes, then
// an optional little-endian uint32 payload. Read in place, no memory needed.
const uint32_t kFcBucket = 16;

struct FcList {
  const unsigned char* data;
  const uint32_t* heads;
  uint32_t count;
  bool has_payload;

  // Looks up key (a reversed host name); fills *payload if found.
  bool Find(const char* key, size_t kn, uint32_t* payload) const {
    if (count == 0) return false;
    const uint32_t nheads = (count + kFcBucket - 1) / kFcBucket;
    size_t lo = 0;
    size_t hi = nheads;
    while (lo < hi) {  // first bucket whose first entry is > key
      size_t mid = lo + (hi - lo) / 2;
      const unsigned char* e = data + heads[mid];
      if (Compare(e + 2, e[1], key, kn) <= 0) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    if (lo == 0) return false;
    const size_t bucket = lo - 1;
    const unsigned char* p = data + heads[bucket];
    unsigned char buf[256];
    size_t idx = bucket * kFcBucket;
    for (uint32_t i = 0; i < kFcBucket && idx < count; ++i, ++idx) {
      const size_t shared = p[0];
      const size_t sl = p[1];
      memcpy(buf + shared, p + 2, sl);
      const size_t len = shared + sl;
      p += 2 + sl;
      uint32_t pl = 0;
      if (has_payload) {
        pl = static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
             (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
        p += 4;
      }
      int c = Compare(buf, len, key, kn);
      if (c == 0) {
        if (payload) *payload = pl;
        return true;
      }
      if (c > 0) return false;
    }
    return false;
  }

 private:
  static int Compare(const unsigned char* a, size_t an, const char* b, size_t bn) {
    size_t n = an < bn ? an : bn;
    for (size_t i = 0; i < n; ++i) {
      unsigned char y = static_cast<unsigned char>(b[i]);
      if (a[i] != y) return a[i] < y ? -1 : 1;
    }
    if (an == bn) return 0;
    return an < bn ? -1 : 1;
  }
};

FcList MakeFc(const char* data, const uint32_t* heads, uint32_t count, bool payload) {
  FcList l;
  l.data = reinterpret_cast<const unsigned char*>(data);
  l.heads = heads;
  l.count = count;
  l.has_payload = payload;
  return l;
}

struct Data {
  Data()
      : important(MakeFc(kAdgImportant, kAdgImportantHeads, kAdgImportantCount, false)),
        block_all(MakeFc(kAdgBlockAll, kAdgBlockAllHeads, kAdgBlockAllCount, false)),
        block_3p(MakeFc(kAdgBlock3p, kAdgBlock3pHeads, kAdgBlock3pCount, false)),
        allow(MakeFc(kAdgAllow, kAdgAllowHeads, kAdgAllowCount, false)),
        typed(MakeFc(kAdgTyped, kAdgTypedHeads, kAdgTypedCount, true)),
        cos_keys(kAdgCosKeys) {}
  FcList important;
  FcList block_all;
  FcList block_3p;
  FcList allow;
  FcList typed;
  SortedList cos_keys;
};

std::once_flag g_data_once;
Data* g_data = nullptr;

const Data& GetData() {
  std::call_once(g_data_once, [] { g_data = new Data(); });
  return *g_data;
}

// ------------------------------------------------------------------ helpers

bool IsTokenChar(unsigned char c) {
  return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '%';
}

// AdGuard "^": anything but a letter, a digit or one of _ - . %
bool IsSeparator(unsigned char c) {
  if (c >= 0x80) return false;
  if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9'))
    return false;
  return c != '_' && c != '-' && c != '.' && c != '%';
}

std::string Lower(const std::string& s) {
  std::string r(s);
  for (char& c : r) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return r;
}

uint32_t Fnv(const char* s, size_t n) {
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < n; ++i) {
    h ^= static_cast<unsigned char>(s[i]);
    h *= 16777619u;
  }
  return h;
}

// Host part [b, e) of a URL ("scheme://user@host:port/...").
void HostBounds(const std::string& url, size_t* b, size_t* e) {
  *b = *e = 0;
  size_t s = url.find("://");
  if (s == std::string::npos) return;
  s += 3;
  size_t end = url.find_first_of("/?#", s);
  if (end == std::string::npos) end = url.size();
  size_t at = url.rfind('@', end);
  if (at != std::string::npos && at >= s) s = at + 1;
  size_t colon = url.find(':', s);
  if (colon != std::string::npos && colon < end) end = colon;
  *b = s;
  *e = end;
}

// d[0, n) is "example.org" (matches it and its subdomains) or "example.*"
// (any public suffix).
bool HostMatchesDomain(const std::string& host, size_t registry_len,
                       const char* d, size_t n) {
  if (host.empty() || n == 0) return false;
  size_t hn = host.size();
  if (n >= 2 && d[n - 1] == '*' && d[n - 2] == '.') {
    if (registry_len == 0 || registry_len + 1 >= hn) return false;
    hn -= registry_len + 1;  // "a.example.co.uk" -> "a.example"
    n -= 2;
  }
  if (n > hn) return false;
  if (memcmp(host.data() + hn - n, d, n) != 0) return false;
  return n == hn || host[hn - n - 1] == '.';
}

// $domain=a.com|~b.com|c.*
bool DomainListAllows(const char* list, size_t n, const std::string& host,
                      size_t registry_len) {
  if (n == 0) return true;
  bool has_positive = false;
  bool positive = false;
  const char* p = list;
  const char* end = list + n;
  while (p < end) {
    const char* bar = static_cast<const char*>(memchr(p, '|', end - p));
    if (!bar) bar = end;
    bool neg = *p == '~';
    const char* d = neg ? p + 1 : p;
    size_t dn = bar - d;
    if (neg) {
      if (HostMatchesDomain(host, registry_len, d, dn)) return false;
    } else {
      has_positive = true;
      if (!positive && HostMatchesDomain(host, registry_len, d, dn)) positive = true;
    }
    p = bar + 1;
  }
  return !has_positive || positive;
}

bool DomainListContains(const char* list, size_t n, const std::string& host) {
  const char* p = list;
  const char* end = list + n;
  while (p < end) {
    const char* bar = static_cast<const char*>(memchr(p, '|', end - p));
    if (!bar) bar = end;
    if (HostMatchesDomain(host, 0, p, bar - p)) return true;
    p = bar + 1;
  }
  return false;
}

// AdGuard pattern match of s[0, se) against p[0, pe) ("*" and "^").
bool Glob(const char* s, const char* se, const char* p, const char* pe,
          bool end_anchor, int depth) {
  while (p < pe) {
    char c = *p;
    if (c == '*') {
      while (p < pe && *p == '*') ++p;
      if (p == pe) return true;
      if (depth > 6) return false;
      for (const char* q = s; q <= se; ++q) {
        if (*p != '^' && q < se && *q != *p) continue;
        if (Glob(q, se, p, pe, end_anchor, depth + 1)) return true;
      }
      return false;
    }
    if (c == '^') {
      if (s == se) {  // the end of the URL counts as a separator
        ++p;
        continue;
      }
      if (!IsSeparator(static_cast<unsigned char>(*s))) return false;
      ++s;
      ++p;
      continue;
    }
    if (s == se || *s != c) return false;
    ++s;
    ++p;
  }
  return !end_anchor || s == se;
}

bool MatchPattern(const std::string& url, size_t host_b, size_t host_e,
                  const char* pat, size_t n) {
  const char* s = url.data();
  const char* se = s + url.size();
  const char* p = pat;
  const char* pe = pat + n;
  bool end_anchor = false;
  if (n >= 1 && pe[-1] == '|' && !(n == 2 && p[0] == '|')) {
    end_anchor = true;
    --pe;
  }
  if (pe - p >= 2 && p[0] == '|' && p[1] == '|') {
    p += 2;
    for (size_t i = host_b; i < host_e; ++i) {
      if (i != host_b && url[i - 1] != '.') continue;
      if (Glob(s + i, se, p, pe, end_anchor, 0)) return true;
    }
    return false;
  }
  if (pe - p >= 1 && p[0] == '|') return Glob(s, se, p + 1, pe, end_anchor, 0);
  if (p == pe) return true;
  for (const char* q = s; q <= se; ++q) {
    if (*p != '*' && *p != '^' && (q == se || *q != *p)) continue;
    if (Glob(q, se, p, pe, end_anchor, 0)) return true;
  }
  return false;
}

// ------------------------------------------------------------------ network rules

struct NetRule {
  uint32_t flags;
  uint32_t types;
  const char* dom;
  size_t dom_n;
  const char* deny;
  size_t deny_n;
  const char* pat;
  size_t pat_n;
};

// Line format: "flags\ttypes\tdomains\tdenyallow\tpattern\n" (hex numbers).
void ParseNetRule(uint32_t i, NetRule* r) {
  const char* p = kAdgNet + kAdgNetOff[i];
  char* e = nullptr;
  r->flags = static_cast<uint32_t>(strtoul(p, &e, 16));
  p = e + 1;
  r->types = static_cast<uint32_t>(strtoul(p, &e, 16));
  p = e + 1;
  const char* t = strchr(p, '\t');
  r->dom = p;
  r->dom_n = t - p;
  p = t + 1;
  t = strchr(p, '\t');
  r->deny = p;
  r->deny_n = t - p;
  p = t + 1;
  t = strchr(p, '\n');
  r->pat = p;
  r->pat_n = t - p;
}

void UrlTokenHashes(const std::string& lc, std::vector<uint32_t>* out) {
  size_t i = 0;
  const size_t n = lc.size();
  while (i < n && out->size() < kMaxUrlTokens) {
    while (i < n && !IsTokenChar(static_cast<unsigned char>(lc[i]))) ++i;
    size_t st = i;
    while (i < n && IsTokenChar(static_cast<unsigned char>(lc[i]))) ++i;
    if (i - st >= 2) {
      uint32_t h = Fnv(lc.data() + st, i - st);
      if (std::find(out->begin(), out->end(), h) == out->end()) out->push_back(h);
    }
  }
}

// Calls f(rule index) for every rule indexed under one of |hashes| and every
// unindexed rule, until f returns false.
template <typename F>
void ForEachCandidate(const std::vector<uint32_t>& hashes, F f) {
  for (uint32_t h : hashes) {
    size_t lo = 0;
    size_t hi = kAdgNetTokCount;
    while (lo < hi) {
      size_t mid = lo + (hi - lo) / 2;
      if (kAdgNetTok[2 * mid] < h) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    for (size_t k = lo; k < kAdgNetTokCount && kAdgNetTok[2 * k] == h; ++k) {
      if (!f(kAdgNetTok[2 * k + 1])) return;
    }
  }
  for (size_t k = 0; k < kAdgNetNoTokCount; ++k) {
    if (!f(kAdgNetNoTok[k])) return;
  }
}

bool NetRuleMatches(const NetRule& nr, const Request& r, const std::string& lc,
                    size_t host_b, size_t host_e) {
  if (nr.flags & kFlagPage) return false;
  if (nr.types) {
    if (r.type == 0) {
      // Type unknown (NetworkDelegate): typed exceptions still allow, typed
      // blocking rules wait for the typed check (CspDelegate::CanLoad).
      if (!(nr.flags & kFlagException)) return false;
    } else if (!(nr.types & r.type)) {
      return false;
    }
  }
  if ((nr.flags & kFlagThirdParty) && !r.third_party) return false;
  if ((nr.flags & kFlagFirstParty) && r.third_party) return false;
  if (!DomainListAllows(nr.dom, nr.dom_n, r.page_host, r.page_registry_len))
    return false;
  if (nr.deny_n && DomainListContains(nr.deny, nr.deny_n, r.host)) return false;
  const std::string& u = (nr.flags & kFlagMatchCase) ? r.url : lc;
  return MatchPattern(u, host_b, host_e, nr.pat, nr.pat_n);
}

struct Verdict {
  bool block = false;
  bool block_important = false;
  bool allow = false;
  bool allow_important = false;
  std::string why;
};

// The host and each parent domain ("a.b.c" -> "b.c" -> "c") against the host
// tables. Tables hold reversed names, so the parents are prefixes of the
// reversed host that end before a '.'.
void CheckHostLists(const Data& d, const Request& r, Verdict* v) {
  const std::string& host = r.host;
  const std::string rev(host.rbegin(), host.rend());
  size_t n = rev.size();
  while (n > 0) {
    const char* p = rev.data();
    const std::string name = host.substr(host.size() - n);
    uint32_t types = 0;
    if (d.important.Find(p, n, nullptr)) {
      v->block_important = true;
      v->why = "||" + name + "^$important";
    }
    if (d.allow.Find(p, n, nullptr)) v->allow = true;
    if (d.block_all.Find(p, n, nullptr)) {
      v->block = true;
      if (v->why.empty()) v->why = "||" + name + "^";
    }
    if (r.third_party && d.block_3p.Find(p, n, nullptr)) {
      v->block = true;
      if (v->why.empty()) v->why = "||" + name + "^$third-party";
    }
    if (r.type && d.typed.Find(p, n, &types)) {
      const uint32_t mask = (types & 0xffffu) | (r.third_party ? (types >> 16) : 0u);
      if (mask & r.type) {
        v->block = true;
        if (v->why.empty()) v->why = name + " (typed)";
      }
    }
    size_t dot = rev.rfind('.', n - 1);
    if (dot == std::string::npos) break;
    n = dot;
  }
}

// ------------------------------------------------------------------ cosmetic

const char* CosEntry(uint32_t i, size_t* n) {
  const char* p = kAdgCosEntries + kAdgCosOff[i];
  const char* e = strchr(p, '\n');
  *n = e - p;
  return p;
}

bool IsGeneric(uint32_t i) {
  return std::binary_search(kAdgCosGeneric, kAdgCosGeneric + kAdgCosGenericCount, i);
}

bool IsKeyed(uint32_t i) {
  return std::binary_search(kAdgCosGenericKeyed,
                            kAdgCosGenericKeyed + kAdgCosGenericKeyedCount, i);
}

// Appends s as a JavaScript string literal.
void AppendJsString(std::string* out, const char* s, size_t n) {
  static const char kHex[] = "0123456789abcdef";
  out->push_back('"');
  for (size_t i = 0; i < n; ++i) {
    unsigned char c = static_cast<unsigned char>(s[i]);
    if (c == '"' || c == '\\') {
      out->push_back('\\');
      out->push_back(static_cast<char>(c));
    } else if (c == '\n') {
      out->append("\\n");
    } else if (c < 0x20 || c == 0x7f) {
      out->append("\\u00");
      out->push_back(kHex[c >> 4]);
      out->push_back(kHex[c & 15]);
    } else if (c == 0xe2 && i + 2 < n && static_cast<unsigned char>(s[i + 1]) == 0x80 &&
               (static_cast<unsigned char>(s[i + 2]) == 0xa8 ||
                static_cast<unsigned char>(s[i + 2]) == 0xa9)) {
      out->append(static_cast<unsigned char>(s[i + 2]) == 0xa8 ? "\\u2028" : "\\u2029");
      i += 2;
    } else if (c == '<') {
      out->append("\\u003c");
    } else {
      out->push_back(static_cast<char>(c));
    }
  }
  out->push_back('"');
}

// DOM functions every current browser has but Cobalt 25 lacks (found with the
// debug channel: Element.closest, NodeList.forEach); added only when missing.
const char kPolyfills[] =
    "try{(function(){var E=window.Element&&Element.prototype;if(E){"
    "if(!E.matches)E.matches=E.webkitMatchesSelector||function(s){"
    "var m=(this.ownerDocument||document).querySelectorAll(s),i=m.length;"
    "while(--i>=0&&m[i]!==this);return i>-1;};"
    "if(!E.closest)E.closest=function(s){var el=this;while(el&&el.nodeType===1){"
    "if(el.matches(s))return el;el=el.parentElement||el.parentNode;}return null;};"
    "if(!E.remove)E.remove=function(){if(this.parentNode)this.parentNode.removeChild(this);};"
    "var nodes=function(a){var f=document.createDocumentFragment();"
    "for(var i=0;i<a.length;i++){var n=a[i];"
    "f.appendChild(n&&typeof n==='object'?n:document.createTextNode(String(n)));}return f;};"
    "if(!E.append)E.append=function(){this.appendChild(nodes(arguments));};"
    "if(!E.prepend)E.prepend=function(){this.insertBefore(nodes(arguments),this.firstChild);};"
    "if(!E.before)E.before=function(){if(this.parentNode)"
    "this.parentNode.insertBefore(nodes(arguments),this);};"
    "if(!E.after)E.after=function(){if(this.parentNode)"
    "this.parentNode.insertBefore(nodes(arguments),this.nextSibling);};"
    "if(!E.replaceWith)E.replaceWith=function(){if(this.parentNode)"
    "this.parentNode.replaceChild(nodes(arguments),this);};"
    "if(!E.toggleAttribute)E.toggleAttribute=function(n,f){var h=this.hasAttribute(n);"
    "if(f===undefined)f=!h;if(f)this.setAttribute(n,'');else this.removeAttribute(n);return f;};}"
    "var it=typeof Symbol!=='undefined'&&Symbol.iterator;"
    "[window.NodeList,window.HTMLCollection,window.DOMTokenList].forEach(function(C){"
    "var P=C&&C.prototype;if(!P)return;"
    "if(C!==window.HTMLCollection&&!P.forEach)P.forEach=Array.prototype.forEach;"
    "if(it&&!P[it])P[it]=Array.prototype[it];});})();}catch(e){}\n";

// Debug channel: release builds of Cobalt drop console output, so page errors,
// console.error/warn and failed fetch() calls are reported as a request to
// https://gb-debug.invalid/?<message>; adguard_filter.cc logs and blocks it.
const char kDebugHead[] =
    "var gbn=0;function gbr(m){if(gbn++>=150)return;try{var x=new XMLHttpRequest();"
    "x.open('GET','https://gb-debug.invalid/?'+encodeURIComponent(String(m).slice(0,400)));"
    "x.send();}catch(e){}}\n"
    "function gbs(e){return e?(e.name+': '+e.message+' | '+String(e.stack||'').slice(0,300)):String(e);}\n"
    "try{var gwm=new WeakMap(),gae=EventTarget.prototype.addEventListener,"
    "gre=EventTarget.prototype.removeEventListener;"
    "EventTarget.prototype.addEventListener=function(t,f,o){var g=f;"
    "if(typeof f==='function'){g=gwm.get(f);if(!g){g=function(){try{return f.apply(this,arguments);}"
    "catch(e){gbr('listener '+t+': '+gbs(e));throw e;}};gwm.set(f,g);}}"
    "return gae.call(this,t,g,o);};"
    "EventTarget.prototype.removeEventListener=function(t,f,o){"
    "return gre.call(this,t,(typeof f==='function'&&gwm.get(f))||f,o);};}"
    "catch(e){gbr('no listener wrap: '+gbs(e));}\n"
    "try{document.addEventListener('DOMContentLoaded',function(){"
    "gbr('DOMContentLoaded, readyState='+document.readyState);});}catch(e){}\n"
    "try{window.addEventListener('error',function(e){gbr('error: '+(e&&e.message)+' @'+"
    "(e&&e.filename)+':'+(e&&e.lineno)+':'+(e&&e.colno)+' '+(e&&e.error?gbs(e.error):''));});"
    "window.addEventListener('unhandledrejection',function(e){var r=e&&e.reason;"
    "gbr('rejection: '+gbs(r));});}catch(e){}\n"
    "try{['error','warn'].forEach(function(k){var f=console[k];console[k]=function(){"
    "var a=[];for(var i=0;i<arguments.length;i++)a.push(String(arguments[i]));"
    "gbr('console.'+k+': '+a.join(' '));if(f)return f.apply(console,arguments);};});}catch(e){}\n"
    "var gfc=0;try{if(window.fetch){var gof=window.fetch;window.fetch=function(u,o){"
    "if(gfc++<3)gbr('fetch #'+gfc+' '+String(u&&u.url||u).slice(0,120)+' '+"
    "(o&&(o.method+' '+o.mode)));"
    "var p;try{p=gof.apply(this,arguments);}catch(e){gbr('fetch threw: '+gbs(e));throw e;}"
    "return p.then(null,function(e){"
    "gbr('fetch failed: '+String(u&&u.url||u).slice(0,150)+' mode='+(o&&o.mode)+' '+"
    "(e&&(e.name+': '+e.message)||e));throw e;});};}else{gbr('no window.fetch');}}catch(e){}\n";

// Ad probes (test switch bit kModeAdProbes only): what the video-info answers contain
// before (RAW) and after (FINAL) the scriptlets, what Cobalt supports, and the
// scriptlets' own log lines (they run verbose then).
const char kAdProbes[] =
    "var gyp=/youtubei\\/v1\\/(player|next|reel|get_watch)|\\/player\\?|get_watch/;\n"
    "function gad(t){return 'len='+t.length+' adPlacements='+(t.indexOf('\"adPlacements\"')>=0)+"
    "' playerAds='+(t.indexOf('\"playerAds\"')>=0)+' adSlots='+(t.indexOf('\"adSlots\"')>=0)+"
    "' ssap='+(t.indexOf('ssapConfig')>=0||t.indexOf('ssapPrerollEnabled')>=0);}\n"
    "function gprobe(tag,f){return function(u,o){var s=String(u&&u.url||u);"
    "var p=f.apply(this,arguments);if(gyp.test(s)&&p&&p.then){p.then(function(r){try{"
    "if(!r||!r.clone){gbr(tag+' no clone '+s.slice(0,80));return;}"
    "r.clone().text().then(function(t){gbr(tag+' '+s.slice(0,60)+' '+gad(t));},"
    "function(e){gbr(tag+' text failed '+gbs(e));});}catch(e){gbr(tag+' probe err '+gbs(e));}},"
    "function(){});}return p;};}\n"
    "try{if(window.fetch)window.fetch=gprobe('RAW',window.fetch);}catch(e){}\n"
    "var gfp=window.fetch;\n"
    "try{var gxo=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){"
    "var s=String(u);if(gyp.test(s)){this.addEventListener('load',function(){try{"
    "gbr('XHR '+s.slice(0,60)+' '+gad(String(this.responseText||'')));}catch(e){}});}"
    "return gxo.apply(this,arguments);};}catch(e){}\n"
    "try{gbr('env Proxy='+typeof Proxy+' Reflect='+typeof Reflect+' Response='+typeof Response+"
    "' clone='+(typeof Response!=='undefined'&&typeof Response.prototype.clone)+"
    "' Request='+typeof Request+' Headers='+typeof Headers);"
    "if(typeof Response==='function'){try{new Response('{\"a\":1}',{status:200}).json().then("
    "function(j){gbr('new Response ok a='+j.a);},function(e){gbr('new Response json failed '+gbs(e));});}"
    "catch(e){gbr('new Response threw '+gbs(e));}}}catch(e){}\n"
    "try{var gcl=console.log;console.log=function(){var a=[];for(var i=0;i<arguments.length;i++)"
    "a.push(String(arguments[i]));var t=a.join(' ');"
    "if(/json-prune|set-constant|replace-|adPlacements|adSlots|playerAds|AdGuard|scriptlet/i.test(t))"
    "gbr('log: '+t.slice(0,300));if(gcl)return gcl.apply(console,arguments);};}catch(e){}\n";

// YouTube TV ad handler: GENERATED from patches/yt_tv.js by patches/embed_js.py (edit
// the .js, then run the script). Cleans /youtubei/v1/(player|get_watch|next|browse|search)
// answers loaded with fetch() or XMLHttpRequest: ad lists emptied at any depth, Sponsored
// feed cards removed. Test bits (debug.gb.adguard): 16 delete keys, 32 re-serialise
// unchanged, 128 original text, 64 off.
const char kYtTv[] =
    "try{(function(){\n"
    "var m=(typeof gbmode==='number'?gbmode:0);\n"
    "if(m&512){try{var tn=0;function tr(w,u){if(tn++<120)gbr('trace '+w+' '+String(u).slice(0,170));}\n"
    "var tf=window.fetch;if(tf)window.fetch=function(u){tr('fetch',u&&u.url||u);return tf.apply(this,arguments);};\n"
    "var TX=window.XMLHttpRequest;if(TX&&TX.prototype){var to=TX.prototype.open;\n"
    "TX.prototype.open=function(mt,u){if(String(u).indexOf('gb-debug.invalid')<0)tr('xhr '+mt,u);return to.apply(this,arguments);};}\n"
    "var TW=window.Worker;if(TW)window.Worker=function(u,o){tr('worker',u);return new TW(u,o);};\n"
    "tr('env','sw='+!!(navigator.serviceWorker)+' ctl='+!!(navigator.serviceWorker&&navigator.serviceWorker.controller)\n"
    "+' worker='+!!TW+' sab='+(typeof SharedArrayBuffer));}catch(e){gbr('trace err '+gbs(e));}}\n"
    "if(m&64){gbr('yt off');return;}\n"
    "var re=/youtubei\\/v1\\/(player|get_watch|next|browse|search)/,n=0,nf=0,\n"
    "ads=['adPlacements','adSlots','playerAds'];\n"
    "var JP=JSON.parse,JS=JSON.stringify,np=0,nq=0;\n"
    "if(!(m&2048))JSON.stringify=function(v,r,sp){try{var c=v&&v.playbackContext&&v.playbackContext.contentPlaybackContext;\n"
    "if(c&&typeof c==='object'&&c.isInlinePlaybackNoAd!==true){var cp=JP(JS(v));\n"
    "cp.playbackContext.contentPlaybackContext.isInlinePlaybackNoAd=true;\n"
    "if(nq++<10)gbr('yt request no-ad flag set'+(v.videoId?' '+v.videoId:''));return JS.call(this,cp,r,sp);}}catch(e){}\n"
    "return JS.apply(this,arguments);};\n"
    "var rq=/youtubei\\/v1\\/(player|get_watch)/;\n"
    "function flag(q,d){if(!q||typeof q!=='object'||d>3)return 0;var c=q.playbackContext&&q.playbackContext.contentPlaybackContext;\n"
    "if(c&&typeof c==='object'){if(c.isInlinePlaybackNoAd===true)return 0;c.isInlinePlaybackNoAd=true;return 1;}\n"
    "var k,h=0;for(k in q)if(q[k]&&typeof q[k]==='object')h+=flag(q[k],d+1);return h;}\n"
    "function noad(b,u,via){if(m&2048||typeof b!=='string'||!rq.test(String(u))||b.indexOf('contentPlaybackContext')<0)return b;\n"
    "try{var q=JP(b);if(flag(q,0)){b=JS(q);if(nq++<20)gbr('yt request no-ad flag set via '+via+' '+(String(u).match(rq)||[''])[1]\n"
    "+(q.videoId?' '+q.videoId:(q.playerRequest&&q.playerRequest.videoId?' '+q.playerRequest.videoId:'')));}}\n"
    "catch(e){gbr('yt request flag failed '+gbs(e));}return b;}\n"
    "JSON.parse=function(){var r=JP.apply(this,arguments);try{if(r&&typeof r==='object'){\n"
    "var o=Array.isArray(r)?r.slice(0,4):[r],hit=0;for(var i=0;i<o.length;i++){var x=o[i];\n"
    "if(!x||typeof x!=='object')continue;var ys=[x,x.playerResponse];for(var y=0;y<2;y++){var z=ys[y];\n"
    "if(!z||typeof z!=='object')continue;for(var a=0;a<3;a++){var k=ads[a];\n"
    "if(z[k]&&z[k].length){hit++;z[k]=[];}}}}if(hit&&np++<20)gbr('yt parse removed '+hit);}}catch(e){}return r;};\n"
    "function fix(o,d,f){if(!o||typeof o!=='object'||d>24)return;\n"
    "if(Array.isArray(o)){for(var i=o.length-1;i>=0;i--){var e=o[i];\n"
    "if(e&&typeof e==='object'&&e.adSlotRenderer){o.splice(i,1);f.push('adSlotRenderer');}\n"
    "else fix(e,d+1,f);}return;}\n"
    "for(var k in o){var v=o[k];if(ads.indexOf(k)>=0){\n"
    "if(v&&v.length)f.push(k+':'+v.length);if(m&16)delete o[k];else o[k]=[];}\n"
    "else if(v&&typeof v==='object')fix(v,d+1,f);}}\n"
    "function sabr(j,f,d){if(!j||typeof j!=='object'||d>3)return;\n"
    "if(Array.isArray(j)){for(var i=0;i<j.length;i++)sabr(j[i],f,d+1);return;}\n"
    "var sd=j.streamingData;if(sd&&typeof sd==='object'){\n"
    "var af=sd.adaptiveFormats||[],a0=af[0]||{};\n"
    "f.push('SD:'+Object.keys(sd).join('/')+' fmt='+af.length+(a0.url?' url':'')+(a0.signatureCipher?' cipher':''));\n"
    "if((m&1024)&&sd.serverAbrStreamingUrl){delete sd.serverAbrStreamingUrl;f.push('SABR-DROPPED');}}\n"
    "if(j.playerResponse)sabr(j.playerResponse,f,d+1);}\n"
    "function proc(j,s,via,inLen){var f=[];if(!(m&(32|128)))fix(j,0,f);sabr(j,f,0);\n"
    "var o=JS(j);\n"
    "var sp=o.match(/\"[^\"]*(?:ssap|Ssap|SSAP|serverStitched|ServerStitched)[^\"]*\"/g);\n"
    "if(sp){var su={};sp.forEach(function(x){su[x.slice(0,40)]=1;});f.push('SSAP:'+Object.keys(su).slice(0,6).join(','));}\n"
    "var ak={};(o.match(/\"(?:ad|\\w+Ad)\\w*Renderer\"/g)||[]).forEach(function(x){ak[x]=1;});\n"
    "ak=Object.keys(ak).join(',');if(ak)f.push('LEFT:'+ak);\n"
    "if(n++<3||(f.length&&nf++<40)){var ks=[];if(!Array.isArray(j))for(var k in j)\n"
    "ks.push(k+':'+JS(j[k]).length);\n"
    "gbr('yt mode='+m+' '+via+' '+(s.match(re)||[''])[1]+(Array.isArray(j)?' array'+j.length:'')\n"
    "+' in='+inLen+' out='+o.length+' removed='+(f.join(',')||'none')+' play='\n"
    "+(j.playabilityStatus&&j.playabilityStatus.status)+' '+ks.join(' ').slice(0,240));}\n"
    "return o;}\n"
    "var of=window.fetch;\n"
    "if(of)window.fetch=function(u,opt){var s=String(u&&u.url||u);\n"
    "if(opt&&typeof opt.body==='string'&&rq.test(s)){var nb=noad(opt.body,s,'fetch');if(nb!==opt.body){\n"
    "var o2={};for(var k in opt)o2[k]=opt[k];o2.body=nb;arguments[1]=o2;}}\n"
    "var p=of.apply(this,arguments);\n"
    "if(!re.test(s))return p;return p.then(function(r){if(!r||!r.ok||!r.clone)return r;\n"
    "return r.clone().text().then(function(t){var j;try{j=JP(t);}catch(e){\n"
    "gbr('yt not json '+gbs(e));return r;}\n"
    "var o=proc(j,s,'fetch',t.length);if(m&128)o=t;\n"
    "var h={};try{r.headers.forEach(function(v,k){h[k]=v;});}catch(e){}\n"
    "return new Response(o,{status:r.status,statusText:r.statusText,headers:h});},\n"
    "function(e){gbr('yt text failed '+gbs(e));return r;});});};\n"
    "var X=window.XMLHttpRequest,P=X&&X.prototype;if(!P)return;\n"
    "var oo=P.open;\n"
    "P.open=function(mt,u){try{this.__gbu=String(u);}catch(e){}return oo.apply(this,arguments);};\n"
    "var os=P.send;\n"
    "P.send=function(b){if(typeof b==='string'&&this.__gbu)arguments[0]=noad(b,this.__gbu,'xhr');\n"
    "return os.apply(this,arguments);};\n"
    "function hook(name){var d=Object.getOwnPropertyDescriptor(P,name);\n"
    "if(!d||!d.get){gbr('yt xhr no getter '+name);return;}\n"
    "Object.defineProperty(P,name,{configurable:true,enumerable:d.enumerable,get:function(){\n"
    "var v=d.get.call(this);var s=this.__gbu;\n"
    "if(!s||this.readyState!==4||!re.test(s)||v===null||v===undefined||v==='')return v;\n"
    "var c='__gbc_'+name;if(this[c]!==undefined)return this[c];\n"
    "try{var obj=typeof v==='object',j=obj?v:JP(String(v));\n"
    "var o=proc(j,s,'xhr',obj?-1:String(v).length);this[c]=obj?j:((m&128)?v:o);}\n"
    "catch(e){gbr('yt xhr '+name+' '+gbs(e));this[c]=v;}\n"
    "return this[c];}});}\n"
    "hook('responseText');hook('response');\n"
    "})();}catch(e){gbr('yt err '+gbs(e));}\n";

// Applies css/ext once the document exists, and the generic lookup table G
// ("key\tselector" lines) to elements as they appear or change class/id.
const char kInjectTail[] =
    "function inject(){var r=document.documentElement;if(!r)return false;"
    "injected=true;if(css){var s=document.createElement('style');s.textContent=css;"
    "(document.head||r).appendChild(s);}"
    "if(ext.length&&typeof ExtendedCss!=='undefined'){"
    "try{new ExtendedCss({cssRules:ext}).apply();}catch(e){}}"
    "return true;}\n"
    "var gm=null,gd={},gs=null,pend=[],timer=0,injected=false;\n"
    "function gmap(){if(gm)return gm;gm={};var L=G.split('\\n');"
    "for(var i=0;i<L.length;i++){var l=L[i],t=l.indexOf('\\t');if(t<1)continue;"
    "var k=l.substring(0,t),a=gm[k];if(!a)a=gm[k]=[];a.push(l.substring(t+1));}"
    "for(var j=0;j<GX.length;j++)gd[GX[j]]=1;return gm;}\n"
    "function gadd(a,out){for(var i=0;i<a.length;i++){var s=a[i];"
    "if(!gd[s]){gd[s]=1;out.push(s+'{display:none!important}');}}}\n"
    "function gcheck(el,out){var a,id=el.id;if(id&&typeof id==='string'){"
    "a=gm['#'+id];if(a)gadd(a,out);}var c=el.className;"
    "if(c&&typeof c==='string'){var cs=c.split(/\\s+/);"
    "for(var k=0;k<cs.length;k++){if(!cs[k])continue;a=gm['.'+cs[k]];"
    "if(a)gadd(a,out);}}}\n"
    "function flush(){timer=0;var p=pend;pend=[];gmap();var out=[];"
    "for(var i=0;i<p.length;i++){var n=p[i];if(!n||n.nodeType!==1)continue;"
    "gcheck(n,out);if(n.getElementsByTagName){var all=n.getElementsByTagName('*');"
    "for(var j=0;j<all.length;j++)gcheck(all[j],out);}}"
    "if(out.length){var r=document.documentElement;if(!r)return;"
    "if(!gs){gs=document.createElement('style');(document.head||r).appendChild(gs);}"
    "gs.textContent+=out.join('\\n')+'\\n';}}\n"
    "function queue(n){pend.push(n);if(!timer)timer=setTimeout(flush,200);}\n"
    "inject();\n"
    "try{var o=new MutationObserver(function(ms){"
    "if(!injected){inject();if(injected&&!G)o.disconnect();}"
    "if(!G)return;for(var i=0;i<ms.length;i++){var m=ms[i];"
    "if(m.type==='attributes'){queue(m.target);}else{var an=m.addedNodes;"
    "for(var j=0;j<an.length;j++)queue(an[j]);}}});"
    "var opt={childList:true,subtree:true};"
    "if(G){opt.attributes=true;opt.attributeFilter=['class','id'];}"
    "if(!injected||G)o.observe(document,opt);}catch(e){"
    "document.addEventListener('DOMContentLoaded',function(){"
    "if(!injected)inject();"
    "if(G&&document.documentElement)queue(document.documentElement);});}\n"
    "if(G&&document.documentElement)queue(document.documentElement);\n"
    "})();\n";

}  // namespace

// ------------------------------------------------------------------ API

bool EngineShouldBlock(const Request& r, uint32_t page_flags, std::string* why) {
  if (r.host.empty()) return false;
  if (page_flags & (kPageDocument | kPageUrlblock)) return false;
  const Data& d = GetData();
  Verdict v;
  CheckHostLists(d, r, &v);
  if (!r.domain_lists_only) {
    const std::string lc = Lower(r.url);
    size_t hb = 0;
    size_t he = 0;
    HostBounds(lc, &hb, &he);
    std::vector<uint32_t> hashes;
    UrlTokenHashes(lc, &hashes);
    ForEachCandidate(hashes, [&](uint32_t i) {
      NetRule nr;
      ParseNetRule(i, &nr);
      if (!NetRuleMatches(nr, r, lc, hb, he)) return true;
      if (nr.flags & kFlagException) {
        if (nr.flags & kFlagImportant) {
          v.allow_important = true;
          return false;
        }
        v.allow = true;
      } else {
        if (nr.flags & kFlagImportant) {
          v.block_important = true;
          v.why.assign(nr.pat, nr.pat_n);
        } else {
          v.block = true;
          if (v.why.empty()) v.why.assign(nr.pat, nr.pat_n);
        }
      }
      return true;
    });
  }
  bool blocked =
      !v.allow_important && (v.block_important || (v.block && !v.allow));
  if (blocked && why) *why = v.why;
  return blocked;
}

uint32_t EnginePageFlags(const std::string& page_url, const std::string& page_host,
                         size_t registry_len) {
  if (page_url.empty() || page_host.empty()) return 0;
  const std::string lc = Lower(page_url);
  size_t hb = 0;
  size_t he = 0;
  HostBounds(lc, &hb, &he);
  std::vector<uint32_t> hashes;
  UrlTokenHashes(lc, &hashes);
  uint32_t flags = 0;
  ForEachCandidate(hashes, [&](uint32_t i) {
    NetRule nr;
    ParseNetRule(i, &nr);
    if (!(nr.flags & kFlagPage)) return true;
    if (!DomainListAllows(nr.dom, nr.dom_n, page_host, registry_len)) return true;
    const std::string& u = (nr.flags & kFlagMatchCase) ? page_url : lc;
    if (MatchPattern(u, hb, he, nr.pat, nr.pat_n)) flags |= nr.types;
    return true;
  });
  if (flags & kPageDocument) flags = 0xffffffffu;
  return flags;
}

std::string EnginePageScript(const std::string& host, size_t registry_len,
                             uint32_t page_flags, uint32_t mode) {
  if (host.empty() || (page_flags & kPageDocument)) return std::string();
  const Data& d = GetData();

  // Domain-specific entries for the host, its parents and "label.*" forms.
  std::vector<uint32_t> inc;
  std::vector<uint32_t> exc;
  size_t s = 0;
  while (s < host.size()) {
    std::string p = host.substr(s);
    std::string keys[2] = {p, std::string()};
    if (registry_len && p.size() > registry_len + 1)
      keys[1] = p.substr(0, p.size() - registry_len) + "*";
    for (const std::string& key : keys) {
      if (key.empty()) continue;
      long k = d.cos_keys.Find(key.data(), key.size());
      if (k < 0) continue;
      for (uint32_t j = kAdgCosKeyStart[k]; j < kAdgCosKeyStart[k + 1]; ++j) {
        uint32_t ref = kAdgCosRefs[j];
        if (ref & kExceptionRef) {
          exc.push_back(ref & ~kExceptionRef);
        } else {
          inc.push_back(ref);
        }
      }
    }
    size_t dot = host.find('.', s);
    if (dot == std::string::npos) break;
    s = dot + 1;
  }
  std::sort(inc.begin(), inc.end());
  inc.erase(std::unique(inc.begin(), inc.end()), inc.end());
  std::sort(exc.begin(), exc.end());
  exc.erase(std::unique(exc.begin(), exc.end()), exc.end());
  auto excluded = [&](uint32_t i) {
    return std::binary_search(exc.begin(), exc.end(), i);
  };

  const bool specific_css = !(page_flags & (kPageElemhide | kPageSpecifichide));
  const bool generic_css = !(page_flags & (kPageElemhide | kPageGenerichide));
  const bool js = !(page_flags & kPageJsinject);

  // Cobalt always runs scripts, so <noscript> content is never shown.
  std::string css = "noscript{display:none!important}\n";
  std::vector<std::pair<const char*, size_t>> ext;
  std::vector<std::pair<const char*, size_t>> scriptlets;
  std::vector<std::pair<const char*, size_t>> scripts;
  auto take = [&](uint32_t i, bool specific) {
    size_t n = 0;
    const char* e = CosEntry(i, &n);
    if (n < 1) return;
    const char* b = e + 1;
    const size_t bn = n - 1;
    const bool css_ok = specific ? specific_css : generic_css;
    switch (e[0]) {
      case 'H':
        if (css_ok) {
          css.append(b, bn);
          css.append("{display:none!important}\n");
        }
        break;
      case 'C':
        if (css_ok) {
          css.append(b, bn);
          css.push_back('\n');
        }
        break;
      case 'X':
        if (css_ok) ext.emplace_back(b, bn);
        break;
      case 'S':
        if (js) scriptlets.emplace_back(b, bn);
        break;
      case 'J':
        if (js) scripts.emplace_back(b, bn);
        break;
      default:
        break;
    }
  };

  // Generic entries. Hiding selectors keyed by a class or id go to the page as
  // a lookup table (G), applied only for classes/ids that appear on the page;
  // the rest is the prebuilt CSS, rebuilt when this page has an exception for
  // one of its selectors. Generic ExtendedCss rules are added only when the
  // site has extended rules of its own (ExtendedCss is not loaded otherwise).
  const bool generic_on = generic_css && !(mode & kModeNoGenericCosmetic);
  const bool keyed_as_css = (mode & kModeGenericAsCss) != 0;
  bool rebuild_generic_css = false;
  std::string keyed_excluded;  // JavaScript array items
  for (uint32_t e : exc) {
    size_t n = 0;
    const char* t = CosEntry(e, &n);
    if (t[0] != 'H' || !IsGeneric(e)) continue;
    if (IsKeyed(e)) {
      if (!keyed_excluded.empty()) keyed_excluded.push_back(',');
      AppendJsString(&keyed_excluded, t + 1, n - 1);
    } else {
      rebuild_generic_css = true;
    }
  }
  if (generic_on && !rebuild_generic_css) css.append(kAdgGenericCss);
  std::vector<std::pair<const char*, size_t>> generic_ext;
  for (size_t k = 0; k < kAdgCosGenericCount; ++k) {
    uint32_t e = kAdgCosGeneric[k];
    if (excluded(e)) continue;
    size_t n = 0;
    const char* t = CosEntry(e, &n);
    switch (t[0]) {
      case 'H':
        if (!generic_on) break;
        if (IsKeyed(e) ? keyed_as_css : rebuild_generic_css) take(e, false);
        break;
      case 'X':
        if (generic_on) generic_ext.emplace_back(t + 1, n - 1);
        break;
      case 'C':
        if (generic_on) take(e, false);
        break;
      default:
        take(e, false);  // scriptlets and scripts
        break;
    }
  }
  for (uint32_t i : inc) {
    if (!excluded(i) && !IsGeneric(i)) take(i, true);
  }
  if (!ext.empty()) ext.insert(ext.end(), generic_ext.begin(), generic_ext.end());
  const bool use_lookup = generic_on && !keyed_as_css && kAdgCosGenericKeyedCount > 0;

  if (css.empty() && ext.empty() && scriptlets.empty() && scripts.empty() && !use_lookup)
    return std::string();

  std::string out = "(function(){\n";
  out += kPolyfills;
  out += kDebugHead;
  const bool probes = (mode & kModeAdProbes) != 0;
  if (probes) out += kAdProbes;
  std::vector<uint32_t> defined;
  std::string sl_names;
  for (const auto& sl : scriptlets) {
    // "index\tsource-json\targs-json"
    const char* t1 = static_cast<const char*>(memchr(sl.first, '\t', sl.second));
    if (!t1) continue;
    const char* end = sl.first + sl.second;
    const char* t2 = static_cast<const char*>(memchr(t1 + 1, '\t', end - t1 - 1));
    if (!t2) continue;
    uint32_t idx = static_cast<uint32_t>(strtoul(sl.first, nullptr, 10));
    if (idx >= kAdgSlCount) continue;
    std::string fn = "F" + std::to_string(idx);
    if (std::find(defined.begin(), defined.end(), idx) == defined.end()) {
      defined.push_back(idx);
      out += "var " + fn + "=(" + kAdgSlCode[idx] + ");\n";
    }
    // With the ad probes on, the scriptlets run verbose so they log what they do.
    std::string src(t1 + 1, t2 - t1 - 1);
    const size_t vpos = src.find("\"verbose\":false");
    if (probes && vpos != std::string::npos) src.replace(vpos, 15, "\"verbose\":true");
    std::string name = "?";
    const size_t npos_ = src.find("\"name\":\"");
    if (npos_ != std::string::npos) {
      const size_t b = src.find('"', npos_ + 8);
      if (b != std::string::npos) name = src.substr(npos_ + 8, b - npos_ - 8);
    }
    sl_names += name + " ";
    out += "try{" + fn + "(" + src + ",";
    out.append(t2 + 1, end - t2 - 1);
    out += ");}catch(e){gbr('scriptlet " + name + " threw '+gbs(e));}\n";
  }
  if (probes) {
    out += "gbr('scriptlets ran: " + sl_names + "');\n";
    out += "try{gbr('fetch replaced by scriptlets: '+(window.fetch!==gfp));}catch(e){}\n";
  }
  out += "var gbmode=" + std::to_string(mode) + ";\n";
  out += kYtTv;
  if (probes) {
    out += "try{"
           "if(window.fetch)window.fetch=gprobe('FINAL',window.fetch);}catch(e){}\n";
  }
  for (const auto& sc : scripts) {
    out += "try{\n";
    out.append(sc.first, sc.second);
    out += "\n}catch(e){}\n";
  }
  if (!ext.empty()) {
    out += kAdgExtCss;
    out += "\ntry{ExtendedCss.init();}catch(e){}\n";
  }
  out += "var css=";
  AppendJsString(&out, css.data(), css.size());
  out += ";\nvar ext=[";
  for (size_t i = 0; i < ext.size(); ++i) {
    if (i) out.push_back(',');
    AppendJsString(&out, ext[i].first, ext[i].second);
  }
  out += "];\nvar G=";
  out += use_lookup ? kAdgGenericKeyedJs : "\"\"";
  out += ";\nvar GX=[" + keyed_excluded + "];\n";
  out += kInjectTail;
  return out;
}

std::string EngineInfo() {
  return std::string(kAdgInfo) + ": " + kAdgStats;
}

}  // namespace adguard
}  // namespace network
}  // namespace cobalt
