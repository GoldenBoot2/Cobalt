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

struct Data {
  Data()
      : important(kAdgImportant),
        block_all(kAdgBlockAll),
        block_3p(kAdgBlock3p),
        allow(kAdgAllow),
        cos_keys(kAdgCosKeys) {}
  SortedList important;
  SortedList block_all;
  SortedList block_3p;
  SortedList allow;
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

void CheckHostLists(const Data& d, const Request& r, Verdict* v) {
  const std::string& host = r.host;
  size_t s = 0;
  while (s < host.size()) {
    const char* p = host.data() + s;
    size_t n = host.size() - s;
    if (d.important.Contains(p, n)) {
      v->block_important = true;
      v->why = "||" + host.substr(s) + "^$important";
    }
    if (d.allow.Contains(p, n)) v->allow = true;
    if (d.block_all.Contains(p, n)) {
      v->block = true;
      if (v->why.empty()) v->why = "||" + host.substr(s) + "^";
    }
    if (r.third_party && d.block_3p.Contains(p, n)) {
      v->block = true;
      if (v->why.empty()) v->why = "||" + host.substr(s) + "^$third-party";
    }
    size_t dot = host.find('.', s);
    if (dot == std::string::npos) break;
    s = dot + 1;
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

  std::string css;
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
  std::vector<uint32_t> defined;
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
    out += "try{" + fn + "(";
    out.append(t1 + 1, t2 - t1 - 1);
    out += ",";
    out.append(t2 + 1, end - t2 - 1);
    out += ");}catch(e){}\n";
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
