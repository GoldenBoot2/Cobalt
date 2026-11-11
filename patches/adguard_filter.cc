// GoldenBoot: AdGuard filter-list network blocking for Cobalt.

#include "cobalt/network/adguard_filter.h"

#include <stdint.h>
#include <string.h>

#include <string>
#include <vector>

#include "net/base/registry_controlled_domains/registry_controlled_domain.h"

#if defined(__ANDROID__)
#include <android/log.h>
#endif

namespace cobalt {
namespace network {
namespace adguard {

namespace {

// Defines kAdgImportant, kAdgBlockAll, kAdgBlock3p, kAdgAllow and kAdgInfo:
// sorted host names, each ending in '\n'. Kept in read-only data; only an
// offset table is built in memory.
#include "cobalt/network/adguard_rules.inc"

class HostList {
 public:
  explicit HostList(const char* blob) : blob_(blob) {
    const char* p = blob;
    while (*p) {
      offsets_.push_back(static_cast<uint32_t>(p - blob));
      const char* nl = strchr(p, '\n');
      if (!nl) break;
      p = nl + 1;
    }
  }

  bool Contains(const char* s, size_t n) const {
    size_t lo = 0;
    size_t hi = offsets_.size();
    while (lo < hi) {
      size_t mid = lo + (hi - lo) / 2;
      int c = Compare(blob_ + offsets_[mid], s, n);
      if (c == 0) return true;
      if (c < 0) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    return false;
  }

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

struct Lists {
  Lists()
      : important(kAdgImportant),
        block_all(kAdgBlockAll),
        block_3p(kAdgBlock3p),
        allow(kAdgAllow) {}
  HostList important;
  HostList block_all;
  HostList block_3p;
  HostList allow;
};

const Lists& GetLists() {
  static const Lists* lists = [] {
    Lists* l = new Lists();
#if defined(__ANDROID__)
    __android_log_print(ANDROID_LOG_INFO, "GBAdGuard",
                        "%s: important %zu, block %zu, block-3p %zu, allow %zu",
                        kAdgInfo, l->important.size(), l->block_all.size(),
                        l->block_3p.size(), l->allow.size());
#endif
    return l;
  }();
  return *lists;
}

bool IsThirdParty(const GURL& url, const GURL& initiator) {
  if (!initiator.is_valid() || initiator.host().empty()) return false;
  return !net::registry_controlled_domains::SameDomainOrHost(
      url, initiator,
      net::registry_controlled_domains::INCLUDE_PRIVATE_REGISTRIES);
}

void LogBlocked(const std::string& host, const char* why) {
#if defined(__ANDROID__)
  __android_log_print(ANDROID_LOG_INFO, "GBAdGuard", "blocked %s (%s)",
                      host.c_str(), why);
#endif
}

}  // namespace

bool ShouldBlock(const GURL& url, const GURL& initiator) {
  if (!url.SchemeIsHTTPOrHTTPS() && !url.SchemeIsWSOrWSS()) return false;
  const std::string host = url.host();
  if (host.empty()) return false;
  const Lists& lists = GetLists();

  // The host itself and every parent domain ("a.b.c" -> "b.c" -> "c"),
  // like AdGuard's "||domain^" matching.
  std::vector<size_t> starts(1, 0);
  for (size_t i = 0; i + 1 < host.size(); ++i) {
    if (host[i] == '.') starts.push_back(i + 1);
  }

  for (size_t s : starts) {
    if (lists.important.Contains(host.data() + s, host.size() - s)) {
      LogBlocked(host, "important");
      return true;
    }
  }
  for (size_t s : starts) {
    if (lists.allow.Contains(host.data() + s, host.size() - s)) return false;
  }
  bool third_known = false;
  bool third = false;
  for (size_t s : starts) {
    const char* p = host.data() + s;
    size_t n = host.size() - s;
    if (lists.block_all.Contains(p, n)) {
      LogBlocked(host, "rule");
      return true;
    }
    if (lists.block_3p.Contains(p, n)) {
      if (!third_known) {
        third = IsThirdParty(url, initiator);
        third_known = true;
      }
      if (third) {
        LogBlocked(host, "third-party rule");
        return true;
      }
    }
  }
  return false;
}

}  // namespace adguard
}  // namespace network
}  // namespace cobalt
