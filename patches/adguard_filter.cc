// GoldenBoot: AdGuard filter lists for Cobalt - Chromium/Cobalt side.
// The rule engine is adguard_engine.cc; this file converts URLs and logs.

#include "cobalt/network/adguard_filter.h"

#include <stdint.h>

#include <mutex>
#include <string>

#include "cobalt/network/adguard_engine.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"

#if defined(__ANDROID__)
#include <android/log.h>
#endif

namespace cobalt {
namespace network {
namespace adguard {

namespace {

namespace rcd = net::registry_controlled_domains;

#if defined(__ANDROID__)
#define GB_LOG(...) __android_log_print(ANDROID_LOG_INFO, "GBAdGuard", __VA_ARGS__)
#else
#define GB_LOG(...) ((void)0)
#endif

std::once_flag g_init_once;
std::mutex* g_page_mutex = nullptr;  // heap: no exit-time destructor
std::string* g_last_page = nullptr;
uint32_t g_last_page_flags = 0;

void InitOnce() {
  std::call_once(g_init_once, [] {
    g_page_mutex = new std::mutex();
    g_last_page = new std::string();
    std::string info = EngineInfo();
    GB_LOG("%s", info.c_str());
  });
}

size_t RegistryLength(const std::string& host) {
  size_t n = rcd::GetCanonicalHostRegistryLength(
      host, rcd::EXCLUDE_UNKNOWN_REGISTRIES, rcd::EXCLUDE_PRIVATE_REGISTRIES);
  return n == std::string::npos ? 0 : n;
}

uint32_t PageFlags(const GURL& page) {
  if (!page.is_valid() || !page.SchemeIsHTTPOrHTTPS() || page.host().empty())
    return 0;
  const std::string& spec = page.spec();
  InitOnce();
  {
    std::lock_guard<std::mutex> lock(*g_page_mutex);
    if (*g_last_page == spec) return g_last_page_flags;
  }
  const std::string host = page.host();
  uint32_t flags = EnginePageFlags(spec, host, RegistryLength(host));
  std::lock_guard<std::mutex> lock(*g_page_mutex);
  *g_last_page = spec;
  g_last_page_flags = flags;
  return flags;
}

// web::CspDelegate::ResourceType (cobalt/web/csp_delegate.h) -> ContentType.
uint32_t TypeFromCsp(int csp_type) {
  switch (csp_type) {
    case 0:  // kFont
      return kTypeFont;
    case 1:  // kImage
      return kTypeImage;
    case 3:  // kMedia
      return kTypeMedia;
    case 4:  // kScript
    case 6:  // kWorker
      return kTypeScript;
    case 5:  // kStyle
      return kTypeStylesheet;
    case 7:  // kXhr
      return kTypeXhr;
    case 8:  // kWebSocket
      return kTypeWebsocket;
    default:  // kLocation (navigation): not filtered
      return 0;
  }
}

bool Decide(const GURL& url, const GURL& page, uint32_t type) {
  if (!url.SchemeIsHTTPOrHTTPS() && !url.SchemeIsWSOrWSS()) return false;
  InitOnce();
  Request r;
  r.url = url.spec();
  r.host = url.host();
  if (r.host.empty()) return false;
  const bool has_page = page.is_valid() && !page.host().empty();
  if (has_page) {
    r.page_host = page.host();
    r.page_registry_len = RegistryLength(r.page_host);
    r.third_party = !rcd::SameDomainOrHost(url, page, rcd::INCLUDE_PRIVATE_REGISTRIES);
  }
  r.type = type;
  std::string why;
  if (!EngineShouldBlock(r, has_page ? PageFlags(page) : 0, &why)) return false;
  std::string shown = r.url.size() > 160 ? r.url.substr(0, 160) + "..." : r.url;
  GB_LOG("blocked %s (%s)", shown.c_str(), why.c_str());
  return true;
}

}  // namespace

bool ShouldBlock(const GURL& url, const GURL& initiator) {
  return Decide(url, initiator, 0);
}

bool ShouldBlockResource(const GURL& url, const GURL& page, int csp_type) {
  uint32_t type = TypeFromCsp(csp_type);
  if (!type) return false;
  return Decide(url, page, type);
}

std::string PageScript(const GURL& page) {
  if (!page.is_valid() || !page.SchemeIsHTTPOrHTTPS()) return std::string();
  const std::string host = page.host();
  if (host.empty()) return std::string();
  InitOnce();
  std::string script = EnginePageScript(host, RegistryLength(host), PageFlags(page));
  GB_LOG("page script for %s: %zu bytes", host.c_str(), script.size());
  return script;
}

}  // namespace adguard
}  // namespace network
}  // namespace cobalt
