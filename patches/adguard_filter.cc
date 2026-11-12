// GoldenBoot: AdGuard filter lists for Cobalt - Chromium/Cobalt side.
// The rule engine is adguard_engine.cc; this file converts URLs and logs.

#include "cobalt/network/adguard_filter.h"

#include <stdint.h>
#include <stdlib.h>

#include <mutex>
#include <string>

#include "cobalt/network/adguard_engine.h"
#include "net/base/registry_controlled_domains/registry_controlled_domain.h"

#if defined(__ANDROID__)
#include <android/log.h>
#include <sys/system_properties.h>
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

// Test switches: adb shell setprop debug.gb.adguard <Mode bits> (0 = all on).
uint32_t ReadMode() {
#if defined(__ANDROID__)
  char v[PROP_VALUE_MAX] = {0};
  if (__system_property_get("debug.gb.adguard", v) > 0)
    return static_cast<uint32_t>(strtoul(v, nullptr, 0));
#endif
  return 0;
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
  if (url.host() == "gb-debug.invalid") {  // debug channel (adguard_engine.cc)
    std::string q = url.query();
    if (q.size() > 600) q.resize(600);
    GB_LOG("js %s: %s", page.host().c_str(), q.c_str());
    return true;
  }
  const uint32_t mode = ReadMode();
  if ((mode & kModeTraceYt) && url.path().find("/youtubei/") != std::string::npos) {
    std::string shown = url.spec().size() > 200 ? url.spec().substr(0, 200) : url.spec();
    GB_LOG("trace net type=%u page=%s %s", type, page.host().c_str(), shown.c_str());
  }
  if (mode & kModeNoNetwork) return false;
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
  const uint32_t mode = ReadMode();
  if (mode & kModeNoPageScript) {
    GB_LOG("page script for %s: off (mode %u)", host.c_str(), mode);
    return std::string();
  }
  std::string script =
      EnginePageScript(host, RegistryLength(host), PageFlags(page), mode);
  GB_LOG("page script for %s: %zu bytes (mode %u)", host.c_str(), script.size(), mode);
  return script;
}

void LogPageScriptRun(const GURL& page, int64_t ms) {
  GB_LOG("page script for %s ran in %lld ms", page.host().c_str(),
         static_cast<long long>(ms));
}

}  // namespace adguard
}  // namespace network
}  // namespace cobalt
