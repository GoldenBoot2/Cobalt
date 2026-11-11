// GoldenBoot: AdGuard filter lists for Cobalt.
// Rules come from AdGuard's public filter lists (filters.adtidy.org), compiled at
// build time by patches/adguard_rules.py into cobalt/network/adguard_rules.inc and
// applied by adguard_engine.cc.

#ifndef COBALT_NETWORK_ADGUARD_FILTER_H_
#define COBALT_NETWORK_ADGUARD_FILTER_H_

#include <stdint.h>

#include <string>

#include "url/gurl.h"

namespace cobalt {
namespace network {
namespace adguard {

// NetworkDelegate: true when |url| is blocked. |initiator| is the page that
// started the request (empty if none). The content type is not known here, so
// only rules without a type can block (typed exceptions still allow).
bool ShouldBlock(const GURL& url, const GURL& initiator);

// web::CspDelegateSecure::CanLoad: true when a resource of a document is
// blocked. |csp_type| is a web::CspDelegate::ResourceType, |page| the document.
bool ShouldBlockResource(const GURL& url, const GURL& page, int csp_type);

// WebModule: JavaScript that applies the cosmetic rules (element hiding,
// ExtendedCss, CSS) and scriptlets for |page|, or "" if none.
std::string PageScript(const GURL& page);

// Logs how long the page script took to run (WebModule).
void LogPageScriptRun(const GURL& page, int64_t ms);

}  // namespace adguard
}  // namespace network
}  // namespace cobalt

#endif  // COBALT_NETWORK_ADGUARD_FILTER_H_
