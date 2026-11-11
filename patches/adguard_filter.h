// GoldenBoot: AdGuard filter-list network blocking for Cobalt.
// Rules come from AdGuard's public filter lists (filters.adtidy.org), converted at
// build time by patches/adguard_rules.py into cobalt/network/adguard_rules.inc.

#ifndef COBALT_NETWORK_ADGUARD_FILTER_H_
#define COBALT_NETWORK_ADGUARD_FILTER_H_

#include "url/gurl.h"

namespace cobalt {
namespace network {
namespace adguard {

// True when |url| matches an AdGuard blocking rule and no exception rule.
// |initiator| is the URL of the page that started the request (empty if none);
// it decides $third-party rules.
bool ShouldBlock(const GURL& url, const GURL& initiator);

}  // namespace adguard
}  // namespace network
}  // namespace cobalt

#endif  // COBALT_NETWORK_ADGUARD_FILTER_H_
