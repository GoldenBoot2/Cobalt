// GoldenBoot: rewrites CSS that Cobalt's parser does not understand into
// equivalents it does, before parsing:
//  - var(--name[, fallback]) -> the value of --name (custom properties are
//    collected from every style sheet parsed so far, first definition wins
//    within a sheet, later sheets override earlier ones);
//  - clamp(a, b, c) -> b, min(a, b, ...) -> a, max(..., z) -> z;
//  - inset: a [b [c [d]]] -> top/right/bottom/left.
// Plain C++, so it can be tested on its own.

#ifndef COBALT_CSS_PARSER_CSS_COMPAT_H_
#define COBALT_CSS_PARSER_CSS_COMPAT_H_

#include <string>

namespace cobalt {
namespace css_parser {
namespace css_compat {

// Returns |input| itself when nothing needs changing, otherwise the rewritten
// text stored in |*storage|.
const std::string& Process(const std::string& input, std::string* storage);

}  // namespace css_compat
}  // namespace css_parser
}  // namespace cobalt

#endif  // COBALT_CSS_PARSER_CSS_COMPAT_H_
