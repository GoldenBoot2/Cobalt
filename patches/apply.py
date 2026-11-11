"""Applies the GoldenBoot changes to a youtube/cobalt 25.lts checkout.

Usage: python3 apply.py <cobalt source dir>
 1. AdGuard filter lists: copies adguard_engine.{h,cc} and adguard_filter.{h,cc} into
    cobalt/network and adds them to its BUILD.gn; adguard_rules.inc is generated separately by
    adguard_rules.py. Hooks:
    - NetworkDelegate::OnBeforeURLRequest: every request (blocked = ERR_BLOCKED_BY_CLIENT);
    - CspDelegateSecure::CanLoad: resource loads with their type (script, image, xhr...);
    - WebModule::Impl: runs the page's cosmetic rules and scriptlets before the page's own
      scripts.
 2. Lower memory limits for 512 MB TVs: built-in memory switches (CobaltActivity DEBUG_ARGS,
    used in release builds too) and the Android resource limits read by ResourceOverlay.
Every edit checks that its anchor exists exactly once, so a changed source fails loudly.
"""
import os, re, shutil, sys

SRC = sys.argv[1]
HERE = os.path.dirname(os.path.abspath(__file__))


def edit(rel, old, new, count=1):
    p = os.path.join(SRC, rel)
    s = open(p, encoding='utf-8').read()
    n = s.count(old)
    assert n == count, '%s: anchor found %d times: %r' % (rel, n, old[:60])
    s = s.replace(old, new)
    open(p, 'w', encoding='utf-8', newline='\n').write(s)
    print('patched', rel)


# 1. AdGuard network blocking
net = os.path.join(SRC, 'cobalt', 'network')
for f in ('adguard_engine.h', 'adguard_engine.cc', 'adguard_filter.h', 'adguard_filter.cc'):
    shutil.copyfile(os.path.join(HERE, f), os.path.join(net, f))
    print('copied', f)
assert os.path.isfile(os.path.join(net, 'adguard_rules.inc')), 'run adguard_rules.py first'

edit('cobalt/network/network_delegate.cc',
     '#include "cobalt/network/local_network.h"\n',
     '#include "cobalt/network/adguard_filter.h"\n#include "cobalt/network/local_network.h"\n')
edit('cobalt/network/network_delegate.cc',
     '  const GURL& url = request->url();\n  if (url.SchemeIsCryptographic()',
     '  const GURL& url = request->url();\n'
     '  // GoldenBoot: AdGuard filter lists.\n'
     '  if (adguard::ShouldBlock(url, request->initiator().has_value()\n'
     '                                    ? request->initiator()->GetURL()\n'
     '                                    : GURL())) {\n'
     '    return net::ERR_BLOCKED_BY_CLIENT;\n'
     '  }\n'
     '  if (url.SchemeIsCryptographic()')
edit('cobalt/network/BUILD.gn',
     '    "network_delegate.cc",\n    "network_delegate.h",\n',
     '    "adguard_engine.cc",\n    "adguard_engine.h",\n'
     '    "adguard_filter.cc",\n    "adguard_filter.h",\n    "adguard_rules.inc",\n'
     '    "network_delegate.cc",\n    "network_delegate.h",\n')

# Typed checks in the CSP delegate (it knows the resource type and the document URL).
edit('cobalt/web/csp_delegate.h',
     '  csp::CSPHeaderPolicy csp_header_policy_;\n',
     '  csp::CSPHeaderPolicy csp_header_policy_;\n\n'
     '  // GoldenBoot: document URL for the AdGuard filter.\n'
     '  GURL adguard_page_url_;\n')
edit('cobalt/web/csp_delegate.cc',
     '#include "base/bind.h"\n',
     '#include "base/bind.h"\n#include "cobalt/network/adguard_filter.h"\n')
edit('cobalt/web/csp_delegate.cc',
     '  csp_header_policy_ = csp_header_policy;\n',
     '  csp_header_policy_ = csp_header_policy;\n  adguard_page_url_ = url;\n')
edit('cobalt/web/csp_delegate.cc',
     '      did_redirect ? csp::kDidRedirect : csp::kDidNotRedirect;\n',
     '      did_redirect ? csp::kDidRedirect : csp::kDidNotRedirect;\n\n'
     '  // GoldenBoot: AdGuard rules for this resource type and document.\n'
     '  if (::cobalt::network::adguard::ShouldBlockResource(\n'
     '          url, adguard_page_url_, static_cast<int>(type))) {\n'
     '    return false;\n'
     '  }\n')

# Cosmetic rules and scriptlets: run before the page's own scripts.
edit('cobalt/browser/web_module.cc',
     '#include "cobalt/browser/web_module.h"\n',
     '#include "cobalt/browser/web_module.h"\n\n#include "cobalt/network/adguard_filter.h"\n')
edit('cobalt/browser/web_module.cc',
     '  web_context_->SetupFinished();\n  is_running_ = true;\n',
     '  web_context_->SetupFinished();\n  is_running_ = true;\n\n'
     '  // GoldenBoot: AdGuard cosmetic rules and scriptlets for this page.\n'
     '  {\n'
     '    const std::string adguard_script =\n'
     '        ::cobalt::network::adguard::PageScript(data.initial_url);\n'
     '    if (!adguard_script.empty()) {\n'
     '      bool adguard_ok = false;\n'
     '      const base::TimeTicks adguard_start = base::TimeTicks::Now();\n'
     '      web_context_->script_runner()->Execute(\n'
     '          adguard_script, base::SourceLocation("[GoldenBoot AdGuard]", 1, 1),\n'
     '          true /*mute_errors*/, &adguard_ok);\n'
     '      ::cobalt::network::adguard::LogPageScriptRun(\n'
     '          data.initial_url,\n'
     '          (base::TimeTicks::Now() - adguard_start).InMilliseconds());\n'
     '    }\n'
     '  }\n')

# 3a. <noscript>: Cobalt always runs scripts but draws <noscript> content and applies <style>
# elements inside it (pages use that to hide themselves when JavaScript is off). Such styles are
# skipped here; the page script also hides <noscript> (adguard_engine.cc).
edit('cobalt/dom/html_style_element.cc',
     'void HTMLStyleElement::Process() {\n  Document* document = node_document();\n',
     'void HTMLStyleElement::Process() {\n  Document* document = node_document();\n\n'
     '  // GoldenBoot: scripting is always on, so a <style> inside <noscript> does\n'
     '  // not apply.\n'
     '  for (Element* p = parent_element(); p; p = p->parent_element()) {\n'
     '    if (p->local_name() == std::string("noscript")) return;\n'
     '  }\n')

# 3c. <script defer>: Cobalt ignores "defer" and runs a parser-inserted <script src defer> at
# its place in <head> (synchronously), before <body> exists. Such scripts are now held back
# and run in order when parsing ends, just before DOMContentLoaded, as in browsers.
edit('cobalt/dom/document.h',
     '  std::deque<HTMLScriptElement*>* scripts_to_be_executed() {\n'
     '    return &scripts_to_be_executed_;\n  }\n',
     '  std::deque<HTMLScriptElement*>* scripts_to_be_executed() {\n'
     '    return &scripts_to_be_executed_;\n  }\n\n'
     '  // GoldenBoot: <script defer> elements held back until parsing ends.\n'
     '  std::vector<scoped_refptr<HTMLScriptElement>>* gb_deferred_scripts() {\n'
     '    return &gb_deferred_scripts_;\n  }\n')
edit('cobalt/dom/document.h',
     '  std::deque<HTMLScriptElement*> scripts_to_be_executed_;\n',
     '  std::deque<HTMLScriptElement*> scripts_to_be_executed_;\n'
     '  std::vector<scoped_refptr<HTMLScriptElement>> gb_deferred_scripts_;\n')
edit('cobalt/dom/html_script_element.h',
     '\n public:\n',
     '\n public:\n  // GoldenBoot: runs a held-back <script defer> (end of parsing).\n'
     '  void RunDeferred();\n\n')
edit('cobalt/dom/html_script_element.h',
     '  bool is_already_started_;\n',
     '  bool is_already_started_;\n  bool gb_defer_released_ = false;  // GoldenBoot\n')
edit('cobalt/dom/html_script_element.cc',
     '  if (HasAttribute("src") && is_parser_inserted_ && !async()) {\n',
     '  if (HasAttribute("src") && is_parser_inserted_ && !async() &&\n'
     '      HasAttribute("defer") && !gb_defer_released_) {\n'
     '    // GoldenBoot: hold <script defer> until parsing ends (RunDeferred).\n'
     '    is_already_started_ = false;\n'
     '    document_->gb_deferred_scripts()->push_back(this);\n'
     '    return;\n'
     '  }\n'
     '  if (HasAttribute("src") && is_parser_inserted_ && !async()) {\n')
edit('cobalt/dom/html_script_element.cc',
     'void HTMLScriptElement::Prepare() {\n',
     'void HTMLScriptElement::RunDeferred() {\n'
     '  gb_defer_released_ = true;\n'
     '  Prepare();\n'
     '}\n\n'
     'void HTMLScriptElement::Prepare() {\n')
edit('cobalt/dom_parser/libxml_parser_wrapper.cc',
     '#include "cobalt/dom/element.h"\n',
     '#include "cobalt/dom/element.h"\n#include "cobalt/dom/html_script_element.h"\n\n'
     '#include <vector>  // GoldenBoot\n')
edit('cobalt/dom_parser/libxml_parser_wrapper.cc',
     '    document_->CollectTimingInfoAndDispatchEvent();\n',
     '    // GoldenBoot: run held-back <script defer> elements in order.\n'
     '    std::vector<scoped_refptr<dom::HTMLScriptElement>> gb_deferred;\n'
     '    gb_deferred.swap(*document_->gb_deferred_scripts());\n'
     '    for (const auto& script : gb_deferred) script->RunDeferred();\n'
     '    document_->CollectTimingInfoAndDispatchEvent();\n')

# 3b. CSS that Cobalt cannot parse (custom properties, clamp/min/max, inset) is rewritten
# before parsing: css_compat.{h,cc} in cobalt/css_parser.
cp = os.path.join(SRC, 'cobalt', 'css_parser')
for f in ('css_compat.h', 'css_compat.cc'):
    shutil.copyfile(os.path.join(HERE, f), os.path.join(cp, f))
    print('copied', f)
edit('cobalt/css_parser/BUILD.gn',
     '    "grammar.h",\n',
     '    "css_compat.cc",\n    "css_compat.h",\n    "grammar.h",\n')
edit('cobalt/css_parser/parser.cc',
     '#include "cobalt/css_parser/parser.h"\n',
     '#include "cobalt/css_parser/parser.h"\n\n#include "cobalt/css_parser/css_compat.h"\n')
edit('cobalt/css_parser/parser.cc',
     '  ParserImpl parser_impl(input, input_location, this, on_warning_callback_,\n',
     '  std::string gb_storage;  // GoldenBoot: CSS compatibility rewrites\n'
     '  const std::string& gb_input = css_compat::Process(input, &gb_storage);\n'
     '  ParserImpl parser_impl(gb_input, input_location, this, on_warning_callback_,\n',
     count=4)
edit('cobalt/css_parser/parser.cc',
     '  ParserImpl parser_impl(property_value, property_location, this,\n',
     '  std::string gb_storage;  // GoldenBoot: CSS compatibility rewrites\n'
     '  const std::string& gb_value = css_compat::Process(property_value, &gb_storage);\n'
     '  ParserImpl parser_impl(gb_value, property_location, this,\n',
     count=2)

# 2. Lower memory limits
ARGS = [
    '--image_cache_size_in_bytes=8388608',            # 8 MB (default at 720p: 10-20 MB)
    '--encoded_image_cache_size_in_bytes=524288',     # 512 KB (default 1 MB)
    '--skia_cache_size_in_bytes=2097152',             # 2 MB (default 4 MB)
    '--remote_typeface_cache_size_in_bytes=2097152',  # 2 MB (default 4 MB)
    '--skia_atlas_texture_dimensions=1024x1024',      # 2 MB GPU (default 2048x2048 = 8 MB)
]
edit('starboard/android/apk/app/src/main/java/dev/cobalt/coat/CobaltActivity.java',
     'private static final String[] DEBUG_ARGS = {};',
     'private static final String[] DEBUG_ARGS = {\n' +
     ''.join('    "%s",\n' % a for a in ARGS) + '  };')

rro = 'starboard/android/apk/app/src/main/res/values/rro_variables.xml'
p = os.path.join(SRC, rro)
x = open(p, encoding='utf-8').read()
for name, val in (('max_video_buffer_budget', 16),                          # MB, default 30
                  ('buffer_garbage_collection_duration_threshold', 30000000)):  # us, default 170 s
    pat = r'(<integer name="%s"\s+tools:ignore="DuplicateDefinition">)0(</integer>)' % name
    assert len(re.findall(pat, x)) == 1, name
    x = re.sub(pat, r'\g<1>%d\g<2>' % val, x)
open(p, 'w', encoding='utf-8', newline='\n').write(x)
print('patched', rro)

# 3. Content-Security-Policy header optional: our own start pages (e.g. a Cloudflare site) send
# no CSP header, and release builds otherwise refuse to load them ("Can't connect right now").
# HTTPS and CORS stay required; a page that does send a CSP header is still enforced.
APP = 'cobalt/browser/application.cc'
edit(APP, 'SecurityFlags security_flags{csp::kCSPRequired, network::kHTTPSRequired,',
     'SecurityFlags security_flags{csp::kCSPOptional, network::kHTTPSRequired,')
edit(APP, '#if defined(COBALT_FORCE_CSP)\n  security_flags.csp_header_policy = csp::kCSPRequired;',
     '#if defined(COBALT_FORCE_CSP)\n  security_flags.csp_header_policy = csp::kCSPOptional;')
print('all GoldenBoot patches applied')
