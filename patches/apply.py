"""Applies the GoldenBoot changes to a youtube/cobalt 25.lts checkout.

Usage: python3 apply.py <cobalt source dir>
 1. AdGuard network blocking: copies adguard_filter.{h,cc} into cobalt/network, hooks it into
    NetworkDelegate::OnBeforeURLRequest (blocked requests fail with ERR_BLOCKED_BY_CLIENT) and
    adds it to cobalt/network/BUILD.gn. adguard_rules.inc is generated separately by
    adguard_rules.py.
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
for f in ('adguard_filter.h', 'adguard_filter.cc'):
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
     '    "adguard_filter.cc",\n    "adguard_filter.h",\n    "adguard_rules.inc",\n'
     '    "network_delegate.cc",\n    "network_delegate.h",\n')

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
print('all GoldenBoot patches applied')
