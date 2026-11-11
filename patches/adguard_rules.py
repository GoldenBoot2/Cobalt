"""Downloads AdGuard filter lists and compiles them into cobalt/network/adguard_rules.inc
for adguard_engine.cc.

Usage:
  python3 adguard_rules.py <out.inc> --scriptlets <scriptlets.corelibs.json>
                           --extcss <extended-css.min.js> [filter ids or files...]
  Default ids: 2 3 11 (AdGuard Base, Tracking Protection, Mobile Ads). An argument that is an
  existing file is read instead of downloaded (used for local tests).

Compiled rule types:
  - "||host^" network rules (with $third-party/$important) -> sorted host lists (fast path)
  - other network rules: "||", "|", "*", "^" patterns with $domain, $third-party/$first-party,
    content types, $important, $match-case, $denyallow, $badfilter, and @@ exceptions incl.
    page-level $document/$elemhide/$generichide/$specifichide/$jsinject/$urlblock/$content
    -> rule table + token index
  - cosmetic: ## element hiding, #?# extended (ExtendedCss), #$# / #$?# CSS injection,
    #%#//scriptlet(...) (AdGuard Scriptlets corelibs), #%# JavaScript, and their #@...#
    exceptions -> entry table + per-domain index + prebuilt generic CSS
Not compiled (counted): regex network rules, $redirect/$removeparam/$csp/$replace/$header/
$cookie/$popup and other modifiers needing a full browser extension, $$ HTML filtering and
cosmetic rules with [$path/...] modifiers.
"""
import json, os, re, sys, urllib.request
from collections import defaultdict

# ---------------------------------------------------------------- arguments
argv = sys.argv[1:]
out = argv.pop(0)
opts = {'--scriptlets': None, '--extcss': None}
ids = []
while argv:
    a = argv.pop(0)
    if a in opts:
        opts[a] = argv.pop(0)
    else:
        ids.append(a)
ids = ids or ['2', '3', '11']
assert opts['--scriptlets'] and opts['--extcss'], 'need --scriptlets and --extcss'
URL = 'https://filters.adtidy.org/extension/chromium/filters/%s.txt'

# ---------------------------------------------------------------- constants (match adguard_engine.h)
F_EXC, F_IMPORTANT, F_THIRD, F_FIRST, F_MATCHCASE, F_PAGE = 1, 2, 4, 8, 16, 32
TYPES = {'script': 1, 'image': 2, 'stylesheet': 4, 'css': 4, 'xmlhttprequest': 8, 'xhr': 8,
         'media': 16, 'font': 32, 'subdocument': 64, 'frame': 64, 'websocket': 128,
         'other': 256, 'object': 512, 'object-subrequest': 512, 'ping': 1024}
ALL_TYPES = 2047
PAGE = {'document': 1, 'doc': 1, 'elemhide': 2, 'ehide': 2, 'generichide': 4, 'ghide': 4,
        'specifichide': 8, 'shide': 8, 'jsinject': 16, 'urlblock': 32, 'content': 64,
        'extension': 0, 'stealth': 0}
HOST = re.compile(r'^\|\|([a-z0-9][a-z0-9.-]*\.[a-z0-9-]+)\^\|?$')
COSMETIC = re.compile(r'^([^#$\s/|^"\'=]*?)(#@\$\?#|#\$\?#|#@\$#|#\$#|#@%#|#%#|#@\?#|#\?#|#@#|##|\$@\$|\$\$)(.+)$')
MODS = re.compile(r'^~?[a-z0-9_-]+(=[^,]*)?(,~?[a-z0-9_-]+(=[^,]*)?)*$', re.I)
EXT_PSEUDO = (':has(', ':-abp-has(', ':has-text(', ':contains(', ':-abp-contains(', ':matches-css(',
              ':matches-css-before(', ':matches-css-after(', ':-abp-properties(', ':matches-attr(',
              ':matches-property(', ':xpath(', ':nth-ancestor(', ':upward(', ':remove(', ':remove-attr(',
              ':remove-class(', ':is(', ':not(', ':if-not(', ':if(', ':empty-trimmed', ':min-text-length(',
              ':others(', '[-ext-')
BAD_TOKENS = {'http', 'https', 'www', 'com', 'net', 'org', 'js', 'html', 'php', 'cdn', 'static'}

# ---------------------------------------------------------------- scriptlets
corelibs = json.load(open(opts['--scriptlets'], encoding='utf-8'))
SL_VERSION = corelibs.get('version', '')
sl_code, sl_index = [], {}
for s in corelibs['scriptlets']:
    for n in s['names']:
        sl_index[n] = len(sl_code)
    sl_code.append(s['scriptlet'])
extcss = open(opts['--extcss'], encoding='utf-8').read()
assert 'ExtendedCss' in extcss

# ---------------------------------------------------------------- read lists
stats = defaultdict(int)
info = []
lines = []
for fid in ids:
    if os.path.isfile(fid):
        text = open(fid, encoding='utf-8').read()
    else:
        req = urllib.request.Request(URL % fid, headers={'User-Agent': 'cobalt-build'})
        text = urllib.request.urlopen(req, timeout=60).read().decode('utf-8', 'replace')
    title = version = ''
    for line in text.splitlines():
        line = line.strip()
        if line.startswith('! Title:') and not title:
            title = line[8:].strip()
        elif line.startswith('! Version:') and not version:
            version = line[10:].strip()
        if not line or line.startswith('!') or (line.startswith('[') and not line.startswith('[$')):
            continue
        lines.append(line)
    info.append('%s %s' % (title or 'filter ' + os.path.basename(fid), version))


def split_network(line):
    exc = line.startswith('@@')
    body = line[2:] if exc else line
    i = body.rfind('$')
    if i >= 0 and MODS.match(body[i + 1:]):
        return exc, body[:i], [m.strip() for m in body[i + 1:].split(',') if m.strip()]
    return exc, body, []


# $badfilter: drop the rules they cancel
bad = set()
for line in lines:
    if COSMETIC.match(line) or line.startswith('[$'):
        continue
    exc, pat, mods = split_network(line)
    if 'badfilter' in [m.lower() for m in mods]:
        bad.add((exc, pat, frozenset(m.lower() for m in mods if m.lower() != 'badfilter')))

# ---------------------------------------------------------------- compile
important, block_all, block_3p, allow = set(), set(), set(), set()
typed = {}  # host -> content types (low 16 bits: any party, high 16 bits: third-party only)
HOST_ONLY = re.compile(r'^(?:\|\|)?([a-z0-9_][a-z0-9_.-]*\.[a-z0-9-]+)\^?$')
net_rules = {}            # line key -> (flags, types, domains, denyallow, pattern)
cos_entries = {}          # text -> index
cos_generic = set()
cos_inc = defaultdict(set)
cos_exc = defaultdict(set)
cos_global_off = set()


def entry(text):
    if text not in cos_entries:
        cos_entries[text] = len(cos_entries)
    return cos_entries[text]


def parse_scriptlet(body):
    m = re.match(r'^//scriptlet\((.*)\)\s*;?\s*$', body)
    if not m:
        return None
    inner, args, i = m.group(1), [], 0
    while i < len(inner):
        c = inner[i]
        if c in ' ,':
            i += 1
            continue
        if c not in '\'"':
            return None
        j, buf = i + 1, []
        while j < len(inner) and inner[j] != c:
            if inner[j] == '\\' and j + 1 < len(inner) and inner[j + 1] == c:
                buf.append(c)
                j += 2
                continue
            buf.append(inner[j])
            j += 1
        if j >= len(inner):
            return None
        args.append(''.join(buf))
        i = j + 1
    return args or None


def cosmetic_text(marker, body):
    """Entry text for a cosmetic rule body; None if unsupported."""
    m = marker.replace('@', '')
    if m in ('##', '#?#'):
        if '{' in body or '}' in body:
            return None
        low = body.lower()
        if m == '#?#' or any(p in low for p in EXT_PSEUDO):
            return 'X' + body + ' { display: none !important; }'
        return 'H' + body
    if m in ('#$#', '#$?#'):
        if not re.match(r'^[^{}]+\{[^{}]*\}\s*$', body):
            return None
        low = body.lower()
        if m == '#$?#' or 'remove:' in low.replace(' ', '') or any(p in low for p in EXT_PSEUDO):
            return 'X' + body
        return 'C' + body
    if m == '#%#':
        if body.startswith('//scriptlet('):
            args = parse_scriptlet(body)
            if not args or args[0] not in sl_index:
                stats['scriptlet_unknown'] += 1
                return None
            src = {'name': args[0], 'args': args[1:], 'engine': 'corelibs', 'version': SL_VERSION,
                   'verbose': False}
            return 'S%d\t%s\t%s' % (sl_index[args[0]], json.dumps(src, separators=(',', ':')),
                                     json.dumps(args[1:], separators=(',', ':')))
        return 'J' + body
    return None


for line in lines:
    stats['lines'] += 1
    if line.startswith('[$'):
        stats['skip_cosmetic_modifiers'] += 1
        continue
    cm = COSMETIC.match(line)
    if cm:
        dpart, marker, body = cm.groups()
        if marker in ('$$', '$@$'):
            stats['skip_html_filtering'] += 1
            continue
        domains = [d.strip().lower() for d in dpart.split(',') if d.strip()]
        if any(d.lstrip('~').startswith('/') for d in domains):
            stats['skip_regex_domain'] += 1
            continue
        pos = [d for d in domains if not d.startswith('~')]
        neg = [d[1:] for d in domains if d.startswith('~')]
        text = cosmetic_text(marker, body.strip())
        if text is None:
            stats['skip_cosmetic_invalid'] += 1
            continue
        exc = '@' in marker
        if exc:
            if not pos and not neg:
                cos_global_off.add(text)
            for d in pos:
                cos_exc[d].add(text)
        else:
            if pos:
                for d in pos:
                    cos_inc[d].add(text)
            else:
                cos_generic.add(text)
            for d in neg:
                cos_exc[d].add(text)
        stats['cosmetic'] += 1
        continue

    exc, pat, mods = split_network(line)
    lmods = [m.lower() for m in mods]
    if 'badfilter' in lmods:
        continue
    if (exc, pat, frozenset(lmods)) in bad:
        stats['badfiltered'] += 1
        continue
    if len(pat) > 1 and pat.startswith('/') and pat.endswith('/'):
        stats['skip_regex'] += 1
        continue
    if '$' in pat or ' ' in pat:
        stats['skip_other'] += 1
        continue
    plow = pat.lower()
    # fast path: whole-domain rules
    hm = HOST.match(plow)
    modset = set(lmods)
    if hm and not exc and modset <= {'third-party', '3p', 'important', 'all'}:
        host = hm.group(1)
        if 'important' in modset and not ({'third-party', '3p'} & modset):
            important.add(host)
        elif {'third-party', '3p'} & modset:
            block_3p.add(host)
        else:
            block_all.add(host)
        stats['domain'] += 1
        continue
    if hm and exc and modset <= {'important', 'all'}:
        allow.add(hm.group(1))
        stats['domain'] += 1
        continue
    flags, types, negtypes, page, doms, deny, ok = F_EXC if exc else 0, 0, 0, 0, '', '', True
    for m in lmods:
        neg = m.startswith('~')
        name, _, val = m[1 if neg else 0:].partition('=')
        if name in TYPES:
            if neg:
                negtypes |= TYPES[name]
            else:
                types |= TYPES[name]
        elif name in ('third-party', '3p', 'strict-third-party', 'strict3p'):
            flags |= F_FIRST if neg else F_THIRD
        elif name in ('first-party', '1p', 'strict-first-party', 'strict1p'):
            flags |= F_THIRD if neg else F_FIRST
        elif name == 'important':
            flags |= F_IMPORTANT
        elif name == 'match-case':
            flags |= F_MATCHCASE
        elif name in ('domain', 'from'):
            if '/' in val or not val:
                ok = False
            doms = val
        elif name == 'denyallow':
            deny = val
        elif name == 'all' and not neg:
            pass
        elif exc and name in PAGE and not neg:
            page |= PAGE[name]
        else:
            ok = False
    if not ok:
        stats['skip_modifiers'] += 1
        continue
    if negtypes:
        types = (types or ALL_TYPES) & ~negtypes
    if exc and any(k in PAGE for k in (m.lstrip('~').partition('=')[0] for m in lmods)):
        if page == 0:
            stats['skip_modifiers'] += 1
            continue
        flags |= F_PAGE
        types = page
    if not (flags & F_MATCHCASE):
        pat = plow
    elif pat.startswith('||'):
        # host names are always lower case in URLs
        m = re.match(r'^\|\|[^/^*|?]*', pat)
        pat = m.group(0).lower() + pat[m.end():]
    if pat in ('', '*') and not doms and not (flags & F_PAGE):
        stats['skip_too_wide'] += 1
        continue
    # Host-only rules ("host$image", "||host^$script,third-party") go to the compact host
    # tables: matched against the request host and its parents.
    hm2 = HOST_ONLY.match(pat)
    if hm2 and flags in (0, F_THIRD) and not doms and not deny:
        host = hm2.group(1)
        if types == 0:
            (block_3p if flags else block_all).add(host)
        else:
            typed[host] = typed.get(host, 0) | (types << 16 if flags else types)
        stats['host_typed' if types else 'domain'] += 1
        continue
    net_rules[(flags, types, doms, deny, pat)] = 1
    stats['network'] += 1

block_3p -= block_all

# ---------------------------------------------------------------- network rule table + token index
TOK = re.compile(r'[a-z0-9%]+')


def candidate_tokens(pat):
    low = pat.lower()
    res = []
    for m in TOK.finditer(low):
        s, e = m.start(), m.end()
        if e - s < 2:
            continue
        left = low[s - 1] if s > 0 else ''
        right = low[e] if e < len(low) else ''
        if left in ('', '*') or right in ('', '*'):
            continue
        res.append(m.group(0))
    return res


def fnv(s):
    h = 2166136261
    for b in s.encode('ascii'):
        h ^= b
        h = (h * 16777619) & 0xffffffff
    return h


rules = sorted(net_rules)
freq = defaultdict(int)
cands = []
for r in rules:
    c = candidate_tokens(r[4])
    cands.append(c)
    for t in set(c):
        freq[t] += 1
tok_pairs, notok = [], []
for i, c in enumerate(cands):
    if not c:
        notok.append(i)
        continue
    best = min(c, key=lambda t: (t in BAD_TOKENS, freq[t], -len(t)))
    tok_pairs.append((fnv(best), i))
tok_pairs.sort()

# ---------------------------------------------------------------- cosmetic tables
for t in cos_global_off:
    cos_generic.discard(t)
    for d in cos_inc:
        cos_inc[d].discard(t)
used = set(cos_generic)
for d in cos_inc:
    used |= cos_inc[d]
for d in cos_exc:
    cos_exc[d] &= used
texts = sorted(used, key=lambda t: (t[0], t))
tidx = {t: i for i, t in enumerate(texts)}
keys = sorted(k for k in set(cos_inc) | set(cos_exc) if cos_inc.get(k) or cos_exc.get(k))
key_start, refs = [], []
for k in keys:
    key_start.append(len(refs))
    refs.extend(sorted(tidx[t] for t in cos_inc.get(k, ())))
    refs.extend(sorted(tidx[t] | 0x80000000 for t in cos_exc.get(k, ())))
key_start.append(len(refs))
generic = sorted(tidx[t] for t in cos_generic)


def generic_key(sel):
    """'.class' or '#id' that must be on the page for sel to match, or None."""
    if '\\' in sel:
        return None
    s = re.sub(r'\[[^\]]*\]', '', sel)
    while True:
        s2 = re.sub(r':(not|is|where|has)\([^()]*\)', '', s)
        if s2 == s:
            break
        s = s2
    m = re.search(r'([.#])(-?[A-Za-z_][\w-]*)', s)
    return m.group(1) + m.group(2) if m else None


# Generic hiding: selectors with a class/id key are applied only when that class/id is on
# the page (page script lookup, like uBlock Origin's generic cosmetic filtering); the rest is
# plain CSS.
keyed_lines, keyed_idx, unkeyed_css = [], [], []
for t in texts:
    if t in cos_generic and t[0] == 'H':
        k = generic_key(t[1:])
        if k:
            keyed_lines.append(k + '\t' + t[1:])
            keyed_idx.append(tidx[t])
        else:
            unkeyed_css.append(t[1:] + '{display:none!important}\n')
generic_css = ''.join(unkeyed_css)
keyed_js = json.dumps('\n'.join(keyed_lines))
stats['generic_keyed'] = len(keyed_lines)
stats['generic_unkeyed'] = len(unkeyed_css)
for t in texts:
    assert '\n' not in t and '\r' not in t, t[:80]
for k in keys:
    assert '\n' not in k


# ---------------------------------------------------------------- write
def cbytes(s):
    o = []
    for b in s.encode('utf-8'):
        if b in (0x22, 0x5c):
            o.append('\\' + chr(b))
        elif b == 0x3f:
            o.append('\\?')
        elif 0x20 <= b < 0x7f:
            o.append(chr(b))
        else:
            o.append('\\%03o' % b)
    return ''.join(o)


def cstring(f, name, items, sep='\n'):
    """items: list of strings, written as one blob, each followed by sep."""
    f.write('static const char %s[] =\n' % name)
    if not items:
        f.write('    "";\n')
        return
    chunk = []
    size = 0
    for it in items:
        chunk.append(cbytes(it + sep))
        size += len(chunk[-1])
        if size > 4000:
            f.write('    "%s"\n' % ''.join(chunk))
            chunk, size = [], 0
    if chunk:
        f.write('    "%s"\n' % ''.join(chunk))
    f.write('    ;\n')


def carray(f, name, nums, count=False):
    if count:
        f.write('static const uint32_t %sCount = %d;\n' % (name, len(nums)))
    f.write('static const uint32_t %s[] = {\n' % name)
    nums = nums or [0]
    for i in range(0, len(nums), 16):
        f.write('    %s,\n' % ', '.join(str(n) for n in nums[i:i + 16]))
    f.write('};\n')


def cbytes_raw(b):
    o = []
    for x in b:
        if x in (0x22, 0x5c):
            o.append('\\' + chr(x))
        elif x == 0x3f:
            o.append('\\?')
        elif 0x20 <= x < 0x7f:
            o.append(chr(x))
        else:
            o.append('\\%03o' % x)
    return ''.join(o)


FC_BUCKET = 16  # must match kFcBucket in adguard_engine.cc


def front_coded(f, name, hosts, payload=None):
    """Host table: reversed host names, sorted, front-coded in buckets of FC_BUCKET entries
    (the first of each bucket stored whole). Entry: shared-prefix length (1 byte), suffix
    length (1 byte), suffix, then a little-endian uint32 payload if payload is given."""
    keys = sorted((h[::-1].encode('ascii'), h) for h in hosts)
    data = bytearray()
    heads = []
    prev = b''
    for i, (k, h) in enumerate(keys):
        assert len(k) < 256, h
        if i % FC_BUCKET == 0:
            heads.append(len(data))
            shared = 0
        else:
            shared = 0
            while shared < min(len(prev), len(k)) and prev[shared] == k[shared]:
                shared += 1
        suffix = k[shared:]
        data += bytes([shared, len(suffix)]) + suffix
        if payload is not None:
            data += payload[h].to_bytes(4, 'little')
        prev = k
    f.write('static const uint32_t %sCount = %d;\n' % (name, len(keys)))
    f.write('static const char %s[] =\n' % name)
    for i in range(0, max(len(data), 1), 2000):
        f.write('    "%s"\n' % cbytes_raw(data[i:i + 2000]))
    f.write('    ;\n')
    carray(f, name + 'Heads', heads)
    return len(data) + 4 * len(heads)


net_lines = ['%x\t%x\t%s\t%s\t%s' % r for r in rules]
for l in net_lines:
    assert '\n' not in l and l.count('\t') == 4, l
net_off, pos = [], 0
for l in net_lines:
    net_off.append(pos)
    pos += len(l.encode('utf-8')) + 1
cos_off, pos = [], 0
for t in texts:
    cos_off.append(pos)
    pos += len(t.encode('utf-8')) + 1

summary = '; '.join(info)
with open(out, 'w', encoding='ascii', newline='\n') as f:
    f.write('// Generated by patches/adguard_rules.py - do not edit.\n')
    f.write('// %s\n// %s\n\n' % (summary, dict(stats)))
    f.write('static const char kAdgInfo[] = "%s";\n\n' % cbytes(summary))
    host_bytes = 0
    host_bytes += front_coded(f, 'kAdgImportant', important)
    host_bytes += front_coded(f, 'kAdgBlockAll', block_all)
    host_bytes += front_coded(f, 'kAdgBlock3p', block_3p)
    host_bytes += front_coded(f, 'kAdgAllow', allow)
    host_bytes += front_coded(f, 'kAdgTyped', typed, typed)
    # network rules: "flags\ttypes\tdomains\tdenyallow\tpattern\n"
    cstring(f, 'kAdgNet', net_lines)
    carray(f, 'kAdgNetOff', net_off)
    f.write('static const uint32_t kAdgNetTokCount = %d;\n' % len(tok_pairs))
    flat = [x for p in tok_pairs for x in p]
    carray(f, 'kAdgNetTokFlat', flat)
    f.write('static const uint32_t* const kAdgNetTok = kAdgNetTokFlat;\n')
    carray(f, 'kAdgNetNoTok', notok, count=True)
    # cosmetic
    cstring(f, 'kAdgCosEntries', texts)
    carray(f, 'kAdgCosOff', cos_off)
    cstring(f, 'kAdgCosKeys', keys)
    carray(f, 'kAdgCosKeyStart', key_start)
    carray(f, 'kAdgCosRefs', refs)
    carray(f, 'kAdgCosGeneric', generic, count=True)
    carray(f, 'kAdgCosGenericKeyed', keyed_idx, count=True)
    # "key\tselector\n..." as a JavaScript string literal (json.dumps, ASCII only)
    f.write('static const char kAdgGenericKeyedJs[] =\n')
    for i in range(0, len(keyed_js), 3000):
        f.write('    "%s"\n' % cbytes(keyed_js[i:i + 3000]))
    f.write('    ;\n')
    f.write('static const char kAdgGenericCss[] =\n')
    css_lines = generic_css.splitlines(True) or ['']
    for i in range(0, len(css_lines), 40):
        f.write('    "%s"\n' % cbytes(''.join(css_lines[i:i + 40])))
    f.write('    ;\n')
    # scriptlets (AdGuard Scriptlets corelibs) and ExtendedCss
    f.write('static const uint32_t kAdgSlCount = %d;\n' % len(sl_code))
    f.write('static const char* const kAdgSlCode[] = {\n')
    for c in sl_code:
        f.write('    "%s",\n' % cbytes(c))
    f.write('};\n')
    f.write('static const char kAdgExtCss[] =\n')
    for i in range(0, len(extcss), 3000):
        f.write('    "%s"\n' % cbytes(extcss[i:i + 3000]))
    f.write('    ;\n')
    f.write('static const char kAdgStats[] = "%s";\n' % cbytes(
        'domain block %d, block-3p %d, allow %d, important %d, typed hosts %d; network rules %d '
        '(indexed %d, unindexed %d); cosmetic entries %d (generic %d, domains %d); scriptlets lib %d'
        % (len(block_all), len(block_3p), len(allow), len(important), len(typed), len(rules),
           len(tok_pairs), len(notok), len(texts), len(generic), len(keys), len(sl_code))))
    f.write('// host tables: %d bytes\n' % host_bytes)

print(summary)
print(dict(stats))
print('domain: important', len(important), 'block', len(block_all), 'block-3p', len(block_3p),
      'allow', len(allow), 'typed hosts', len(typed), 'host tables bytes', host_bytes)
print('network rules', len(rules), 'indexed', len(tok_pairs), 'unindexed', len(notok))
print('cosmetic entries', len(texts), 'generic', len(generic), 'generic css bytes', len(generic_css),
      'domain keys', len(keys), 'refs', len(refs))
print('kinds', {k: sum(1 for t in texts if t[0] == k) for k in 'HCXSJ'})
print('generic kinds', {k: sum(1 for t in cos_generic if t[0] == k) for k in 'HCXSJ'})
print('output bytes', os.path.getsize(out))
