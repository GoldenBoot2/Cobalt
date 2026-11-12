"""Embeds patches/yt_tv.js into patches/adguard_engine.cc as the C string kYtTv.
Usage: python -I patches/embed_js.py   (comment-only lines are left out; every line ends with \\n)."""
import os, re

HERE = os.path.dirname(os.path.abspath(__file__))
js = open(os.path.join(HERE, 'yt_tv.js'), encoding='utf-8').read()
lines = [l for l in js.splitlines() if l.strip() and not l.lstrip().startswith('//')]


def c_str(s):
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '\\n"'


lit = 'const char kYtTv[] =\n' + '\n'.join('    ' + c_str(l) for l in lines) + ';\n'
cc_path = os.path.join(HERE, 'adguard_engine.cc')
raw = open(cc_path, 'rb').read()
crlf = b'\r\n' in raw
cc = raw.decode('utf-8').replace('\r\n', '\n')
# The old literal may have C++ comment lines between its pieces.
pat = re.compile(r'const char kYtTv\[\] =\n(?:[ \t]*(?:"(?:[^"\\\n]|\\.)*"|//[^\n]*)\n)*?[ \t]*"(?:[^"\\\n]|\\.)*";\n')
m = pat.search(cc)
assert m, 'kYtTv not found'
cc = cc[:m.start()] + lit + cc[m.end():]
open(cc_path, 'wb').write((cc.replace('\n', '\r\n') if crlf else cc).encode('utf-8'))
print('kYtTv: %d lines, %d bytes of JS' % (len(lines), sum(len(l) + 1 for l in lines)))
