"""Renames an apktool-decoded Cobalt APK into our own app.

Usage: python -I manifest_patch.py <decoded dir> <package> <label> <versionName> <versionCode> [app_url]
Removes the AD_ID permission and the YouTube VIEW intent-filter, sets label, start URL (optional),
androidx-startup provider authority and apktool.yml renameManifestPackage/version.
"""
import re, sys, os

D, pkg, label, vname, vcode = sys.argv[1:6]
url = sys.argv[6] if len(sys.argv) > 6 else None
assert pkg.startswith('com.goldenboot.')

p = os.path.join(D, 'AndroidManifest.xml')
m = open(p, encoding='utf-8').read()
n0 = len(m)
m = m.replace('    <uses-permission android:name="com.google.android.gms.permission.AD_ID"/>\n', '', 1)
m, k = re.subn(r'            <intent-filter>\n                <action android:name="android.intent.action.VIEW"/>.*?</intent-filter>\n',
               '', m, count=1, flags=re.S)
assert k == 1, 'VIEW filter'
m, k = re.subn(r'android:label="[^"]*"', 'android:label="%s"' % label.replace('&', '&amp;'), m, count=1)
assert k == 1
m = m.replace('android:authorities="dev.cobalt.coat.androidx-startup"', 'android:authorities="%s.androidx-startup"' % pkg)
assert pkg + '.androidx-startup' in m and 'AD_ID' not in m
if url:
    m, k = re.subn(r'(cobalt\.APP_URL" android:value=")[^"]*"', r'\g<1>%s"' % url, m)
    assert k == 1
open(p, 'w', encoding='utf-8', newline='\n').write(m)

y = os.path.join(D, 'apktool.yml')
t = open(y, encoding='utf-8').read()
t = re.sub(r'renameManifestPackage: .*', 'renameManifestPackage: ' + pkg, t)
t = re.sub(r"versionCode: .*", "versionCode: %s" % vcode, t)
t = re.sub(r"versionName: .*", "versionName: '%s'" % vname, t)
open(y, 'w', encoding='utf-8', newline='\n').write(t)
print('manifest', n0, '->', len(m), 'chars;', pkg, label, vname, vcode, url or '(url unchanged)')
