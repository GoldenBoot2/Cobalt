# Cobalt TV apps

Developer: GoldenBoot

Android TV apps built on [Cobalt](https://github.com/youtube/cobalt), the lightweight
HTML/JS app container for TVs.

## Build Cobalt on GitHub Actions

Actions tab > **Build Cobalt (Android arm)** > Run workflow.

- `cobalt_ref`: a youtube/cobalt tag or branch (default `25.lts.40`)
- `config`: `gold` (release) or `qa`

- `goldenboot`: apply the GoldenBoot patches (default on)

The run builds the official source with Cobalt's own Docker setup and uploads
`cobalt-<ref>-android-arm-<config>[-gb].apk` as a run artifact (kept 30 days).

## GoldenBoot patches (`patches/`)

- **AdGuard filter lists:** `adguard_rules.py` downloads the AdGuard Base, Tracking Protection
  and Mobile Ads lists at build time and converts their whole-domain network rules (`||host^`,
  `$third-party`, `$important`, `@@` exceptions) into `cobalt/network/adguard_rules.inc`.
  `adguard_filter.cc` checks every request in `NetworkDelegate::OnBeforeURLRequest`; a match
  fails with `ERR_BLOCKED_BY_CLIENT`. Blocked hosts are logged to logcat with the tag `GBAdGuard`.
- **Lower memory limits** for 512 MB TVs: smaller image, Skia, font and glyph-atlas caches,
  a 16 MB video buffer budget and 30 s of played media kept in memory.
- **Content-Security-Policy header optional:** release builds otherwise refuse a start page that
  sends no CSP header. HTTPS and CORS stay required, and a CSP header that is sent is still enforced.
- `apply.py <cobalt dir>` applies all of them; every edit fails loudly if its anchor is missing.

## Tools

- `tools/zip_list.py <url> <size>`: lists the files inside a remote zip using HTTP range requests.
- `tools/zip_extract.py <url> <size> <entry> <out>`: downloads one file from a remote zip and checks its CRC.
- `tools/manifest_patch.py <decoded dir> <package> <label> <versionName> <versionCode> [url]`:
  turns an apktool-decoded Cobalt APK into our own app (package, name, start page).

## Licence

Cobalt is licensed under the Apache License 2.0 by The Cobalt Authors.
