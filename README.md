# Cobalt TV apps

Developer: GoldenBoot

Android TV apps built on [Cobalt](https://github.com/youtube/cobalt), the lightweight
HTML/JS app container for TVs.

## Build Cobalt on GitHub Actions

Actions tab > **Build Cobalt (Android arm)** > Run workflow.

- `cobalt_ref`: a youtube/cobalt tag or branch (default `25.lts.40`)
- `config`: `gold` (release) or `qa`

The run builds the official source with Cobalt's own Docker setup and uploads
`cobalt-<ref>-android-arm-<config>.apk` as a run artifact (kept 30 days).

## Tools

- `tools/zip_list.py <url> <size>`: lists the files inside a remote zip using HTTP range requests.
- `tools/zip_extract.py <url> <size> <entry> <out>`: downloads one file from a remote zip and checks its CRC.

## Licence

Cobalt is licensed under the Apache License 2.0 by The Cobalt Authors.
