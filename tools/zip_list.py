"""List a remote zip's entries using HTTP range requests (reads only the tail)."""
import struct, sys, urllib.request

url = sys.argv[1]
size = int(sys.argv[2])

def get(rng):
    req = urllib.request.Request(url, headers={"Range": rng, "User-Agent": "zip-list"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()

tail_start = max(0, size - 2000000)
tail = get(f"bytes={tail_start}-{size - 1}")
i = tail.rfind(b"PK\x05\x06")
if i < 0:
    sys.exit("no end-of-central-directory found")
total, cd_size, cd_off = struct.unpack("<HII", tail[i + 10:i + 20])
if cd_off == 0xFFFFFFFF:
    j = tail.rfind(b"PK\x06\x06")
    cd_size, cd_off = struct.unpack("<QQ", tail[j + 40:j + 56])
if cd_off >= tail_start:
    cd = tail[cd_off - tail_start:cd_off - tail_start + cd_size]
else:
    cd = get(f"bytes={cd_off}-{cd_off + cd_size - 1}")
p = 0
while p < len(cd) and cd[p:p + 4] == b"PK\x01\x02":
    csize, usize = struct.unpack("<II", cd[p + 20:p + 28])
    nl, el, cl = struct.unpack("<HHH", cd[p + 28:p + 34])
    name = cd[p + 46:p + 46 + nl].decode("utf-8", "replace")
    print(f"{usize / 1048576:8.1f} MB  {name}")
    p += 46 + nl + el + cl
