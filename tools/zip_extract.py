"""Extract ONE entry from a remote zip with HTTP range requests.
Usage: python -I zip_extract.py <url> <zip size> <entry name> <out file>"""
import struct, sys, urllib.request, zlib

url, size, entry, out = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]

def get(a, b):
    req = urllib.request.Request(url, headers={"Range": f"bytes={a}-{b}", "User-Agent": "zip-extract"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return r.read()

tail_start = max(0, size - 2000000)
tail = get(tail_start, size - 1)
i = tail.rfind(b"PK\x05\x06")
total, cd_size, cd_off = struct.unpack("<HII", tail[i + 10:i + 20])
cd = tail[cd_off - tail_start:cd_off - tail_start + cd_size] if cd_off >= tail_start else get(cd_off, cd_off + cd_size - 1)

p = 0
found = None
while p < len(cd) and cd[p:p + 4] == b"PK\x01\x02":
    method = struct.unpack("<H", cd[p + 10:p + 12])[0]
    crc, csize, usize = struct.unpack("<III", cd[p + 16:p + 28])
    nl, el, cl = struct.unpack("<HHH", cd[p + 28:p + 34])
    loff = struct.unpack("<I", cd[p + 42:p + 46])[0]
    name = cd[p + 46:p + 46 + nl].decode("utf-8", "replace")
    if name == entry:
        found = (method, crc, csize, usize, loff)
    p += 46 + nl + el + cl
if not found:
    sys.exit("entry not found")
method, crc, csize, usize, loff = found
lh = get(loff, loff + 29)
lnl, lel = struct.unpack("<HH", lh[26:30])
data_start = loff + 30 + lnl + lel

dec = zlib.decompressobj(-15) if method == 8 else None
got_crc = 0
written = 0
CH = 4 * 1024 * 1024
with open(out, "wb") as f:
    pos = data_start
    end = data_start + csize
    while pos < end:
        b = min(end, pos + CH) - 1
        for attempt in range(4):
            try:
                chunk = get(pos, b)
                break
            except Exception as e:
                print("retry", pos, e)
        else:
            sys.exit("download failed")
        part = dec.decompress(chunk) if dec else chunk
        f.write(part)
        got_crc = zlib.crc32(part, got_crc)
        written += len(part)
        pos = b + 1
        print(f"{(pos - data_start) * 100 // csize}%", end=" ", flush=True)
    if dec:
        part = dec.flush()
        f.write(part)
        got_crc = zlib.crc32(part, got_crc)
        written += len(part)
print()
ok = (got_crc & 0xFFFFFFFF) == crc and written == usize
print("size", written, "crc ok" if ok else "CRC MISMATCH")
sys.exit(0 if ok else 1)
