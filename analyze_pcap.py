#!/usr/bin/env python3
"""
Comprehensive pcap analysis for MapleStory Worlds packet capture.
"""

from scapy.all import rdpcap, TCP, UDP, IP, Raw
import re
import collections

pcap_file = r'C:\Users\utor9\Desktop\pack\paaa.pcap'
packets = rdpcap(pcap_file)

print("=" * 80)
print("SECTION 1: BASIC STATISTICS")
print("=" * 80)

total = len(packets)
print(f"Total packets: {total}")

proto_counts = collections.Counter()
for pkt in packets:
    if TCP in pkt:
        proto_counts['TCP'] += 1
    elif UDP in pkt:
        proto_counts['UDP'] += 1
    else:
        proto_counts['Other'] += 1

print(f"\nProtocol breakdown:")
for proto, count in sorted(proto_counts.items(), key=lambda x: -x[1]):
    print(f"  {proto}: {count} ({100*count/total:.1f}%)")

# Packet size distribution
sizes = [len(pkt) for pkt in packets]
print(f"\nPacket size distribution:")
print(f"  Min: {min(sizes)} bytes")
print(f"  Max: {max(sizes)} bytes")
print(f"  Avg: {sum(sizes)/len(sizes):.1f} bytes")
print(f"  Median: {sorted(sizes)[len(sizes)//2]} bytes")

size_buckets = collections.Counter()
for s in sizes:
    if s < 64:
        size_buckets['<64'] += 1
    elif s < 128:
        size_buckets['64-127'] += 1
    elif s < 256:
        size_buckets['128-255'] += 1
    elif s < 512:
        size_buckets['256-511'] += 1
    elif s < 1024:
        size_buckets['512-1023'] += 1
    else:
        size_buckets['>=1024'] += 1

for bucket in ['<64', '64-127', '128-255', '256-511', '512-1023', '>=1024']:
    print(f"  {bucket}: {size_buckets[bucket]}")

print("\n" + "=" * 80)
print("SECTION 2: UNIQUE TCP/UDP PORT PAIRS")
print("=" * 80)

port_pair_counts = collections.Counter()
port_pair_bytes = collections.defaultdict(int)
port_pair_pkts = collections.defaultdict(list)

for pkt in packets:
    if TCP in pkt and IP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        key = ('TCP', sport, dport)
        port_pair_counts[key] += 1
        port_pair_bytes[key] += len(pkt)
        if len(port_pair_pkts[key]) < 3:
            port_pair_pkts[key].append(pkt)
    elif UDP in pkt and IP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        key = ('UDP', sport, dport)
        port_pair_counts[key] += 1
        port_pair_bytes[key] += len(pkt)
        if len(port_pair_pkts[key]) < 3:
            port_pair_pkts[key].append(pkt)

print(f"\nAll unique port pairs (sorted by packet count):")
print(f"{'Proto':<6} {'SPort':<8} {'DPort':<8} {'Pkts':<8} {'Bytes':<12}")
print("-" * 50)
for key, count in sorted(port_pair_counts.items(), key=lambda x: -x[1]):
    proto, sport, dport = key
    print(f"{proto:<6} {sport:<8} {dport:<8} {count:<8} {port_pair_bytes[key]:<12}")

# Find unique ports (either side)
all_ports = set()
for proto, sport, dport in port_pair_counts.keys():
    all_ports.add(sport)
    all_ports.add(dport)
print(f"\nAll unique ports seen: {sorted(all_ports)}")

print("\n" + "=" * 80)
print("SECTION 3: HEX DUMPS OF FIRST PACKETS PER PORT PAIR")
print("=" * 80)

def hex_dump(data, max_bytes=64):
    """Return a hex + ASCII dump of data."""
    lines = []
    data = data[:max_bytes]
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
        lines.append(f"  {i:04x}: {hex_part:<48}  {ascii_part}")
    return '\n'.join(lines)

for key in sorted(port_pair_counts.keys(), key=lambda x: -port_pair_counts[x]):
    proto, sport, dport = key
    pkts = port_pair_pkts[key]
    print(f"\n--- {proto} {sport} -> {dport} ({port_pair_counts[key]} packets) ---")
    for idx, pkt in enumerate(pkts[:3]):
        raw_data = bytes(pkt)
        print(f"  Packet #{idx+1} (total {len(raw_data)} bytes):")
        # Show IP payload (skip Ethernet + IP headers)
        if IP in pkt:
            if TCP in pkt:
                payload = bytes(pkt[TCP])
                print(f"  TCP layer ({len(payload)} bytes):")
            elif UDP in pkt:
                payload = bytes(pkt[UDP])
                print(f"  UDP layer ({len(payload)} bytes):")
            else:
                payload = raw_data
        else:
            payload = raw_data
        print(hex_dump(payload, 64))
        if Raw in pkt:
            raw_payload = bytes(pkt[Raw])
            if raw_payload:
                print(f"  Raw payload ({len(raw_payload)} bytes):")
                print(hex_dump(raw_payload, 64))

print("\n" + "=" * 80)
print("SECTION 4: PATTERN SEARCH IN ALL PAYLOADS")
print("=" * 80)

# Regex patterns
WORLD_ID_RE = re.compile(rb'\d{17}')
CHANNEL_RE = re.compile(rb'[\xac\x00-\xd7\xa3][\x00-\xff]*\d+')  # rough UTF-8 Korean
# Korean in EUC-KR: 0xB0A1-0xC8FE (common range)
KOREAN_EUCKR_RE = re.compile(rb'[\xb0-\xc8][\xa1-\xfe][\xb0-\xc8][\xa1-\xfe][\xb0-\xc8][\xa1-\xfe]')
# UTF-8 Korean: \xEA-\xED range
KOREAN_UTF8_RE = re.compile(rb'[\xea-\xed][\x80-\xbf][\x80-\xbf]')
HTTP_RE = re.compile(rb'HTTP/[12]\.[01]|GET |POST |PUT |DELETE |HEAD ')
JSON_RE = re.compile(rb'\{"|"worldId"|"channelId"|"world_id"|"channel')
WORLD_ID_STR_RE = re.compile(rb'worldId|world_id|worldID')
CHANNEL_STR_RE = re.compile(rb'channelId|channel_id|channelName|channel_name')
DIGIT17_RE = re.compile(rb'\d{17}')

# Collect all findings
worldid_finds = []
korean_utf8_finds = []
korean_euckr_finds = []
http_finds = []
json_finds = []
digit17_finds = []

for pkt in packets:
    if not (IP in pkt):
        continue
    if Raw not in pkt:
        continue

    raw = bytes(pkt[Raw])
    if not raw:
        continue

    # Get port info
    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        proto = 'TCP'
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        proto = 'UDP'
    else:
        continue

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst

    info = f"{proto} {src_ip}:{sport} -> {dst_ip}:{dport} ({len(raw)} bytes payload)"

    # 17-digit numbers
    for m in DIGIT17_RE.finditer(raw):
        digit17_finds.append((info, m.start(), m.group().decode('ascii', errors='replace'), raw))

    # HTTP
    for m in HTTP_RE.finditer(raw):
        http_finds.append((info, m.start(), raw))

    # JSON / keyword
    for m in JSON_RE.finditer(raw):
        json_finds.append((info, m.start(), raw))

    # Korean UTF-8
    for m in KOREAN_UTF8_RE.finditer(raw):
        korean_utf8_finds.append((info, m.start(), raw))

    # Korean EUC-KR
    for m in KOREAN_EUCKR_RE.finditer(raw):
        korean_euckr_finds.append((info, m.start(), raw))

print(f"\n--- 17-digit number sequences (worldId pattern) ---")
print(f"Found {len(digit17_finds)} occurrences")
seen_17 = set()
for info, pos, val, raw in digit17_finds[:20]:
    if val not in seen_17:
        seen_17.add(val)
        print(f"  Value: {val}")
        print(f"  In: {info}")
        print(f"  Context (hex, pos {pos}):")
        start = max(0, pos-4)
        end = min(len(raw), pos+21)
        print(f"    {hex_dump(raw[start:end], 32)}")

print(f"\n--- HTTP traffic ---")
print(f"Found {len(http_finds)} occurrences")
seen_http = set()
for info, pos, raw in http_finds[:10]:
    key = info
    if key not in seen_http:
        seen_http.add(key)
        print(f"  {info}")
        # Try to decode as text
        try:
            text = raw[:512].decode('utf-8', errors='replace')
            print(f"  Content preview: {repr(text[:200])}")
        except:
            print(f"  Hex preview:")
            print(hex_dump(raw, 64))

print(f"\n--- JSON / keyword patterns ---")
print(f"Found {len(json_finds)} occurrences")
for info, pos, raw in json_finds[:10]:
    print(f"  {info}")
    start = max(0, pos-4)
    end = min(len(raw), pos+200)
    try:
        text = raw[start:end].decode('utf-8', errors='replace')
        print(f"  Content: {repr(text[:200])}")
    except:
        print(hex_dump(raw[start:end], 64))

print(f"\n--- Korean UTF-8 sequences ---")
print(f"Found {len(korean_utf8_finds)} occurrences in packets")
# Group by packet
korean_pkts = {}
for info, pos, raw in korean_utf8_finds:
    if info not in korean_pkts:
        korean_pkts[info] = (pos, raw)
print(f"Unique packets with Korean UTF-8: {len(korean_pkts)}")
for info, (pos, raw) in list(korean_pkts.items())[:10]:
    print(f"  {info}")
    start = max(0, pos-4)
    end = min(len(raw), pos+100)
    try:
        text = raw[start:end].decode('utf-8', errors='replace')
        print(f"  Content: {repr(text[:150])}")
    except:
        print(hex_dump(raw[start:end], 48))

print(f"\n--- Korean EUC-KR sequences ---")
print(f"Found {len(korean_euckr_finds)} occurrences in packets")
korean_euckr_pkts = {}
for info, pos, raw in korean_euckr_finds:
    if info not in korean_euckr_pkts:
        korean_euckr_pkts[info] = (pos, raw)
print(f"Unique packets with Korean EUC-KR: {len(korean_euckr_pkts)}")
for info, (pos, raw) in list(korean_euckr_pkts.items())[:10]:
    print(f"  {info}")
    start = max(0, pos-4)
    end = min(len(raw), pos+100)
    try:
        text = raw[start:end].decode('euc-kr', errors='replace')
        print(f"  Content (EUC-KR): {repr(text[:150])}")
    except:
        print(hex_dump(raw[start:end], 48))

print("\n" + "=" * 80)
print("SECTION 5: BYTE-POSITION ENTROPY ANALYSIS FOR ALL PORTS != 32800")
print("=" * 80)

# Group raw payloads by port pair
port_payloads = collections.defaultdict(list)
for pkt in packets:
    if not (IP in pkt and Raw in pkt):
        continue
    raw = bytes(pkt[Raw])
    if not raw:
        continue
    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        proto = 'TCP'
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        proto = 'UDP'
    else:
        continue

    # Skip port 32800
    if sport == 32800 or dport == 32800:
        continue

    key = (proto, sport, dport)
    port_payloads[key].append(raw)

import math

def byte_entropy(data_list, position):
    """Calculate entropy at a given byte position across packets."""
    values = [d[position] for d in data_list if len(d) > position]
    if not values:
        return 0.0
    counter = collections.Counter(values)
    total = len(values)
    entropy = -sum((c/total) * math.log2(c/total) for c in counter.values())
    return entropy

def analyze_port_payloads(key, payloads, max_pos=64):
    proto, sport, dport = key
    print(f"\n  {proto} {sport} -> {dport} ({len(payloads)} packets)")

    # Only analyze if we have enough packets
    if len(payloads) < 3:
        print(f"    Too few packets to analyze ({len(payloads)})")
        # Just show hex dumps
        for i, p in enumerate(payloads[:3]):
            print(f"    Packet {i+1}: {p[:64].hex()}")
        return

    # Show first few raw payloads
    print(f"    First 3 raw payloads (hex, first 48 bytes):")
    for i, p in enumerate(payloads[:3]):
        print(f"      [{i+1}] {p[:48].hex()}")

    # Byte entropy at each position
    max_pos = min(max_pos, min(len(p) for p in payloads if len(p) > 0))
    if max_pos == 0:
        return

    print(f"    Byte entropy at positions 0-{max_pos-1}:")
    entropies = []
    for pos in range(min(max_pos, 64)):
        vals = [d[pos] for d in payloads if len(d) > pos]
        if not vals:
            continue
        e = byte_entropy(payloads, pos)
        # Show byte value distribution too
        counter = collections.Counter([d[pos] for d in payloads if len(d) > pos])
        most_common = counter.most_common(3)
        fixed = len(counter) == 1
        entropies.append((pos, e, most_common, fixed, len(vals)))

    # Print entropy table
    print(f"    {'Pos':<5} {'Entropy':<10} {'Fixed?':<8} {'Most Common Values'}")
    print(f"    {'-'*5} {'-'*10} {'-'*8} {'-'*40}")
    for pos, e, mc, fixed, n in entropies:
        mc_str = ', '.join(f"0x{v:02x}({c})" for v,c in mc)
        fixed_str = "FIXED" if fixed else ""
        print(f"    {pos:<5} {e:<10.4f} {fixed_str:<8} {mc_str}")

    # Check for plaintext patterns
    # Try to decode all payloads as UTF-8
    plaintext_count = 0
    for p in payloads:
        try:
            decoded = p.decode('utf-8', errors='strict')
            plaintext_count += 1
        except:
            pass
    print(f"    UTF-8 decodable packets: {plaintext_count}/{len(payloads)}")

    # Try ASCII ratio
    ascii_ratios = []
    for p in payloads[:10]:
        ascii_count = sum(1 for b in p if 32 <= b < 127)
        ascii_ratios.append(ascii_count / len(p) if p else 0)
    avg_ascii = sum(ascii_ratios) / len(ascii_ratios) if ascii_ratios else 0
    print(f"    Avg ASCII ratio: {avg_ascii:.2%}")

for key in sorted(port_payloads.keys(), key=lambda x: -len(port_payloads[x])):
    analyze_port_payloads(key, port_payloads[key])

print("\n" + "=" * 80)
print("SECTION 6: FULL HTTP CONTENT DUMP")
print("=" * 80)

for pkt in packets:
    if not (IP in pkt and Raw in pkt):
        continue
    raw = bytes(pkt[Raw])
    if not raw:
        continue
    if HTTP_RE.search(raw):
        if TCP in pkt:
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            print(f"\nTCP {pkt[IP].src}:{sport} -> {pkt[IP].dst}:{dport}")
        try:
            text = raw.decode('utf-8', errors='replace')
            print(text[:1000])
        except:
            print(hex_dump(raw, 128))
        print("---")

print("\n" + "=" * 80)
print("SECTION 7: NON-32800 PORT FULL PAYLOAD INSPECTION")
print("=" * 80)

# Show ALL unique packets for non-32800 ports
seen_content = set()
for pkt in packets:
    if not (IP in pkt and Raw in pkt):
        continue
    raw = bytes(pkt[Raw])
    if not raw:
        continue

    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        proto = 'TCP'
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        proto = 'UDP'
    else:
        continue

    if sport == 32800 or dport == 32800:
        continue

    content_key = (sport, dport, raw[:16])
    if content_key in seen_content:
        continue
    seen_content.add(content_key)

    print(f"\n{proto} {pkt[IP].src}:{sport} -> {pkt[IP].dst}:{dport} ({len(raw)} bytes)")
    print(hex_dump(raw, 128))
    # Try various encodings
    for enc in ['utf-8', 'euc-kr', 'cp949']:
        try:
            text = raw.decode(enc, errors='strict')
            printable = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
            if printable / len(text) > 0.7:
                print(f"  Decoded as {enc}: {repr(text[:200])}")
                break
        except:
            pass

print("\n" + "=" * 80)
print("SECTION 8: SEARCH FOR SPECIFIC MAPLEWORLD PATTERNS")
print("=" * 80)

# More aggressive search for any plaintext data
PATTERNS = {
    'world_url': re.compile(rb'maplestory\.nexon\.com|mapleworlds|maple_world', re.I),
    'ppsn': re.compile(rb'ppsn|PPSN'),
    'friend': re.compile(rb'friend|Friend|FRIEND'),
    'channel': re.compile(rb'channel|Channel|CHANNEL|\xcc\xb1\xb3\xa1\xb7'),  # channel in ASCII + Korean
    'world': re.compile(rb'world|World|WORLD'),
    'login': re.compile(rb'login|Login|LOGIN|auth|Auth|token|Token'),
    'session': re.compile(rb'session|Session'),
    'json_brace': re.compile(rb'\{[^\}]{0,200}\}'),
}

for pat_name, pat in PATTERNS.items():
    matches = []
    for pkt in packets:
        if Raw not in pkt:
            continue
        raw = bytes(pkt[Raw])
        for m in pat.finditer(raw):
            if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            else:
                continue
            matches.append((sport, dport, m.start(), m.group(), raw))

    print(f"\nPattern '{pat_name}': {len(matches)} matches")
    for sport, dport, pos, match, raw in matches[:5]:
        print(f"  Port {sport}->{dport}, pos {pos}: {repr(match[:50])}")
        start = max(0, pos-8)
        end = min(len(raw), pos+50)
        try:
            ctx = raw[start:end].decode('utf-8', errors='replace')
            print(f"    Context: {repr(ctx)}")
        except:
            pass

print("\n" + "=" * 80)
print("ANALYSIS COMPLETE")
print("=" * 80)
