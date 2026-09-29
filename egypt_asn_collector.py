#!/usr/bin/env python3
"""
egypt_asn_collector.py
-----------------------
Builds a plain-text list of IPv4/IPv6 prefixes announced by Egyptian ASNs,
formatted for consumption by a FortiGate "External Connector" / threat feed
(Security Fabric > External Connectors > IP Address, or on older firmware
System > External Connectors > IP Address List).

How it works
------------
1. Ask RIPEstat for every ASN registered to country "EG" (routed ASNs).
2. For each ASN, ask RIPEstat for the prefixes it currently announces.
3. Falls back to bgpview.io per-ASN if RIPEstat fails for a given ASN.
4. Collapses/aggregates overlapping or adjacent prefixes to keep the list
   small (FortiGate external resources have a size limit per list, usually
   128KB / ~ a few hundred thousand lines depending on model/firmware).
5. Writes:
     egypt_asn_ipv4.txt
     egypt_asn_ipv6.txt
     egypt_asn_combined.txt   (both, for connectors that accept mixed input)
     egypt_asn_map.csv        (asn,name,prefix_count) for auditing

Requirements
------------
    pip install requests

Usage
-----
    python3 egypt_asn_collector.py                 # writes files to ./output
    python3 egypt_asn_collector.py --out /var/www/html/feeds
    python3 egypt_asn_collector.py --v4-only
    python3 egypt_asn_collector.py --exclude-asn 8452,36992   # e.g. skip mobile CGNAT ASNs

Then serve the output directory over HTTP/HTTPS (nginx, Apache, or even
`python3 -m http.server`) so FortiGate can pull it on a schedule.

FortiGate side (GUI, v7.x):
  Security Fabric > External Connectors > + Create New > IP Address
    Name:            EG-ASN-IPv4
    URI of external resource: http://your-host/feeds/egypt_asn_ipv4.txt
    Refresh Rate:    corresponds to how often you re-run this script (e.g. 1440 min = daily)
  Then reference it as a source/destination address in a firewall policy,
  or add it to an address group alongside other objects.

FortiGate side (CLI):
    config system external-resource
        edit "EG-ASN-IPv4"
            set type address
            set resource "http://your-host/feeds/egypt_asn_ipv4.txt"
            set refresh-rate 1440
        next
    end
"""

import argparse
import csv
import ipaddress
import json
import sys
import time
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("This script needs the 'requests' library: pip install requests")

RIPESTAT_COUNTRY_ASNS = "https://stat.ripe.net/data/country-asns/data.json"
RIPESTAT_ANNOUNCED = "https://stat.ripe.net/data/announced-prefixes/data.json"
BGPVIEW_ASN_PREFIXES = "https://api.bgpview.io/asn/{asn}/prefixes"

HEADERS = {"User-Agent": "egypt-asn-collector/1.0 (fortigate-feed-script)"}
TIMEOUT = 20
RETRIES = 3
RETRY_SLEEP = 2


def http_get_json(url, params=None):
    last_err = None
    for attempt in range(1, RETRIES + 1):
        try:
            r = requests.get(url, params=params, headers=HEADERS, timeout=TIMEOUT)
            r.raise_for_status()
            return r.json()
        except Exception as e:  # noqa: BLE001
            last_err = e
            time.sleep(RETRY_SLEEP * attempt)
    print(f"  ! giving up on {url} ({last_err})", file=sys.stderr)
    return None


def _parse_asn_list(raw):
    """RIPEstat's country-asns `routed` field is inconsistent across
    endpoints/params: sometimes a JSON list of ints, sometimes a list of
    dicts, and often just a plain comma-separated string of ASN numbers
    (e.g. "8452,5536,15475"). Handle all three defensively rather than
    assuming a shape and crashing on real data."""
    if raw is None:
        return []

    if isinstance(raw, str):
        raw = raw.strip()
        try:
            parsed = json.loads(raw)
            items = parsed if isinstance(parsed, list) else [parsed]
        except (json.JSONDecodeError, TypeError):
            items = [tok.strip() for tok in raw.split(",") if tok.strip()]
    elif isinstance(raw, list):
        items = raw
    else:
        items = [raw]

    out = []
    for entry in items:
        if isinstance(entry, dict):
            asn_val = entry.get("asn") or entry.get("resource") or entry.get("id")
            if asn_val is None:
                continue
            out.append((int(asn_val), entry.get("name", "")))
        else:
            try:
                out.append((int(entry), ""))
            except (TypeError, ValueError):
                continue
    return out


def get_egyptian_asns():
    """Return list of (asn:int, name:str) for ASNs registered/routed under EG."""
    data = http_get_json(RIPESTAT_COUNTRY_ASNS, {"resource": "EG", "lod": 1})
    if not data:
        sys.exit("Could not fetch ASN list from RIPEstat — check network/DNS.")

    countries = data.get("data", {}).get("countries", [])
    if not countries:
        sys.exit("RIPEstat returned no country data for EG.")

    routed = countries[0].get("routed")
    asns = _parse_asn_list(routed)
    if not asns:
        sys.exit(f"RIPEstat returned no parseable routed ASNs for EG (raw type: {type(routed).__name__}).")
    return asns


def get_prefixes_ripestat(asn):
    data = http_get_json(RIPESTAT_ANNOUNCED, {"resource": f"AS{asn}"})
    if not data:
        return None
    prefixes = data.get("data", {}).get("prefixes", [])
    return [p["prefix"] for p in prefixes]


def get_prefixes_bgpview(asn):
    data = http_get_json(BGPVIEW_ASN_PREFIXES.format(asn=asn))
    if not data or data.get("status") != "ok":
        return []
    out = []
    for fam in ("ipv4_prefixes", "ipv6_prefixes"):
        for p in data["data"].get(fam, []):
            out.append(p["prefix"])
    return out


def collect_prefixes(asns, exclude, sleep_between):
    v4, v6 = [], []
    audit_rows = []

    for i, (asn, name) in enumerate(asns, 1):
        if asn in exclude:
            continue
        print(f"[{i}/{len(asns)}] AS{asn} {name!r}", file=sys.stderr)

        prefixes = get_prefixes_ripestat(asn)
        if not prefixes:
            prefixes = get_prefixes_bgpview(asn)

        count = 0
        for p in prefixes or []:
            try:
                net = ipaddress.ip_network(p, strict=False)
            except ValueError:
                continue
            (v6 if net.version == 6 else v4).append(net)
            count += 1

        audit_rows.append((asn, name, count))
        if sleep_between:
            time.sleep(sleep_between)

    return v4, v6, audit_rows


def collapse(nets):
    if not nets:
        return []
    v4 = sorted({n for n in nets if n.version == 4}, key=lambda n: (n.network_address, n.prefixlen))
    v6 = sorted({n for n in nets if n.version == 6}, key=lambda n: (n.network_address, n.prefixlen))
    collapsed = list(ipaddress.collapse_addresses(v4)) + list(ipaddress.collapse_addresses(v6))
    return collapsed


def write_list(path, nets, header_lines):
    with open(path, "w") as f:
        for line in header_lines:
            f.write(f"# {line}\n")
        for n in nets:
            f.write(f"{n}\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="./output", help="Output directory (default: ./output)")
    ap.add_argument("--v4-only", action="store_true", help="Skip IPv6 prefixes")
    ap.add_argument("--v6-only", action="store_true", help="Skip IPv4 prefixes")
    ap.add_argument("--exclude-asn", default="", help="Comma-separated ASNs to skip (e.g. mobile CGNAT ranges you don't want)")
    ap.add_argument("--sleep", type=float, default=0.3, help="Seconds to sleep between per-ASN requests (be polite to RIPEstat)")
    args = ap.parse_args()

    exclude = {int(x) for x in args.exclude_asn.split(",") if x.strip()}

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    print("Fetching Egyptian ASN list from RIPEstat...", file=sys.stderr)
    asns = get_egyptian_asns()
    print(f"Found {len(asns)} routed ASNs registered to EG.", file=sys.stderr)

    v4_raw, v6_raw, audit = collect_prefixes(asns, exclude, args.sleep)

    v4 = collapse(v4_raw) if not args.v6_only else []
    v6 = collapse(v6_raw) if not args.v4_only else []

    stamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    header = [
        f"Egyptian ASN prefix list — generated {stamp}",
        f"Source ASNs: {len(asns)} (RIPEstat country-asns, resource=EG)",
        "Format: one CIDR per line — for FortiGate External Connector (IP Address type)",
    ]

    if v4:
        write_list(out_dir / "egypt_asn_ipv4.txt", v4, header + [f"IPv4 prefixes: {len(v4)}"])
    if v6:
        write_list(out_dir / "egypt_asn_ipv6.txt", v6, header + [f"IPv6 prefixes: {len(v6)}"])
    if v4 or v6:
        write_list(out_dir / "egypt_asn_combined.txt", v4 + v6, header + [f"Total prefixes: {len(v4) + len(v6)}"])

    with open(out_dir / "egypt_asn_map.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["asn", "name", "prefix_count"])
        w.writerows(audit)

    print(f"\nDone. IPv4: {len(v4)} prefixes, IPv6: {len(v6)} prefixes.", file=sys.stderr)
    print(f"Files written to {out_dir.resolve()}", file=sys.stderr)


if __name__ == "__main__":
    main()
