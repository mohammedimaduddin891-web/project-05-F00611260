#!/usr/bin/env python3
import csv
import statistics
import sys
from collections import defaultdict
from datetime import datetime

ADMIN_PORTS = {22, 3389, 445, 5985, 5986}

def parse_ts(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

def load_flows(path):
    rows = []
    with open(path, newline="", encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            try:
                ts = row.get("ts", "")
                if ts.startswith("#") or not row.get("src_ip"):
                    continue
                row["ts_dt"] = parse_ts(ts)
                row["dst_port"] = int(row["dst_port"])
                row["bytes_out"] = int(row["bytes_out"])
                row["bytes_in"] = int(row["bytes_in"])
                rows.append(row)
            except Exception:
                continue
    return rows

def p95(values):
    if not values:
        return 0
    if len(values) < 3:
        return max(values)
    return statistics.quantiles(values, n=20)[-1]

def build_profile(rows):
    profile = {}
    grouped = defaultdict(list)
    for r in rows:
        grouped[r["src_ip"]].append(r)
    for host, items in grouped.items():
        profile[host] = {
            "p95_bytes_out": p95([r["bytes_out"] for r in items]),
            "normal_destinations": sorted({r["dst_ip"] for r in items}),
            "normal_ports": sorted({r["dst_port"] for r in items}),
        }
    return profile

def detect_exfil(profile, window_rows):
    findings = []
    for r in window_rows:
        host = r["src_ip"]
        ref = profile.get(host, {}).get("p95_bytes_out", 0) or 10000
        if r["bytes_out"] > 10 * ref and r["bytes_out"] > 1_000_000:
            findings.append({
                "host": host,
                "class": "exfil",
                "evidence": f'bytes_out={r["bytes_out"]} exceeded host p95={int(ref)} by more than 10x; destination {r["dst_ip"]}:{r["dst_port"]}',
                "ts": r["ts"],
            })
    return findings

def detect_port_scan(profile, window_rows):
    findings = []
    by_host = defaultdict(list)
    for r in window_rows:
        by_host[r["src_ip"]].append(r)
    for host, items in by_host.items():
        admin_hits = [r for r in items if r["dst_port"] in ADMIN_PORTS]
        distinct_dst = sorted({r["dst_ip"] for r in admin_hits})
        if len(distinct_dst) >= 4:
            normal_ports = set(profile.get(host, {}).get("normal_ports", []))
            new_ports = sorted({r["dst_port"] for r in admin_hits if r["dst_port"] not in normal_ports})
            findings.append({
                "host": host,
                "class": "port_scan",
                "evidence": f'host touched {len(distinct_dst)} destinations on admin ports {sorted({r["dst_port"] for r in admin_hits})}; baseline normal ports were {sorted(normal_ports)}; new admin ports were {new_ports}',
                "ts": min(r["ts"] for r in admin_hits),
            })
    return findings

def detect_beaconing(profile, window_rows):
    findings = []
    groups = defaultdict(list)
    for r in window_rows:
        groups[(r["src_ip"], r["dst_ip"], r["dst_port"])].append(r)
    for (host, dst, port), items in groups.items():
        items = sorted(items, key=lambda r: r["ts_dt"])
        if len(items) < 4:
            continue
        intervals = []
        for a, b in zip(items, items[1:]):
            intervals.append((b["ts_dt"] - a["ts_dt"]).total_seconds())
        byte_values = [r["bytes_out"] for r in items]
        interval_jitter = statistics.pstdev(intervals) if len(intervals) > 1 else 0
        byte_jitter = statistics.pstdev(byte_values) if len(byte_values) > 1 else 0
        normal_dsts = set(profile.get(host, {}).get("normal_destinations", []))
        normal_ports = set(profile.get(host, {}).get("normal_ports", []))
        if interval_jitter <= 2 and byte_jitter < 50:
            findings.append({
                "host": host,
                "class": "beaconing",
                "evidence": f'{len(items)} repeated flows to {dst}:{port} every ~{int(statistics.mean(intervals))} seconds with bytes_out jitter={byte_jitter:.1f}; destination/port not in baseline sets {sorted(normal_dsts)} / {sorted(normal_ports)}',
                "ts": items[0]["ts"],
            })
    return findings

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 traffic_watch.py baseline_flows.csv window_flows.csv")
        raise SystemExit(1)

    baseline = load_flows(sys.argv[1])
    window = load_flows(sys.argv[2])
    profile = build_profile(baseline)

    print("BASELINE PROFILE")
    for host in sorted(profile):
        p = profile[host]
        print(f'{host}  p95_bytes_out={int(p["p95_bytes_out"])}  normal_destinations={p["normal_destinations"]}  normal_ports={p["normal_ports"]}')

    findings = []
    findings.extend(detect_beaconing(profile, window))
    findings.extend(detect_port_scan(profile, window))
    findings.extend(detect_exfil(profile, window))
    findings = sorted(findings, key=lambda x: (x["ts"], x["host"], x["class"]))

    print("\\nFINDINGS")
    if not findings:
        print("No findings.")
    for f in findings:
        print(f'[{f["class"]}] host={f["host"]} ts={f["ts"]} :: {f["evidence"]}')

    print(f"\\nTotal findings: {len(findings)}")
    print("Human verdict required for every finding before any block or quarantine.")

if __name__ == "__main__":
    main()
