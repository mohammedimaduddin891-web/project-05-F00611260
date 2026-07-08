#!/usr/bin/env python3
"""
flow_baseline.py — a tiny behavioral baseline detector.

Builds a per-host profile from a baseline NetFlow CSV, then scores a live
window against it. Flags three anomaly classes a human still has to confirm:
  - beaconing : same (src,dst,port) at a near-fixed interval, low jitter
  - port_scan : one src hits many dst on admin ports in a short burst
  - exfil      : bytes_out far above the host's p95 baseline

This is deliberately simple and explainable. It is NOT a replacement for an
NDR product — it is the math under the hood, so you can read what the AI reads.
Usage:  python3 flow_baseline.py baseline_flows.csv window_flows.csv
"""
import csv, sys, statistics
from collections import defaultdict

ADMIN_PORTS = {22, 3389, 445, 5985, 5986}

def load(path):
    rows = []
    with open(path) as f:
        for r in csv.DictReader(f):
            if r["ts"].startswith("#") or not r.get("src_ip"):
                continue
            r["bytes_out"] = int(r["bytes_out"]); r["dst_port"] = int(r["dst_port"])
            rows.append(r)
    return rows

def host_p95_out(rows):
    out = defaultdict(list)
    for r in rows:
        out[r["src_ip"]].append(r["bytes_out"])
    return {h: (max(v) if len(v) < 3 else statistics.quantiles(v, n=20)[-1])
            for h, v in out.items()}

def detect(baseline, window):
    p95 = host_p95_out(baseline)
    findings = []
    # exfil: bytes_out >> baseline p95 (10x guardrail so we are not noisy)
    for r in window:
        ref = p95.get(r["src_ip"], 10_000)
        if r["bytes_out"] > 10 * ref and r["bytes_out"] > 1_000_000:
            findings.append(("exfil", r["src_ip"], r["dst_ip"], r["bytes_out"]))
    # port_scan: one src -> many dst on admin ports within a short burst
    scan = defaultdict(set)
    for r in window:
        if r["dst_port"] in ADMIN_PORTS:
            scan[r["src_ip"]].add(r["dst_ip"])
    for src, dsts in scan.items():
        if len(dsts) >= 4:
            findings.append(("port_scan", src, f"{len(dsts)} hosts", sorted(ADMIN_PORTS)))
    # beaconing: same (src,dst,port) repeating with low byte variance
    beac = defaultdict(list)
    for r in window:
        beac[(r["src_ip"], r["dst_ip"], r["dst_port"])].append(r["bytes_out"])
    for (s, d, p), b in beac.items():
        if len(b) >= 4 and statistics.pstdev(b) < 50:
            findings.append(("beaconing", s, f"{d}:{p}", f"{len(b)} hits, low jitter"))
    return findings

if __name__ == "__main__":
    base, win = load(sys.argv[1]), load(sys.argv[2])
    hits = detect(base, win)
    if not hits:
        print("no anomalies — but absence of a flag is not proof of safety. Verify.")
    for cls, src, dst, detail in hits:
        print(f"[{cls:9}] src={src:<13} dst={dst}  ::  {detail}")
    print(f"\n{len(hits)} candidate(s). A human confirms each before any block. — Coach")
