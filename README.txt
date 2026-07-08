Project 5 — Read the Traffic

Files in this repository:
baseline_flows.csv
window_flows.csv
flow_baseline.py
gpu_fabric_check.sh
traffic_watch.py
REPORT.docx
README.txt
AI_USAGE.txt
output/run_output.txt

The command to reproduce the run:
python3 traffic_watch.py baseline_flows.csv window_flows.csv > output/run_output.txt

The function of this detector is:
- Calculates and saves a per-host behavioural baseline from baseline_flows.csv
- records the bytes_out for each host for a p95 percentile
- logs the normal destinations for each host
- captures the default host ports that are used by each host
- compares live hour in window_flows.csv to that baseline
- flags beaconing, port scan / lateral movement, exfiltration

AI usage:
If any AI support was used, it was only reviewed or for writing after the manual analysis. Final results were manually checked with the actual flows.
