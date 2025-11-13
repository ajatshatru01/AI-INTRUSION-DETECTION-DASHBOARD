import pyshark
import pandas as pd
from tqdm import tqdm
from datetime import datetime
import argparse
import numpy as np
import math
import asyncio
from collections import defaultdict

# --------------------------------------------
# Utility functions
# --------------------------------------------
def safe_float(x):
    try:
        return float(x)
    except:
        return 0.0

def compute_flow_features(packets, recent_flows):
    """Compute features for a single flow (list of packets)."""
    if not packets:
        return None

    first_pkt = packets[0]
    last_pkt = packets[-1]

    src_ip = first_pkt['src_ip']
    dst_ip = first_pkt['dst_ip']
    src_port = first_pkt['src_port']
    dst_port = first_pkt['dst_port']
    proto = first_pkt['proto']

    dur = packets[-1]['time'] - packets[0]['time']
    dur = max(dur, 1e-6)  # avoid division by zero

    sbytes = sum(p['length'] for p in packets if p['direction'] == 'src')
    dbytes = sum(p['length'] for p in packets if p['direction'] == 'dst')
    spkts = len([p for p in packets if p['direction'] == 'src'])
    dpkts = len([p for p in packets if p['direction'] == 'dst'])

    smean = sbytes / spkts if spkts > 0 else 0
    dmean = dbytes / dpkts if dpkts > 0 else 0

    rate = (spkts + dpkts) / dur
    sload = (sbytes * 8) / dur
    dload = (dbytes * 8) / dur

    # TCP timing placeholders
    tcprtt, synack, ackdat = np.nan, np.nan, np.nan
    for p in packets:
        if p['proto'] == 'TCP':
            tcprtt = p.get('tcprtt', np.nan)
            synack = p.get('synack', np.nan)
            ackdat = p.get('ackdat', np.nan)
            break

    # Flow identifiers
    flow_id = (src_ip, dst_ip, src_port, dst_port, proto)

    # Temporal features (ct_src_dport_ltm, ct_dst_sport_ltm)
    now_time = packets[-1]['time']
    window = 120  # 2 minutes
    ct_src_dport_ltm = len([f for f in recent_flows['src'][src_ip] if now_time - f < window])
    ct_dst_sport_ltm = len([f for f in recent_flows['dst'][dst_ip] if now_time - f < window])

    # Same IPs and ports
    is_sm_ips_ports = 1 if (src_ip == dst_ip and src_port == dst_port) else 0

    # Basic placeholders for protocol state/service (expand later if needed)
    state = "FIN" if proto == "TCP" else "CON"
    service = "http" if dst_port == "80" or src_port == "80" else "dns" if dst_port == "53" else "other"

    # Update recent flow cache
    recent_flows['src'][src_ip].append(now_time)
    recent_flows['dst'][dst_ip].append(now_time)

    return {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "proto": proto,
        "dur": dur,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "spkts": spkts,
        "dpkts": dpkts,
        "smean": smean,
        "dmean": dmean,
        "rate": rate,
        "sload": sload,
        "dload": dload,
        "tcprtt": tcprtt,
        "synack": synack,
        "ackdat": ackdat,
        "state": state,
        "service": service,
        "ct_src_dport_ltm": ct_src_dport_ltm,
        "ct_dst_sport_ltm": ct_dst_sport_ltm,
        "is_sm_ips_ports": is_sm_ips_ports
    }

# --------------------------------------------
# Flow-level extraction logic
# --------------------------------------------
def parse_pcap_to_flows(pcap_file, output_csv):
    asyncio.set_event_loop(asyncio.new_event_loop())
    cap = pyshark.FileCapture(pcap_file, keep_packets=False)

    flows = defaultdict(list)
    recent_flows = {'src': defaultdict(list), 'dst': defaultdict(list)}

    print(f"Processing packets from {pcap_file}...")
    for pkt in tqdm(cap):
        try:
            ts = safe_float(pkt.sniff_timestamp)
            if hasattr(pkt, 'ip'):
                src_ip = pkt.ip.src
                dst_ip = pkt.ip.dst
            else:
                continue

            if hasattr(pkt, 'tcp'):
                proto = 'TCP'
                src_port = pkt.tcp.srcport
                dst_port = pkt.tcp.dstport
            elif hasattr(pkt, 'udp'):
                proto = 'UDP'
                src_port = pkt.udp.srcport
                dst_port = pkt.udp.dstport
            else:
                proto = pkt.highest_layer
                src_port = dst_port = '0'

            key = (src_ip, dst_ip, src_port, dst_port, proto)
            direction = 'src'
            if 'reply' in pkt.highest_layer.lower():
                direction = 'dst'

            length = safe_float(getattr(pkt, 'length', 0))
            flows[key].append({
                'time': ts,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'proto': proto,
                'length': length,
                'direction': direction
            })

        except Exception:
            continue

    cap.close()

    print("Computing flow-level features...")
    flow_features = []
    for key, pkts in flows.items():
        pkts = sorted(pkts, key=lambda x: x['time'])
        features = compute_flow_features(pkts, recent_flows)
        if features:
            flow_features.append(features)

    df = pd.DataFrame(flow_features)
    df.to_csv(output_csv, index=False)
    print(f"✅ Saved {len(df)} flows to {output_csv}")

# --------------------------------------------
# CLI Entry Point
# --------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract selected flow-based features from PCAP")
    parser.add_argument("--pcap", "-r", required=True, help="Path to PCAP file")
    parser.add_argument("--out", "-o", default="flow_features.csv", help="Output CSV file")
    args = parser.parse_args()
    parse_pcap_to_flows(args.pcap, args.out)
