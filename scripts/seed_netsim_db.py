"""
scripts/seed_netsim_db.py — Pre-populates SQLite database with real NetSim simulation results.
"""

import os
import sys
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.config import DATA_DIR
from backend.services.detection_service import detect_flow
from backend.models.model_manager import get_alert_db

def seed_db(reset_first: bool = True):
    dataset_file = os.path.join(DATA_DIR, "netsim_master_dataset.csv")
    if not os.path.exists(dataset_file):
        print(f"Dataset not found at {dataset_file}")
        return

    df = pd.read_csv(dataset_file)
    print(f"Loading NetSim flows to seed database from {dataset_file} ({len(df)} total flows available)...")

    db = get_alert_db()

    if reset_first:
        conn = db._get_conn()
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM flows")
        conn.commit()
        print("[+] Reset stale records in SQLite database.")

    # Seed an active historical log across all scenarios:
    # 100 Port Scan, 100 DoS, 80 Exfil, 66 Theft, 150 Normal
    samples = []
    for atype in df['attack_type'].fillna('NORMAL').unique():
        sub = df[df['attack_type'].fillna('NORMAL') == atype]
        samples.append(sub.head(min(len(sub), 100)))

    seed_df = pd.concat(samples).sample(frac=1.0, random_state=42).reset_index(drop=True)

    print(f"Processing {len(seed_df)} NetSim flows through hybrid detection pipeline...")
    for _, row in seed_df.iterrows():
        flow = {
            "duration": float(row['duration']),
            "src_bytes": float(row['src_bytes']),
            "dst_bytes": float(row['dst_bytes']),
            "src_ip": str(row.get('src_ip', '11.1.1.2')),
            "dst_ip": str(row.get('dst_ip', '11.1.1.5')),
        }
        res = detect_flow(flow, persist=True)
        db.log_flow(res)

    stats = db.get_statistics()
    print("Seeding complete! Database Stats:")
    print(f"  Total reconstructed flows: {stats.get('total_flows')}")
    print(f"  Intrusions: {stats.get('intrusion_flows')}")
    print(f"  Normal: {stats.get('normal_flows')}")
    print(f"  Detection rate: {stats.get('detection_percentage')}%")
    print(f"  Attack distribution: {stats.get('attack_distribution')}")

if __name__ == '__main__':
    seed_db()
