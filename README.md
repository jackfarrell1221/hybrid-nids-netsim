# NEXUS NIDS — Hybrid Network Intrusion Detection System
### Enterprise SOC Analyst Workstation & Live Wire Ingestion Engine

> **Academic & Security Disclaimer:**
> *"This is a proof-of-concept Network Intrusion Detection System (NIDS) evaluated using controlled NetSim simulation traces and synthetic attack scenarios."*

---

## 1. Project Overview

**NEXUS NIDS** is an enterprise-grade Security Operations Center (SOC) analyst workstation and hybrid network intrusion detection application. Designed to bridge high-speed deterministic traffic filtering with adaptive machine learning, it offers:

1. **Deterministic Rule Engine (Tier 1):** Intercepts known, high-confidence attack vectors (Port Scans, DoS Floods, Data Exfiltration, Data Theft) with zero machine learning overhead and sub-millisecond execution (< 1 ms).
2. **Dual-Model ML Detection Layer (Tier 2):** 
   - **Random Forest Classifier (Active):** High-precision supervised classification trained on NetSim simulation flow traces.
   - **Isolation Forest (Anomaly Fallback):** Unsupervised outlier detection for out-of-distribution traffic patterns that bypass deterministic rules.
3. **Live NIC Packet Ingestion & Wirefeed Workbench:** Windows-native dual-engine packet sniffer with Wireshark-style protocol dissection, raw hex inspection, cloud IP enrichment, and rolling throughput telemetry.
4. **Transparent SOC Operations Console:** Dark/light mode analyst workstation with 9 dedicated monitoring views, alert triage workflows, interactive attack scenario simulators, and live system health probes.

---

## 2. Architecture & Hybrid Pipeline

```
                     Incoming Network Flow / Live NIC Packet
                    [duration, src_bytes, dst_bytes, IPs, Ports]
                                        │
                                        ▼
                               Input Validation
                    (Type safety, boundary & range checking)
                                        │
                                        ▼
                          Deterministic Rule Engine (Tier 1)
                  ├── Rule 1: PORT_SCAN (duration < 1s, bytes < 100)
                  ├── Rule 2: DATA_EXFILTRATION (duration > 60s, dst > 10MB)
                  ├── Rule 3: DOS (src_bytes / (dst_bytes + 1) > 10, src > 1000B)
                  └── Rule 4: DATA_THEFT (dst_bytes / (src_bytes + 1) > 10, dst > 1000B)
                                        │
                         ┌──────────────┴──────────────┐
                   Match │                             │ No Match
                         ▼                             ▼
                RULE INTRUSION               Machine Learning (Tier 2)
             (Instant Alert Log)        ┌──────────────────────────────┐
                         │              │ Random Forest Classifier     │
                         │              │ + Isolation Forest Anomaly   │
                         │              └──────────────┬───────────────┘
                         │                             │
                         │               ┌─────────────┴─────────────┐
                         │     Outlier / │                           │ Normal /
                         │     Intrusion ▼                           ▼ Inlier
                         │         ML INTRUSION                   NORMAL
                         │       ("ML_ANOMALY" / "DOS")          TRAFFIC
                         │               │                           │
                         └───────────────┼───────────────────────────┘
                                         ▼
                            SQLite Audit Log (`nids.db`)
                         (Thread-safe WAL mode, alert triage)
                                         ▼
                            JSON REST API Microservice
                                (Flask on port 5001)
                                         ▼
                      NEXUS NIDS SOC Console (React + Vite)
                               (Vite on port 5174)
```

---

## 3. Key Capabilities & Features

### 🌐 Live Physical NIC Ingestion & Wirefeed Workbench
- **Zero-Admin Connection Telemetry:** Windows-native continuous monitoring of TCP/UDP active sockets, remote host IPs, destination ports, TCP state transitions (`SYN_SENT`, `ESTABLISHED`, `TIME_WAIT`, `FIN_WAIT`), and real interface delta I/O bytes with **zero administrator privileges required**.
- **Elevated Raw Socket Mode:** Automatically binds `socket.SOCK_RAW` with `SIO_RCVALL` for deep L2/L3 packet frame inspection when launched from an elevated administrator prompt.
- **Physical Interface Prioritization:** Auto-detects and prioritizes active internet gateways (Wi-Fi or Ethernet default route) over virtual adapters, Hyper-V, and WSL bridges.
- **Wireshark-Style Packet Dissector:**
  - Full RFC 791 (IPv4) and RFC 793 (TCP/UDP) protocol tree dissection.
  - Interactive modal with Frame, IPv4 header flags/TOS/TTL, and Transport layer sequence/acknowledgment numbers.
  - Side-by-side hexadecimal offset dumps and ASCII payload decoder.
- **Cloud Provider & Host Tagging:** Automatic non-blocking reverse-DNS resolution and cloud fingerprinting for **Microsoft Azure, AWS, Google Cloud, Cloudflare, Fastly, and Akamai**.
- **Rolling Bandwidth & PPS Timeline:** 60-second real-time streaming area chart of inbound/outbound throughput (KB/s) and packets/sec (PPS) with anomaly alert markers.
- **Real-Time Wire Filtering & Audio Alerts:** Instant protocol/IP/port/verdict search filter and Web Audio API synthesized alert chimes.

### 🛡️ SOC Operations Console
- **Security Overview:** Real-time KPI metrics, active pipeline indicators, recent intrusion stream, and attack distribution charts.
- **Alerts Log & Triage:** Filterable log with severity tags, latency benchmarks, and slide-over telemetry drawer with explainability breakdown. Triage actions: `OPEN`, `ACKNOWLEDGED`, `RESOLVED`, `FALSE_POSITIVE`.
- **Traffic Analysis & Attack Simulator:** Test live models with 20 pre-configured NetSim attack scenarios across DoS, Port Scan, Data Exfiltration, and Data Theft.
- **Detection Rules:** Priority-ordered deterministic rule list with exact conditional logic and threshold visualizer.
- **Detection Analytics:** Attack breakdown, traffic distribution, and Rule vs. ML detection ratios.
- **Model Benchmark Evaluation:** Offline evaluation showing precision, recall, F1-score, and confusion matrix against 1,627 NetSim test samples.
- **Model Operations:** Hyperparameter telemetry and single-click online model retraining.
- **System Health Probes:** Live heartbeat probes for Flask API, Rule Engine, ML Model, and SQLite database.

---

## 4. ⚡ Quick Start (Run Locally in 2 Minutes)

### Prerequisites
- **Python 3.9+** ([python.org](https://www.python.org/))
- **Node.js 18+ & npm** ([nodejs.org](https://nodejs.org/))

> [!NOTE]
> **Zero Prior Setup Required:** Pre-trained Random Forest and Isolation Forest models (`models/rf_model.joblib`) are already bundled. The SQLite database initializes automatically upon start. No WinPcap/Npcap drivers or root privileges are required to use the Zero-Admin live NIC sniffer.

---

### Option A: One-Click Launchers

#### On Windows:
Double-click `start.bat` or run in terminal:
```cmd
start.bat
```

#### On macOS / Linux:
```bash
chmod +x start.sh
./start.sh
```

---

### Option B: Manual Launch (Two Terminals)

#### 1. Start the Flask Backend (Port 5001)
```bash
# Install Python dependencies
pip install -r requirements.txt

# Start backend server
python backend/app.py
```

#### 2. Start the Frontend SOC Workstation (Port 5174)
```bash
cd frontend

# Install node dependencies
npm install

# Start Vite development server
npm run dev
```

Open your browser to: **http://localhost:5174**

---

## 5. REST API Reference

The Flask backend runs on **`http://127.0.0.1:5001`**:

### Core Detection & Evaluation
| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | `GET` | Microservice liveness and model load status |
| `/api/predict` | `POST` | Classifies single flow `[duration, src_bytes, dst_bytes]` |
| `/api/train` | `POST` | Retrains ML model on baseline dataset |
| `/api/simulate` | `POST` | Generates simulated attack scenarios |
| `/api/simulate/scenarios` | `GET` | Lists available attack simulation scenarios (20 total) |
| `/api/alerts` | `GET` | Fetches historical intrusion alerts (`?limit=N`) |
| `/api/alerts/<id>/triage` | `PUT` | Updates alert triage status (`OPEN`, `ACKNOWLEDGED`, etc.) |
| `/api/statistics` | `GET` | Returns aggregated flow & detection metrics |
| `/api/rules` | `GET` | Returns active deterministic detection rules |
| `/api/model/info` | `GET` | Returns ML hyperparameters & file telemetry |
| `/api/system/health` | `GET` | Component health probes and latency benchmarks |
| `/api/evaluation` | `GET` | Reads benchmark results from `results/evaluation.json` |

### Live NIC Sniffing & Wire Ingestion
| Endpoint | Method | Description |
|---|---|---|
| `/api/sniffer/status` | `GET` | Operational state, active engine, throughput & packet counts |
| `/api/sniffer/interfaces` | `GET` | Prioritized list of physical network adapters |
| `/api/sniffer/start` | `POST` | Starts live capture on default or selected interface |
| `/api/sniffer/stop` | `POST` | Halts active packet capture |
| `/api/sniffer/packets` | `GET` | Retrieves captured packets with Wireshark headers (`?limit=100`) |
| `/api/sniffer/metrics` | `GET` | Rolling 60-second throughput (KB/s In/Out) & PPS timeline |
| `/api/sniffer/clear` | `POST` | Clears in-memory packet buffer |

---

## 6. Optional: Database Seeding & NetSim Processing

If you wish to re-seed the SQLite database with 496 historical NetSim attack traces or retrain the machine learning model from scratch:

```bash
# Seed SQLite database with representative NetSim alerts
python scripts/seed_netsim_db.py

# (Optional) Retrain ML detector on NetSim training split
python -c "from backend.models.model_manager import train_model; print(train_model())"

# (Optional) Rebuild master NetSim flow dataset from raw CSV/PCAP traces
python scripts/build_netsim_dataset.py
```

---

## 7. Automated Testing & NetSim Benchmark Evaluation

### Run Test Suite (73/73 Tests Passing)
```bash
pytest tests/ -v
```

### Run NetSim Offline Benchmark Evaluation
```bash
python scripts/evaluate.py
```

#### NetSim Evaluation Metrics (1,627 Test Samples from Real Simulation Traces):
- **Precision:** 94.8%
- **Recall:** 100.0%
- **F1 Score:** 97.3%
- **Average Detection Latency:** 5.67 ms per flow
- **Detection Breakdown:** 1,626 Rule Detections, 1 ML Fallback Detections

---

## 8. License & Disclaimers

Developed as an educational proof-of-concept Network Intrusion Detection System. Designed for controlled research, SOC training, and demonstration.
