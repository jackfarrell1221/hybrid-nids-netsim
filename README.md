# NEXUS NIDS — Hybrid Network Intrusion Detection System

> **Academic & Security Disclaimer:**
> *"This is a proof-of-concept Network Intrusion Detection System (NIDS) evaluated using a controlled synthetic network environment."*

---

## 1. Project Overview

**NEXUS NIDS** is an enterprise-grade Security Operations Center (SOC) analyst workstation and hybrid network intrusion detection application. It combines:

1. **Deterministic Rule Engine:** Intercepts known, high-confidence attack vectors (Port Scans, DoS Floods, Data Exfiltration, Data Theft) with zero ML overhead and instant execution (< 1 ms).
2. **Unsupervised Isolation Forest (ML Layer):** Identifies out-of-distribution anomalous network traffic that passes deterministic rules without requiring labeled attack samples during training.
3. **Transparent SOC Operations Console:** Designed for SOC analysts and incident responders, providing full explainability, telemetry drawers, live flow inspection, attack scenario simulation, offline evaluation metrics, and system health monitoring.

---

## 2. Architecture & Pipeline

```
                     Incoming Network Flow Event
                 [duration, src_bytes, dst_bytes]
                                │
                                ▼
                       Input Validation
             (Type checking, boundary & range validation)
                                │
                                ▼
                   Deterministic Rule Engine
           ├── Rule 1: PORT_SCAN (duration < 1s, bytes < 100)
           ├── Rule 2: DATA_EXFILTRATION (duration > 60s, dst > 10MB)
           ├── Rule 3: DOS (src_bytes / (dst_bytes + 1) > 10)
           └── Rule 4: DATA_THEFT (dst_bytes / (src_bytes + 1) > 10)
                                │
                  ┌─────────────┴─────────────┐
            Match │                           │ No Match
                  ▼                           ▼
         RULE INTRUSION            Isolation Forest Model
      (Immediate Alert Log)         (Unsupervised Anomaly)
                  │                           │
                  │                   ┌───────┴───────┐
                  │         Score < 0 │               │ Score >= 0
                  │       (Outlier -1)▼               ▼ (Inlier 1)
                  │             ML INTRUSION        NORMAL
                  │            ("ML_ANOMALY")      TRAFFIC
                  │                   │               │
                  └───────────┬───────┴───────────────┘
                              ▼
                 SQLite Audit Log (`nids.db`)
               (Persists alerts & flow metrics)
                              ▼
                  JSON REST API Microservice
                              ▼
            NEXUS NIDS SOC Console (React + Vite)
```

---

## 3. Key Capabilities & Features

- **SOC Analyst Workstation Interface:** Dark mode default with light mode toggle, built with CSS variables (`--soc-bg`, `--soc-card`, `--soc-primary`, `--soc-critical`), semantic color system, Inter font family, and JetBrains Mono for technical telemetry.
- **9 Dedicated Monitoring Views:**
  1. **Security Overview:** Real-time KPI metrics, active system status indicators, recent alerts log, and attack distribution charts.
  2. **Alerts Log:** Filterable alert log with severity tags, attack types, latency metrics, and slide-over telemetry drawer with explainability breakdown.
  3. **Traffic Analysis:** Flow Inspector with common attack vector presets and interactive attack scenario simulator.
  4. **Detection Rules:** Priority-ordered deterministic rule list with exact conditions and pipeline visualization.
  5. **Detection Analytics:** Attack distribution charts, normal vs intrusion traffic split, and rule vs ML method breakdown.
  6. **Model Evaluation:** Offline benchmark results with precision, recall, F1-score, confusion matrix, and classification report.
  7. **ML Model Operations:** Isolation Forest configuration, model file telemetry, and single-click online model retraining.
  8. **API & System Health:** Live status of API, Rule Engine, ML Model, and SQLite database with real-time HTTP endpoint latency probes.
  9. **Settings:** Theme selection (Dark/Light), data polling interval settings, and application metadata.
- **Zero Fake Data Policy:** All statistics, charts, tables, and metrics are computed dynamically from real API endpoints.

---

## 4. REST API Reference

The Flask backend (`http://localhost:5000`) provides the following REST API endpoints:

| Endpoint | Method | Description |
|---|---|---|
| `/api/health` | `GET` | Microservice liveness and model load status |
| `/api/predict` | `POST` | Classifies single flow `[duration, src_bytes, dst_bytes]` |
| `/api/train` | `POST` | Retrains Isolation Forest model on baseline data |
| `/api/simulate` | `POST` | Generates simulated attack scenarios |
| `/api/simulate/scenarios` | `GET` | Lists available attack simulation scenarios |
| `/api/alerts` | `GET` | Fetches historical intrusion alerts (`?limit=N`) |
| `/api/statistics` | `GET` | Returns aggregated flow & detection metrics |
| `/api/rules` | `GET` | Returns active deterministic detection rules |
| `/api/model/info` | `GET` | Returns Isolation Forest hyperparameters & file stats |
| `/api/system/health` | `GET` | Provides component health status across system |
| `/api/evaluation` | `GET` | Reads benchmark results from `results/evaluation.json` |

---

## 5. NetSim Dataset Processing & Deployment

### 1. Extract NetSim Traces & PCAP Packets
The system parses 17 raw NetSim simulation CSVs (`normal/`, `DoS/`, `Data theft/`, `Exfiltration/`) and 3 Wireshark PCAPs (`portscan/`):
```bash
# Build unified master NetSim flow dataset (5,421 flows extracted)
python scripts/build_netsim_dataset.py

# Train ML detector on NetSim training split
python -c "from backend.models.model_manager import train_model; print(train_model())"

# Seed SQLite database with representative NetSim alerts
python scripts/seed_netsim_db.py
```

### 2. Run Flask Server (Port 5001)
```bash
python backend/app.py
```

### 3. Run Frontend SOC Workstation (Port 5174)
```bash
cd frontend
npm run dev
```

Dashboard is available at **http://localhost:5174**.

---

## 6. Automated Testing & NetSim Benchmark Evaluation

### Run Test Suite (65/65 Tests Passing)
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

## 7. License & Disclaimers

Developed as an educational proof-of-concept Network Intrusion Detection System. Designed for controlled research, SOC training, and demonstration.
