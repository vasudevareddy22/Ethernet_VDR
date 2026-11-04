# Network AI | Threat Defense — Enterprise Anomaly Detection System

A complete college Computer Networks and Cybersecurity capstone project implementing a real-time, AI-powered Intrusion and Anomaly Detection System (IDS/ADS) designed for enterprise SOC/SIEM environments.

![Project Status](https://img.shields.io/badge/status-active-brightgreen)
![Python](https://img.shields.io/badge/python-3.12-blue)
![Framework](https://img.shields.io/badge/backend-Flask%20%7C%20SQLite%20WAL-indigo)
![ML](https://img.shields.io/badge/models-Random%20Forest%20%7C%20Isolation%20Forest-orange)
![UI](https://img.shields.io/badge/UI-Dark%20SOC%2FSIEM%20%230B1020-0ea5e9)

---

## 1. Project Overview & Architecture

Modern enterprise networks experience massive volumes of traffic with sophisticated, polymorphic cyber attacks (DoS, Probe, R2L, U2R). Traditional rule-based firewalls fail against zero-day exploits and novel attack variants.

This project delivers an end-to-end localhost application that performs:
```
Network Session Telemetry (NSL-KDD 41 Features)
               │
               ▼
   Data Ingestion & Validation
   (Type check, Range check, Header validation)
               │
               ▼
   Reproducible Preprocessing
   (OrdinalEncoder for Categoricals, StandardScaler for Numerics)
               │
               ▼
   Dual-Engine Machine Learning Detection
   ├─ Supervised Classifier: Random Forest (Normal vs. Attack)
   └─ Unsupervised Anomaly Detector: Isolation Forest (Decision Function Score)
               │
               ▼
   Risk Scoring & Severity Classification
   (Low, Medium, High, Critical based on prediction probability)
               │
               ▼
   Automated SOC Alert Generation & SQLite Audit Persistence
   (Predictions history, Traffic telemetry logs, Incident alerts)
               │
               ▼
   Dark SOC/SIEM Operations Dashboard
   (Real-time charts, Detection lab, Batch CSV uploads, CSV Audit Reports)
```

---

## 2. Directory Structure

```
CN project/
├── app.py                      # Main Flask application & REST API endpoints
├── database.db                 # SQLite database file (WAL mode)
├── requirements.txt            # Python dependencies (Flask, scikit-learn, scapy, etc.)
├── README.md                   # Complete documentation & college viva guide
├── .gitignore                  # Git ignore rules
│
├── ai_agent/                   # AI SOC Cybersecurity Analyst Agent
│   ├── __init__.py
│   ├── agent.py                # Main SOC Analyst & Voice orchestrator
│   ├── context_builder.py      # Grounded context assembler from live SQLite tables
│   ├── conversation.py         # Multi-turn history & speech sanitization
│   ├── prompts.py              # System prompts & cybersecurity taxonomy
│   └── provider.py             # Local Expert reasoning engine + Ollama / Cloud LLM
│
├── network_monitor/            # Real-Time Packet Sniffer & Flow Aggregator
│   ├── __init__.py
│   ├── packet_capture.py       # Scapy live packet capture service & session tracking
│   └── traffic_processor.py    # ConnectionFlow bidirectional aggregation & 41-feature synthesis
│
├── database/
│   ├── __init__.py
│   └── db.py                   # SQLite schema, migrations, sessions & audit records
│
├── ml/
│   ├── __init__.py
│   ├── train_rf.py             # Reproducible training & evaluation pipeline
│   ├── predict.py              # Inference engine (RF Pipeline + Isolation Forest)
│   └── traffic_analyzer.py     # CSV traffic parser, metrics calculator & report generator
│
├── models/
│   ├── rf_pipeline.pkl         # Fitted ColumnTransformer + RandomForest pipeline
│   ├── feature_names.json      # 41 NSL-KDD feature schema
│   ├── rf_metrics.json         # Real held-out benchmark evaluation metrics
│   └── trained/
│       └── isolation_forest.joblib  # Unsupervised Isolation Forest model
│
├── data/
│   ├── raw/
│   │   ├── KDDTrain+.txt       # 125,973 training records
│   │   └── KDDTest+.txt        # 22,544 held-out test records
│   └── processed/
│       ├── label_encoders.joblib # Categorical encoders for IF
│       └── scaler.joblib         # StandardScaler offsets
│
├── static/
│   ├── css/
│   │   └── style.css           # Premium Dark SOC/SIEM design system (#0B1020)
│   └── js/
│       └── dashboard.js        # Dynamic frontend controllers, Voice API & Chart.js logic
│
├── templates/
│   └── index.html              # 7-page Single-Page SOC Dashboard (Agent, Monitor, Traffic, Lab)
│
└── tests/
    ├── test_agent_and_monitor.py    # AI SOC Agent & Live Monitor test suite (9 tests)
    ├── test_csv_investigation.py    # CSV upload & traffic analysis test suite (11 tests)
    └── test_full_suite.py           # Core ML, API & Alert test suite (22 tests)
```

---

## 3. Real Benchmark Model Evaluation Metrics

Evaluated on the official **NSL-KDD `KDDTest+.txt`** held-out benchmark dataset (22,544 connection records, including 17 novel zero-day attack types not present in the training set):

| Metric | Measured Value | Meaning in Enterprise Cybersecurity |
| :--- | :--- | :--- |
| **Accuracy** | **77.30%** | Overall correct classifications on difficult out-of-distribution test set. |
| **Precision** | **96.66%** | **Extremely high.** When an alert fires, it is virtually guaranteed to be a real attack. |
| **Recall** | **62.27%** | Proportion of all attack instances caught (affected by novel unseen zero-days). |
| **F1-Score** | **75.74%** | Harmonic mean of precision and recall. |
| **False Positive Rate** | **2.84%** | **Critically low.** Only 2.8% of legitimate business traffic is flagged. |
| **Training Samples** | **125,973** | Full KDDTrain+ dataset. |
| **Test Samples** | **22,544** | Full KDDTest+ dataset. |

### Confusion Matrix (Test Split)
```
                    Predicted Normal    Predicted Attack
Actual Normal           9,435 (TN)          276 (FP)
Actual Attack           4,842 (FN)        7,991 (TP)
```

---

## 4. Setup & Running Instructions (Windows PowerShell)

Open Windows PowerShell in the project directory:

```powershell
cd "c:\Users\vasud\OneDrive\Desktop\CN project"
```

### 1. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 2. (Optional) Retrain the Machine Learning Model
The repository already includes the trained model artifact (`models/rf_pipeline.pkl`). If you wish to retrain from scratch:
```powershell
python ml/train_rf.py
```

### 3. Run Automated Tests
Execute the 22 comprehensive test suites:
```powershell
python -m pytest tests/test_full_suite.py -v
```

### 4. Start the Application
```powershell
python app.py
```

### 5. Access the Dashboard
Open your web browser and navigate to:
> **http://localhost:5000**

---

## 5. Available REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Renders the primary SOC/SIEM Dashboard UI |
| `GET` | `/api/status` | System health, database connection, and model loaded state |
| `GET` | `/api/stats` | Aggregated telemetry, attack counts, active alerts, and 24h trend |
| `POST` | `/api/predict` | Single connection classification (RF prediction + IF anomaly score) |
| `GET` | `/api/alerts` | Paginated incident alerts with status, severity, and search filters |
| `GET` | `/api/alerts/<id>` | Full alert detail with associated prediction record |
| `PATCH` | `/api/alerts/<id>` | Update alert status (`open`, `acknowledged`, `resolved`) |
| `POST` | `/api/alerts/<id>/acknowledge` | One-click alert acknowledgement |
| `POST` | `/api/alerts/<id>/resolve` | One-click alert resolution |
| `GET` | `/api/traffic` | Ingested network telemetry logs |
| `GET` | `/api/model/performance` | Returns genuine model evaluation metrics & confusion matrix |
| `POST` | `/api/upload` (or `/api/predict/batch`) | Batch CSV file upload and classification |
| `GET` | `/api/export` | Download predictions audit report as CSV |
| `POST` | `/api/model/reload` | Hot reload ML model artifacts from disk |

---

## 6. Beginner-Friendly 5-Minute College Demo Sequence

Follow this exact flow during your project demonstration:

1. **Step 1: Introduction (1 min)**
   - *"Good morning/afternoon. My project is AI-Based Anomaly Detection in Enterprise Networks. It integrates supervised Random Forest classification with unsupervised Isolation Forest anomaly scoring to detect malicious intrusions in enterprise network traffic."*

2. **Step 2: Overview & Dashboard (1 min)**
   - Open `http://localhost:5000`.
   - Point out the dark SOC/SIEM layout: *"Here is our Security Operations Center dashboard. It shows total predictions, attacks detected, open alerts, and real-time 24-hour traffic trend lines alongside severity breakdowns."*

3. **Step 3: Interactive Detection Lab (1.5 min)**
   - Click **Detection Lab** in the left sidebar.
   - Click the **"Load Normal Sample"** button. Point out that all 41 NSL-KDD features (TCP, http, SF flag, byte counts) are populated.
   - Click **Run Prediction**. Show the green card: **NORMAL (100% confidence)**.
   - Now click **"Load Attack (DoS) Sample"**. Note the connection parameters (TCP, private service, REJ flag, count 229).
   - Click **Run Prediction**. Show the red card: **ATTACK (100% confidence)**. Point out the unsupervised Isolation Forest score (`-0.0661`), demonstrating that both models concurred.

4. **Step 4: Alert Investigation & Triage (1 min)**
   - Navigate to **Alerts** in the sidebar.
   - Show that the malicious traffic we just submitted automatically generated an Incident Alert in SQLite!
   - Click on the row to expand the detail panel (showing Source IP, Destination IP, Protocol, and attack timestamp).
   - Click the **Acknowledge** button, then click **Resolve**. Show the live status transition badge.

5. **Step 5: Reports & Model Evaluation (30 sec)**
   - Click **Reports** and show the date range selector and click **Download CSV Report** to demonstrate audit compliance.
   - Click **Model Performance** and display the real held-out test evaluation metrics (96.7% Precision, 2.8% False Positive Rate, and the Confusion Matrix).

---

## 7. 15 Viva Questions & Verified Technical Answers

#### Q1: What is NSL-KDD and why is it used?
**Answer:** NSL-KDD is an improved benchmark dataset derived from KDD Cup '99 for network intrusion detection. It solves critical flaws in the original dataset by removing duplicate records (which previously caused classifier bias toward frequent attacks) and establishing realistic difficulty levels across 41 features.

#### Q2: What are the 41 features in NSL-KDD?
**Answer:** The features are divided into 4 categories:
1. *Basic features* (duration, protocol_type, service, flag, src_bytes, dst_bytes).
2. *Content features* (num_failed_logins, logged_in, root_shell, etc.).
3. *Time-based traffic features* (connections to the same host in a 2-second window, e.g., count, srv_count, serror_rate).
4. *Host-based traffic features* (connections across destination hosts over larger windows, e.g., dst_host_count, dst_host_srv_count).

#### Q3: Why did you choose Random Forest as your primary classifier?
**Answer:** Random Forest is an ensemble learning method using bagging (Bootstrap Aggregating) of decision trees. It excels on tabular network data because:
- It handles non-linear relationships and high-dimensional features without overfitting.
- It resists noise through feature subsampling at each split.
- It provides fast, low-latency inference suitable for network session evaluation.

#### Q4: How is Isolation Forest different from Random Forest?
**Answer:** 
- *Random Forest* is **supervised** — it trains on labeled data (normal vs. attack) and outputs a class probability.
- *Isolation Forest* is **unsupervised** — it isolates anomalies by randomly partitioning feature space. Because anomalous records are few and attribute-different, they are isolated in fewer splits. Its output is an anomaly score (`decision_function`), not an attack probability.

#### Q5: Why shouldn't Isolation Forest anomaly scores be treated as attack probabilities?
**Answer:** Isolation Forest does not calculate posterior class probabilities ($P(Attack \mid X)$). Its score represents the average path length across isolation trees relative to an expected depth. Converting this raw scalar directly into a probability would be statistically misleading.

#### Q6: How do you handle categorical features like protocol_type and service?
**Answer:** In the supervised pipeline, we use scikit-learn's `ColumnTransformer` with `OrdinalEncoder(handle_unknown="use_encoded_value", unknown_value=-1)`. This ensures that if a network session contains an unseen service or flag during production, the pipeline handles it safely rather than crashing.

#### Q7: Why is Precision particularly important in enterprise cybersecurity?
**Answer:** In an Enterprise Security Operations Center (SOC), security analysts face "alert fatigue" from investigating hundreds of daily false alarms. High precision (96.7% in our project) guarantees that when an alert triggers, it represents genuine malicious activity, avoiding wasted analyst investigation time.

#### Q8: What does False Positive Rate (FPR) measure in this system?
**Answer:** False Positive Rate measures the fraction of legitimate normal traffic incorrectly classified as malicious:
$$\text{FPR} = \frac{\text{FP}}{\text{FP} + \text{TN}} = \frac{276}{276 + 9435} \approx 2.84\%$$
A low FPR ensures normal enterprise operations are not blocked.

#### Q9: What is the F1-Score and why not rely solely on Accuracy?
**Answer:** Accuracy can be deceptive on imbalanced datasets. F1-Score is the harmonic mean of Precision and Recall:
$$\text{F1} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$
It balances the trade-off between catching all attacks (recall) and ensuring that detected attacks are real (precision).

#### Q10: How does your system avoid data leakage?
**Answer:** The `StandardScaler` and `OrdinalEncoder` parameters (mean, standard deviation, categories) are fitted strictly on `KDDTrain+.txt`. The testing data and live inference sessions only transform using these frozen, saved parameters without refitting.

#### Q11: Why is SQLite in WAL mode suitable for this project?
**Answer:** Write-Ahead Logging (WAL) allows concurrent readers while a write operation is occurring. It provides ACID compliance, fast local execution without external database server configuration, and persistence across server restarts.

#### Q12: How are alerts prioritized by severity?
**Answer:** Alerts are categorized based on the Random Forest predicted probability:
- $\ge 0.90$: **Critical**
- $0.70 - 0.89$: **High**
- $0.50 - 0.69$: **Medium**
- $< 0.50$: **Low / Normal**

#### Q13: Does this project capture live raw packets like Wireshark?
**Answer:** No, and it is important to be precise: this project analyzes structured network connection telemetry (flow-level features like NetFlow/IPFIX/Zeek output). Full live packet capturing (PCAP) requires administrative kernel-level drivers (like Npcap) and packet reassembly, which can be a future extension.

#### Q14: How does the CSV batch upload work?
**Answer:** The user uploads a CSV file containing flow records. The backend validates the headers against `ALL_FEATURES`, casts numerical types, executes batch inference with `predict_batch()`, persists each record to the SQLite database, and returns aggregate statistics.

#### Q15: What are the primary future enhancements for this system?
**Answer:**
1. Integration with live packet capture engines like Zeek or Suricata.
2. Multi-class classification to specifically identify attack sub-types (e.g., Neptune, Smurf, Portsweep, Buffer Overflow).
3. Automated active response actions (e.g., blocking offending IPs via firewall API).

---

## 8. Known Limitations
- The current implementation evaluates flow-level session records rather than raw network wire packets.
- Classification is binary (Normal vs. Attack) rather than multi-class category attribution.
- Localhost demonstrator using SQLite; high-throughput enterprise scale (millions of flows/sec) would require distributed message streaming (Kafka) and time-series clustering (ClickHouse/Elasticsearch).
