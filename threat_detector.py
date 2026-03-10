"""
SENTINEL — ML Threat Detection Engine
Uses a scikit-learn ensemble: IsolationForest (anomaly) + RandomForest (classification)
Works out-of-the-box with synthetic data. Swap in real NetFlow features easily.
"""

import numpy as np
import joblib
import os
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

# ─────────────────────────────────────────────────────
#  FEATURE DEFINITIONS
#  These 10 features map directly to NetFlow fields.
#  For real data, extract them from your packet captures
#  or CSV logs before calling score_flow().
# ─────────────────────────────────────────────────────
FEATURES = [
    "bytes_per_sec",       # Throughput
    "packets_per_sec",     # Packet rate
    "avg_packet_size",     # Average payload size
    "port_dst",            # Destination port (normalised 0-1)
    "duration_sec",        # Flow duration
    "tcp_flags_ratio",     # SYN/ACK ratio
    "unique_dst_ports",    # Number of distinct destination ports
    "unique_src_ips",      # Source IP diversity (spread)
    "icmp_ratio",          # % of ICMP packets
    "payload_entropy",     # Shannon entropy of payload
]

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")


# ─────────────────────────────────────────────────────
#  SYNTHETIC TRAINING DATA
#  In production, replace this with real labelled flows.
#  Format: each row = one network flow, last col = label
#  Labels: 0=normal, 1=ddos, 2=portscan, 3=sqli, 4=c2
# ─────────────────────────────────────────────────────
def _generate_training_data(n=3000):
    rng = np.random.default_rng(42)
    X, y = [], []

    # Normal traffic
    for _ in range(n // 2):
        X.append([
            rng.uniform(100, 5000),    # bytes/s
            rng.uniform(1, 50),        # pkt/s
            rng.uniform(64, 1400),     # avg pkt size
            rng.choice([80, 443, 22, 25, 53]) / 65535,  # port
            rng.uniform(0.1, 30),      # duration
            rng.uniform(0.4, 0.8),     # tcp flags
            rng.integers(1, 4),        # unique dst ports
            rng.integers(1, 5),        # unique src IPs
            rng.uniform(0, 0.05),      # icmp ratio
            rng.uniform(3.5, 5.5),     # payload entropy (normal)
        ])
        y.append(0)

    # DDoS
    for _ in range(n // 8):
        X.append([
            rng.uniform(50000, 500000),
            rng.uniform(1000, 50000),
            rng.uniform(40, 80),
            rng.uniform(0, 1),
            rng.uniform(0, 2),
            rng.uniform(0.9, 1.0),
            rng.integers(1, 3),
            rng.integers(100, 5000),
            rng.uniform(0.3, 0.9),
            rng.uniform(0, 1.5),
        ])
        y.append(1)

    # Port Scan
    for _ in range(n // 8):
        X.append([
            rng.uniform(10, 500),
            rng.uniform(5, 100),
            rng.uniform(40, 60),
            rng.uniform(0, 1),
            rng.uniform(0, 0.5),
            rng.uniform(0.8, 1.0),
            rng.integers(50, 1000),
            rng.integers(1, 3),
            rng.uniform(0, 0.1),
            rng.uniform(0, 2.0),
        ])
        y.append(2)

    # SQL Injection (HTTP anomalies)
    for _ in range(n // 8):
        X.append([
            rng.uniform(500, 8000),
            rng.uniform(1, 20),
            rng.uniform(800, 1400),
            443 / 65535,
            rng.uniform(0.5, 10),
            rng.uniform(0.4, 0.6),
            rng.integers(1, 3),
            rng.integers(1, 5),
            rng.uniform(0, 0.02),
            rng.uniform(6.5, 8.0),   # high entropy (encoded payload)
        ])
        y.append(3)

    # C2 Beaconing
    for _ in range(n // 8):
        X.append([
            rng.uniform(50, 800),
            rng.uniform(1, 10),
            rng.uniform(100, 400),
            rng.uniform(0, 1),
            rng.uniform(25, 90),     # long periodic connections
            rng.uniform(0.5, 0.7),
            rng.integers(1, 3),
            rng.integers(1, 2),
            rng.uniform(0, 0.02),
            rng.uniform(4.0, 6.0),
        ])
        y.append(4)

    return np.array(X, dtype=np.float32), np.array(y)


THREAT_LABELS = {
    0: "normal",
    1: "ddos",
    2: "portscan",
    3: "sqli",
    4: "c2_beacon",
}

THREAT_DISPLAY = {
    "normal":    {"label": "Normal Traffic",     "color": "#00ff88", "severity": "none"},
    "ddos":      {"label": "DDoS Pattern",        "color": "#ff2244", "severity": "critical"},
    "portscan":  {"label": "Port Scan",           "color": "#ff8c00", "severity": "high"},
    "sqli":      {"label": "SQL Injection",       "color": "#ffd700", "severity": "medium"},
    "c2_beacon": {"label": "C2 Beaconing",        "color": "#00d4ff", "severity": "critical"},
}


class ThreatDetector:
    """
    Ensemble detector:
      1. IsolationForest  →  anomaly score (unsupervised)
      2. RandomForest     →  threat classification (supervised)
    Final confidence = blend of both scores.
    """

    def __init__(self):
        self.classifier = None
        self.anomaly_detector = None
        self.scaler = None
        self._trained = False

    # ── PUBLIC API ─────────────────────────────────

    def ensure_trained(self):
        """Load from disk or train fresh."""
        if self._trained:
            return
        if os.path.exists(MODEL_PATH):
            self._load()
        else:
            self.train()

    def train(self, X=None, y=None):
        """Train on provided data, or generate synthetic data."""
        if X is None:
            X, y = _generate_training_data()

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.anomaly_detector = IsolationForest(
            n_estimators=150,
            contamination=0.12,
            random_state=42,
            n_jobs=-1,
        )
        self.anomaly_detector.fit(X_scaled)

        self.classifier = RandomForestClassifier(
            n_estimators=200,
            max_depth=12,
            min_samples_leaf=4,
            random_state=42,
            n_jobs=-1,
        )
        self.classifier.fit(X_scaled, y)

        self._trained = True
        self._save()
        return {"status": "trained", "samples": len(X)}

    def score_flow(self, flow: dict) -> dict:
        """
        Score a single network flow dict.
        Expected keys: bytes_per_sec, packets_per_sec, avg_packet_size,
                       port_dst, duration_sec, tcp_flags_ratio,
                       unique_dst_ports, unique_src_ips, icmp_ratio, payload_entropy
        Returns classification result with confidence scores.
        """
        self.ensure_trained()

        vec = np.array([[
            flow.get("bytes_per_sec", 0),
            flow.get("packets_per_sec", 0),
            flow.get("avg_packet_size", 512),
            flow.get("port_dst", 80) / 65535,
            flow.get("duration_sec", 1),
            flow.get("tcp_flags_ratio", 0.5),
            flow.get("unique_dst_ports", 1),
            flow.get("unique_src_ips", 1),
            flow.get("icmp_ratio", 0),
            flow.get("payload_entropy", 4.0),
        ]], dtype=np.float32)

        vec_scaled = self.scaler.transform(vec)

        # Anomaly score: -1 = anomaly, 1 = normal → convert to 0-1
        raw_anomaly = self.anomaly_detector.decision_function(vec_scaled)[0]
        anomaly_score = float(np.clip(1 - (raw_anomaly + 0.5), 0, 1))

        # Classification probabilities
        proba = self.classifier.predict_proba(vec_scaled)[0]
        class_id = int(np.argmax(proba))
        class_confidence = float(proba[class_id])

        # Blend: 40% anomaly + 60% classifier
        if class_id == 0:
            confidence = 0.4 * anomaly_score + 0.6 * (1 - class_confidence)
        else:
            confidence = 0.4 * anomaly_score + 0.6 * class_confidence

        threat_type = THREAT_LABELS[class_id]
        display = THREAT_DISPLAY[threat_type]

        return {
            "threat_type": threat_type,
            "label": display["label"],
            "confidence": round(confidence, 3),
            "color": display["color"],
            "severity": display["severity"],
            "is_threat": class_id != 0 and confidence > 0.45,
            "anomaly_score": round(anomaly_score, 3),
            "class_scores": {
                THREAT_LABELS[i]: round(float(p), 3)
                for i, p in enumerate(proba)
            },
        }

    def score_batch(self, flows: list) -> list:
        """Score multiple flows at once (more efficient)."""
        return [self.score_flow(f) for f in flows]

    def model_info(self) -> dict:
        self.ensure_trained()
        return {
            "status": "ready",
            "algorithms": ["IsolationForest", "RandomForestClassifier"],
            "n_features": len(FEATURES),
            "features": FEATURES,
            "threat_types": list(THREAT_LABELS.values()),
            "model_path": MODEL_PATH,
        }

    # ── INTERNAL ───────────────────────────────────

    def _save(self):
        joblib.dump({
            "scaler": self.scaler,
            "classifier": self.classifier,
            "anomaly_detector": self.anomaly_detector,
        }, MODEL_PATH)

    def _load(self):
        bundle = joblib.load(MODEL_PATH)
        self.scaler = bundle["scaler"]
        self.classifier = bundle["classifier"]
        self.anomaly_detector = bundle["anomaly_detector"]
        self._trained = True


# Singleton — import this anywhere
detector = ThreatDetector()
