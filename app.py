import json
import random
import time
import threading
import os
import logging
import numpy as np
import joblib
from queue import Queue, Empty
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import List, Optional

from flask import Flask, request, jsonify, Response, stream_with_context
from flask_cors import CORS
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler

# ─────────────────────────────────────────────────────
#  1. LOGGING & ENVIRONMENT CONFIG
# ─────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Deployment settings
PORT = int(os.environ.get("PORT", 5000))
MODEL_PATH = os.path.join(os.getcwd(), "model.pkl")

FEATURES = [
    "bytes_per_sec", "packets_per_sec", "avg_packet_size", "port_dst",
    "duration_sec", "tcp_flags_ratio", "unique_dst_ports", "unique_src_ips",
    "icmp_ratio", "payload_entropy"
]

THREAT_LABELS = {0: "normal", 1: "ddos", 2: "portscan", 3: "sqli", 4: "c2_beacon"}
THREAT_DISPLAY = {
    "normal":    {"label": "Normal Traffic", "color": "#00ff88", "severity": "none"},
    "ddos":      {"label": "DDoS Pattern",   "color": "#ff2244", "severity": "critical"},
    "portscan":  {"label": "Port Scan",      "color": "#ff8c00", "severity": "high"},
    "sqli":      {"label": "SQL Injection",  "color": "#ffd700", "severity": "medium"},
    "c2_beacon": {"label": "C2 Beaconing",   "color": "#00d4ff", "severity": "critical"},
}

THRESHOLD_BLOCK = 0.85
THRESHOLD_HONEYPOT = 0.65
THRESHOLD_RATELIMIT = 0.45

# ─────────────────────────────────────────────────────
#  2. ML THREAT DETECTOR ENGINE
# ─────────────────────────────────────────────────────


class ThreatDetector:
    def __init__(self):
        self.classifier = None
        self.anomaly_detector = None
        self.scaler = None
        self._trained = False

    def ensure_trained(self):
        if self._trained: return
        if os.path.exists(MODEL_PATH): 
            try:
                self._load()
            except Exception as e:
                logger.error(f"Failed to load model: {e}. Training new one.")
                self.train()
        else: 
            self.train()

    def train(self, X=None, y=None):
        logger.info("Starting model training session...")
        if X is None: X, y = self._generate_synthetic_data()
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)
        self.anomaly_detector = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
        self.anomaly_detector.fit(X_scaled)
        self.classifier = RandomForestClassifier(n_estimators=100, random_state=42)
        self.classifier.fit(X_scaled, y)
        self._trained = True
        self._save()
        logger.info(f"Training complete. Samples: {len(X)}")
        return {"status": "trained", "samples": len(X)}

    def score_flow(self, flow: dict) -> dict:
        self.ensure_trained()
        vec = np.array([[
            flow.get("bytes_per_sec", 0), flow.get("packets_per_sec", 0),
            flow.get("avg_packet_size", 512), flow.get("port_dst", 80) / 65535,
            flow.get("duration_sec", 1), flow.get("tcp_flags_ratio", 0.5),
            flow.get("unique_dst_ports", 1), flow.get("unique_src_ips", 1),
            flow.get("icmp_ratio", 0), flow.get("payload_entropy", 4.0)
        ]], dtype=np.float32)
        
        vec_scaled = self.scaler.transform(vec)
        raw_anomaly = self.anomaly_detector.decision_function(vec_scaled)[0]
        anomaly_score = float(np.clip(1 - (raw_anomaly + 0.5), 0, 1))
        
        proba = self.classifier.predict_proba(vec_scaled)[0]
        class_id = int(np.argmax(proba))
        class_conf = float(proba[class_id])
        
        confidence = (0.4 * anomaly_score + 0.6 * class_conf) if class_id != 0 else (0.4 * anomaly_score + 0.6 * (1 - class_conf))
        threat_type = THREAT_LABELS[class_id]
        display = THREAT_DISPLAY[threat_type]

        return {
            "threat_type": threat_type, "label": display["label"], "confidence": round(confidence, 3),
            "color": display["color"], "severity": display["severity"],
            "is_threat": class_id != 0 and confidence > 0.45, "timestamp": datetime.now(timezone.utc).isoformat()
        }

    def _generate_synthetic_data(self):
        rng = np.random.default_rng(42)
        X, y = [], []
        for _ in range(1000): # Normal
            X.append([rng.uniform(100,5000), rng.uniform(1,50), rng.uniform(64,1400), 80/65535, rng.uniform(0.1,30), 0.5, 1, 1, 0, 4.0])
            y.append(0)
        for _ in range(200): # DDoS
            X.append([rng.uniform(80000,400000), rng.uniform(2000,40000), 64, 80/65535, 1.0, 0.95, 1, 1000, 0.5, 0.5])
            y.append(1)
        return np.array(X), np.array(y)

    def _save(self): joblib.dump({"s": self.scaler, "c": self.classifier, "a": self.anomaly_detector}, MODEL_PATH)
    def _load(self):
        b = joblib.load(MODEL_PATH)
        self.scaler, self.classifier, self.anomaly_detector, self._trained = b["s"], b["c"], b["a"], True

detector = ThreatDetector()

# ─────────────────────────────────────────────────────
#  3. RESPONSE ENGINE
# ─────────────────────────────────────────────────────


@dataclass
class ResponseAction:
    action: str; src_ip: str; threat_type: str; confidence: float; severity: str; message: str; timestamp: str; css_class: str
    def to_dict(self): return asdict(self)

def respond(detection: dict, src_ip: str) -> ResponseAction:
    conf, t_type, sev, is_t = detection["confidence"], detection["threat_type"], detection["severity"], detection["is_threat"]
    now = datetime.now(timezone.utc).strftime("%H:%M:%S")
    
    if not is_t:
        return ResponseAction("none", src_ip, t_type, conf, "none", f"Normal traffic: {src_ip}", now, "ok")
    if conf >= THRESHOLD_BLOCK:
        return ResponseAction("block", src_ip, t_type, conf, sev, f"BLOCK: {src_ip} ({t_type})", now, "block")
    if conf >= THRESHOLD_HONEYPOT:
        return ResponseAction("honeypot", src_ip, t_type, conf, sev, f"HONEYPOT: {src_ip}", now, "honey")
    return ResponseAction("monitor", src_ip, t_type, conf, sev, f"Monitoring {src_ip}", now, "alert")

# ─────────────────────────────────────────────────────
#  4. FLASK API & SSE STREAMING
# ─────────────────────────────────────────────────────
app = Flask(__name__)
CORS(app) # Allows any domain to connect - refine this for real production!

_sse_subscribers: List[Queue] = []
_sse_lock = threading.Lock()

def _broadcast(event_type: str, data: dict):
    payload = f"event: {event_type}\ndata: {json.dumps(data)}\n\n"
    with _sse_lock:
        for q in _sse_subscribers[:]:
            try: q.put_nowait(payload)
            except: _sse_subscribers.remove(q)

@app.route("/")
def health_check():
    return jsonify({"status": "online", "model": "ready" if detector._trained else "training"})

@app.route("/api/stream")
def stream():
    q = Queue(maxsize=100)
    with _sse_lock: _sse_subscribers.append(q)
    def generate():
        try:
            yield "data: {\"type\":\"connected\"}\n\n"
            while True:
                try: yield q.get(timeout=25)
                except Empty: yield "event: heartbeat\ndata: {}\n\n"
        except GeneratorExit:
            with _sse_lock: 
                if q in _sse_subscribers: _sse_subscribers.remove(q)
    return Response(stream_with_context(generate()), mimetype="text/event-stream")

@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(force=True)
    src_ip = data.pop("src_ip", "0.0.0.0")
    detection = detector.score_flow(data)
    action = respond(detection, src_ip)
    res = {**detection, "src_ip": src_ip, "response": action.to_dict()}
    _broadcast("detection", res)
    return jsonify(res)

@app.route("/api/model/info")
def model_info(): 
    return jsonify({
        "status": "ready" if detector._trained else "loading",
        "features": FEATURES,
        "labels": THREAT_LABELS
    })

# ─────────────────────────────────────────────────────
#  5. BACKGROUND SIMULATOR
# ─────────────────────────────────────────────────────
def _background_simulator():
    detector.ensure_trained()
    logger.info("Background flow simulator started.")
    while True:
        try:
            time.sleep(random.uniform(5, 15)) # Slowed down for production visibility
            flow = {f: random.random() for f in FEATURES}
            src_ip = f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            detection = detector.score_flow(flow)
            action = respond(detection, src_ip)
            if detection["is_threat"] or random.random() < 0.10:
                _broadcast("detection", {**detection, "src_ip": src_ip, "response": action.to_dict()})
        except Exception as e:
            logger.error(f"Simulator error: {e}")

# Start simulation in background
threading.Thread(target=_background_simulator, daemon=True).start()

if __name__ == "__main__":
    # Ensure model is ready before serving traffic
    detector.ensure_trained()
    # In production, use: gunicorn -w 1 -b 0.0.0.0:$PORT app:app
    app.run(host="0.0.0.0", port=5001, debug=False, threaded=True)