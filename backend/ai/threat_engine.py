"""
backend/ai/threat_engine.py
Isolation Forest anomaly detection + multi-factor risk scoring.
"""
import logging
import numpy as np
from collections import defaultdict, deque
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

logger = logging.getLogger(__name__)


# ── IP Behaviour Tracker ───────────────────────────────────

class IPTracker:
    """Sliding-window per-IP behaviour store (in-memory)."""

    def __init__(self, window_seconds: int = 300):
        self.window   = window_seconds
        self._events: dict[str, deque] = defaultdict(deque)  # ip -> deque of timestamps
        self._fails:  dict[str, int]   = defaultdict(int)
        self._ports:  dict[str, set]   = defaultdict(set)

    def record(self, ip: str, failed: bool = False, port: int | None = None) -> dict:
        now = datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window)
        dq = self._events[ip]
        dq.append(now)
        # evict old
        while dq and dq[0] < cutoff:
            dq.popleft()

        if failed:
            self._fails[ip] += 1
        if port:
            self._ports[ip].add(port)

        return {
            "request_count": len(dq),
            "fail_count":    self._fails[ip],
            "unique_ports":  len(self._ports[ip]),
        }

    def reset_fails(self, ip: str) -> None:
        self._fails[ip] = 0


# ── Isolation Forest Model ─────────────────────────────────

class AnomalyDetector:
    """
    Online Isolation Forest.
    Features: [request_rate, fail_rate, unique_ports, hour_of_day, abuse_score]
    """

    FEATURE_COUNT = 5
    MIN_SAMPLES   = 50   # train only after enough data

    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self._model  = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        self._scaler  = StandardScaler()
        self._buffer: list[list[float]] = []
        self._trained = False

    def _build_features(self, behaviour: dict, abuse_score: int) -> list[float]:
        rc = behaviour.get("request_count", 0)
        fc = behaviour.get("fail_count",    0)
        up = behaviour.get("unique_ports",  0)
        hour = datetime.utcnow().hour
        fail_rate = fc / max(rc, 1)
        return [float(rc), fail_rate, float(up), float(hour), float(abuse_score)]

    def train(self, samples: list[list[float]]) -> None:
        if len(samples) < self.MIN_SAMPLES:
            return
        X = np.array(samples)
        X_scaled = self._scaler.fit_transform(X)
        self._model.fit(X_scaled)
        self._trained = True
        logger.info("IsolationForest retrained on %d samples", len(samples))

    def predict(self, behaviour: dict, abuse_score: int) -> tuple[bool, float]:
        """
        Returns (is_anomaly, anomaly_score 0-1).
        anomaly_score 1 = most anomalous.
        """
        features = self._build_features(behaviour, abuse_score)
        self._buffer.append(features)

        # retrain every 200 new samples
        if len(self._buffer) % 200 == 0:
            self.train(self._buffer[-2000:])  # keep last 2000

        if not self._trained:
            # heuristic fallback before model is ready
            rc, fail_rate, up = features[0], features[1], features[2]
            score = min(1.0, (rc / 100) * 0.4 + fail_rate * 0.4 + (up / 20) * 0.2)
            return score > 0.6, score

        X = np.array([features])
        X_scaled = self._scaler.transform(X)
        raw_score = self._model.decision_function(X_scaled)[0]   # negative = anomalous
        prediction = self._model.predict(X_scaled)[0]            # -1 = anomaly

        # normalise to 0-1 (higher = more anomalous)
        norm_score = float(np.clip(1 - (raw_score + 0.5), 0, 1))
        return prediction == -1, norm_score


# ── Risk Scorer ────────────────────────────────────────────

class RiskScorer:
    """
    Combines multiple signals into a 0-100 risk score
    and maps it to a threat classification.
    """

    ATTACK_WEIGHTS = {
        "brute_force":      35,
        "port_scan":        25,
        "sql_injection":    30,
        "ddos":             30,
        "malware":          40,
        "unauthorized":     20,
        "suspicious":       15,
        "normal":            0,
    }

    HIGH_RISK_COUNTRIES = {
        "RU", "CN", "KP", "IR", "NG", "BR", "UA", "RO"
    }

    def compute(
        self,
        behaviour:    dict,
        abuse_score:  int,
        anomaly_score: float,
        attack_type:  str,
        country_code: str = "",
        is_blocked:   bool = False,
    ) -> tuple[int, str]:
        """
        Returns (risk_score 0-100, risk_level).
        """
        score = 0

        # 1. Anomaly signal (0-30 pts)
        score += int(anomaly_score * 30)

        # 2. Abuse / reputation (0-20 pts)
        score += int(min(abuse_score, 100) * 0.20)

        # 3. Attack type weight (0-40 pts)
        score += self.ATTACK_WEIGHTS.get(attack_type, 10)

        # 4. Behaviour signals (0-20 pts)
        rc = behaviour.get("request_count", 0)
        fc = behaviour.get("fail_count",    0)
        up = behaviour.get("unique_ports",  0)
        score += min(int(rc / 10), 8)
        score += min(fc * 2, 8)
        score += min(up, 4)

        # 5. Geo risk bonus (+5)
        if country_code.upper() in self.HIGH_RISK_COUNTRIES:
            score += 5

        # 6. Already blocked (+10)
        if is_blocked:
            score += 10

        score = min(score, 100)

        if score >= 80:
            level = "critical"
        elif score >= 60:
            level = "high"
        elif score >= 35:
            level = "medium"
        else:
            level = "low"

        return score, level


# ── Attack Classifier ──────────────────────────────────────

class AttackClassifier:
    """Rule-based attack type classifier from log message."""

    PATTERNS = [
        ("brute_force",   ["brute", "brute-force", "failed login", "invalid password",
                           "authentication failure", "too many attempts"]),
        ("port_scan",     ["port scan", "nmap", "masscan", "syn flood", "port sweep"]),
        ("sql_injection", ["sql injection", "' or ", "union select", "drop table",
                           "1=1", "xp_cmdshell"]),
        ("ddos",          ["ddos", "flood", "amplification", "reflection attack"]),
        ("malware",       ["malware", "trojan", "ransomware", "backdoor", "c2",
                           "command and control", "botnet"]),
        ("unauthorized",  ["unauthorized", "forbidden", "403", "access denied",
                           "privilege escalation"]),
        ("suspicious",    ["suspicious", "anomaly", "unusual", "unknown"]),
    ]

    def classify(self, message: str) -> str:
        msg = message.lower()
        for attack_type, keywords in self.PATTERNS:
            if any(kw in msg for kw in keywords):
                return attack_type
        return "normal"


# ── Singleton instances ────────────────────────────────────
ip_tracker   = IPTracker(window_seconds=300)
anomaly_det  = AnomalyDetector(contamination=0.1)
risk_scorer  = RiskScorer()
classifier   = AttackClassifier()
