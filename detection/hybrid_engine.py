
import joblib
import numpy as np
import os

from detection.rule_engine import RuleEngine
from preprocessing.feature_engineering import (
    flow_to_feature_vector,
    validate_flow_features,
    FEATURE_ORDER,
)

MODEL_PATH  = "models/saved/random_forest.pkl"
SCALER_PATH = "data/processed/scaler.pkl"

ATTACK_THRESHOLD     = 60
SUSPICIOUS_THRESHOLD = 30

RULE_WEIGHT = 60   # max points from rule engine
ML_WEIGHT   = 40   # max points from ML engine


class HybridEngine:
   

    def __init__(
        self,
        model_path=MODEL_PATH,
        scaler_path=SCALER_PATH
    ):
       
        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model not found at {model_path}\n"
                f"Run preprocessing/train_model.py first."
            )
        self.model = joblib.load(model_path)

        if not os.path.exists(scaler_path):
            raise FileNotFoundError(
                f"Scaler not found at {scaler_path}\n"
                f"Run preprocessing/process_dataset.py first."
            )
        self.scaler = joblib.load(scaler_path)

        self.rule_engine = RuleEngine()

        print("[*] Hybrid engine initialized.")
        print(f"    Model:  {model_path}")
        print(f"    Scaler: {scaler_path}")
        print(f"    Thresholds: ATTACK>={ATTACK_THRESHOLD} | "
              f"SUSPICIOUS>={SUSPICIOUS_THRESHOLD}")

    def _run_rule_engine(self, flow):
      
        rule_result = self.rule_engine.check(flow)
        rule_score  = RULE_WEIGHT if rule_result != "BENIGN" else 0
        return rule_result, rule_score

    def _run_ml_engine(self, flow):
       
        try:
          
            if not validate_flow_features(flow):
                return 0.0, 0.0

            feature_vector = flow_to_feature_vector(flow, self.scaler)
            attack_prob = float(
                self.model.predict_proba(feature_vector)[0][1]
            )
            ml_score = attack_prob * ML_WEIGHT
            return attack_prob, ml_score

        except Exception as e:
            print(f"[!] ML inference error: {e}")
            return 0.0, 0.0

    def _compute_verdict(self, score):
        if score >= ATTACK_THRESHOLD:
            return "ATTACK"
        elif score >= SUSPICIOUS_THRESHOLD:
            return "SUSPICIOUS"
        else:
            return "BENIGN"

    def analyze(self, flow):
       
        rule_result, rule_score = self._run_rule_engine
        attack_prob, ml_score = self._run_ml_engine(flow)

        threat_score = round(min(rule_score + ml_score, 100), 2)
        verdict      = self._compute_verdict(threat_score)

        return {
            
            "src_ip":        flow.get("src_ip",   "unknown"),
            "dst_ip":        flow.get("dst_ip",   "unknown"),
            "src_port":      flow.get("src_port", 0),
            "dst_port":      flow.get("dst_port", 0),
            "protocol":      flow.get("protocol", 0),

            "packet_count":      flow.get("packet_count", 0),
            "duration":          flow.get("duration", 0),
            "packets_per_second":flow.get("packets_per_second", 0),

            "rule_alert":    rule_result,
            "rule_score":    rule_score,
            "ml_probability":round(attack_prob, 4),
            "ml_score":      round(ml_score, 2),
            "threat_score":  threat_score,
            "verdict":       verdict,

            "needs_cti":     verdict == "ATTACK",
        }

    def is_attack(self, flow):
        return self.analyze(flow)["verdict"] == "ATTACK"
