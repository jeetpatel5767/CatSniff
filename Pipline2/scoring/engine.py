"""
engine.py — Live inference engine for CatSniff Risk Scoring.
Loads the trained Random Forest model and predicts scores for live data.
"""

import joblib
import os
import numpy as np
from .features import extract_features

MODEL_PATH = os.path.join(os.path.dirname(__file__), "threat_model.pkl")

class ScoringEngine:
    def __init__(self):
        self.model = None
        self._load_model()

    def _load_model(self):
        """Loads the pre-trained ML model."""
        if os.path.exists(MODEL_PATH):
            try:
                self.model = joblib.load(MODEL_PATH)
            except Exception:
                self.model = None
        else:
            self.model = None

    def get_risk_score(self, aggregated_data: dict) -> dict:
        """
        Calculates a risk score (0-100) based on live scan data.
        Returns a dictionary with score, level, and metadata.
        """
        import pandas as pd
        from .features import get_feature_names, is_safelisted
        
        # 1. Check Safelist first
        if is_safelisted(aggregated_data):
            return {
                "score": 0.0,
                "level": "CLEAN / WHITELISTED",
                "color": "GREEN",
                "method": "Trusted Infrastructure (Safelisted)"
            }

        features = extract_features(aggregated_data)
        
        if self.model:
            # Use ML Model
            input_df = pd.DataFrame([features], columns=get_feature_names())
            score = float(self.model.predict(input_df)[0])
            method = "Machine Learning (Random Forest)"
        else:
            # Fallback to Heuristic if model is missing
            score = self._heuristic_fallback(features)
            method = "Rule-based Heuristic (Model Missing)"

        # Cap and Round
        score = round(max(0, min(100, score)), 1)
        
        # Determine Level
        if score >= 75:
            level = "CRITICAL / MALICIOUS"
            color = "RED"
        elif score >= 40:
            level = "SUSPICIOUS"
            color = "YELLOW"
        elif score >= 15:
            level = "POTENTIALLY UNWANTED"
            color = "CYAN"
        else:
            level = "CLEAN / SAFE"
            color = "GREEN"

        return {
            "score": score,
            "level": level,
            "color": color,
            "method": method
        }

    def _heuristic_fallback(self, features: list) -> float:
        """Simple fallback scoring if ML model isn't available."""
        # Feature indices match features.py
        vt_mal = features[0]
        vt_sus = features[1]
        abuse_score = features[3]
        has_tor = features[7]
        
        score = (vt_mal * 10) + (vt_sus * 3) + (abuse_score * 0.5) + (has_tor * 20)
        return score

# Singleton instance
engine = ScoringEngine()
