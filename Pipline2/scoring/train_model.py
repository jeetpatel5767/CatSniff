"""
train_model.py — Generates synthetic training data and trains the Random Forest model.
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestRegressor
import joblib
import os
import random

# Import feature extractor to ensure consistency
from features import get_feature_names

MODEL_PATH = os.path.join(os.path.dirname(__file__), "threat_model.pkl")

def generate_synthetic_data(n_samples=5000):
    """Generates a synthetic dataset for threat intelligence scoring."""
    data = []
    
    for _ in range(n_samples):
        # Choose a scenario: 0=Safe, 1=Suspicious, 2=Malicious
        scenario = random.choices([0, 1, 2], weights=[0.4, 0.3, 0.3])[0]
        
        if scenario == 0: # SAFE
            vt_mal = random.randint(0, 1)
            vt_sus = random.randint(0, 2)
            vt_rep = random.randint(0, 50)
            abuse_score = random.randint(0, 15)
            reports = random.randint(0, 5)
            vpn = 0 if random.random() > 0.1 else 1
            proxy = 0 if random.random() > 0.05 else 1
            tor = 0
            relay = 0
            hosting = 0 if random.random() > 0.2 else 1
            ssl = 1 if random.random() > 0.1 else 0
            resolved = 1
            
            # Base score for safe
            target_score = vt_mal * 5 + vt_sus * 2 + abuse_score * 0.5 + random.uniform(0, 10)
            
        elif scenario == 1: # SUSPICIOUS
            vt_mal = random.randint(1, 5)
            vt_sus = random.randint(2, 10)
            vt_rep = random.randint(-10, 10)
            abuse_score = random.randint(15, 60)
            reports = random.randint(5, 50)
            vpn = random.choice([0, 1])
            proxy = random.choice([0, 1])
            tor = 0 if random.random() > 0.2 else 1
            relay = random.choice([0, 1])
            hosting = random.choice([0, 1])
            ssl = random.choice([0, 1])
            resolved = 1
            
            # Base score for suspicious
            target_score = 30 + vt_mal * 7 + vt_sus * 3 + abuse_score * 0.4 + vpn * 10 + random.uniform(0, 15)
            
        else: # MALICIOUS
            vt_mal = random.randint(5, 70)
            vt_sus = random.randint(5, 30)
            vt_rep = random.randint(-100, -10)
            abuse_score = random.randint(60, 100)
            reports = random.randint(50, 1000)
            vpn = random.choice([0, 1])
            proxy = random.choice([0, 1])
            tor = random.choice([0, 1])
            relay = random.choice([0, 1])
            hosting = 1 if random.random() > 0.3 else 0
            ssl = 0 if random.random() > 0.6 else 1
            resolved = random.choice([0, 1])
            
            # Base score for malicious
            target_score = 65 + (vt_mal/2) + (abuse_score * 0.2) + tor * 15 + (1-ssl) * 10 + random.uniform(0, 10)

        # Cap score at 0-100
        target_score = max(0, min(100, target_score))
        
        data.append([
            vt_mal, vt_sus, vt_rep, abuse_score, reports, 
            vpn, proxy, tor, relay, hosting, ssl, resolved, 
            target_score
        ])

    columns = get_feature_names() + ["Target_Score"]
    return pd.DataFrame(data, columns=columns)

def train_and_save():
    """Trains the Random Forest model and saves it."""
    print("Generating synthetic security dataset...")
    df = generate_synthetic_data(6000)
    
    X = df.drop("Target_Score", axis=1)
    y = df["Target_Score"]
    
    print(f"Training Random Forest Regressor (Samples: {len(df)})...")
    model = RandomForestRegressor(
        n_estimators=100,
        max_depth=12,
        random_state=42,
        n_jobs=-1
    )
    
    model.fit(X, y)
    
    print(f"Saving model to {MODEL_PATH}...")
    joblib.dump(model, MODEL_PATH)
    print("Training complete.")

if __name__ == "__main__":
    train_and_save()
