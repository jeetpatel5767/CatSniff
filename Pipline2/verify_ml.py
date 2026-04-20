"""
verify_ml.py — Test script to verify the ML Scoring Engine.
"""

from scoring.engine import engine

def test_engine():
    print("--- TESTING ML SCORING ENGINE ---")
    
    # Test Case 1: Known Clean (Google DNS)
    clean_data = {
        'vt': {'last_analysis_stats': {'malicious': 0, 'suspicious': 0}, 'reputation': 50},
        'ipinfo': {'privacy': {'vpn': False, 'proxy': False, 'tor': False}, 'asn_type': 'isp'},
        'abuse': {'abuse_confidence_score': 0, 'total_reports': 0},
        'recon': {'ip': '8.8.8.8', 'ssl': True}
    }
    
    # Test Case 2: Suspicious (Residential Proxy/VPN)
    sus_data = {
        'vt': {'last_analysis_stats': {'malicious': 2, 'suspicious': 3}, 'reputation': 5},
        'ipinfo': {'privacy': {'vpn': True, 'proxy': True, 'tor': False}, 'asn_type': 'hosting'},
        'abuse': {'abuse_confidence_score': 45, 'total_reports': 12},
        'recon': {'ip': '1.2.3.4', 'ssl': False}
    }
    
    # Test Case 3: High Threat (Malicious C2/Botnet)
    mal_data = {
        'vt': {'last_analysis_stats': {'malicious': 45, 'suspicious': 10}, 'reputation': -80},
        'ipinfo': {'privacy': {'vpn': False, 'proxy': True, 'tor': True}, 'asn_type': 'hosting'},
        'abuse': {'abuse_confidence_score': 98, 'total_reports': 450},
        'recon': {'ip': '6.6.6.6', 'ssl': False}
    }

    # Test Case 4: Google DNS (Safelist Check)
    google_dns = {
        'vt': {'last_analysis_stats': {'malicious': 0, 'suspicious': 0}, 'reputation': 100},
        'ipinfo': {'ip': '8.8.8.8', 'privacy': {'vpn': False, 'proxy': False, 'tor': False}, 'asn_type': 'isp'},
        'abuse': {'abuse_confidence_score': 0, 'total_reports': 0},
        'recon': {'ip': '8.8.8.8'}
    }

    cases = [
        ("CLEAN TARGET", clean_data),
        ("GOOGLE DNS (SAFELIST)", google_dns),
        ("SUSPICIOUS TARGET", sus_data),
        ("MALICIOUS TARGET", mal_data)
    ]

    for name, data in cases:
        print(f"\n[!] Testing {name}...")
        result = engine.get_risk_score(data)
        print(f"    Score: {result['score']}")
        print(f"    Level: {result['level']}")
        print(f"    Method: {result['method']}")

if __name__ == "__main__":
    test_engine()
