"""
features.py — Extracts numerical features and handles safelisting for CatSniff.
"""

from typing import Dict, Any, List

# KNOWN SAFE INFRASTRUCTURE (Safelisting)
SAFELIST_IPS = [
    "8.8.8.8", "8.8.4.4",      # Google DNS
    "1.1.1.1", "1.0.0.1",      # Cloudflare
    "9.9.9.9",                 # Quad9
    "208.67.222.222",          # OpenDNS
    "127.0.0.1", "0.0.0.0"     # Localhost
]

SAFELIST_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "cloudflare.com", 
    "amazon.com", "github.com", "google.co.in", "googlevideo.com"
]

def is_safelisted(data: Dict[str, Any]) -> bool:
    """Checks if the target is in the known safe list."""
    # Check IP
    ip = data.get('recon', {}).get('ip') or data.get('ipinfo', {}).get('ip')
    if ip in SAFELIST_IPS:
        return True
        
    # Check Domain
    domain = data.get('vt', {}).get('domain') or data.get('recon', {}).get('domain')
    if domain:
        domain = domain.lower()
        if any(sd in domain for sd in SAFELIST_DOMAINS):
            return True
            
    return False

def extract_features(data: Dict[str, Any]) -> List[float]:
    """
    Converts aggregated scan results into a numerical feature vector.
    """
    # 1. VirusTotal Features
    vt = data.get('vt', {}) or {}
    vt_stats = vt.get('last_analysis_stats', {}) or {}
    
    vt_malicious = float(vt_stats.get('malicious', 0))
    vt_suspicious = float(vt_stats.get('suspicious', 0))
    vt_reputation = float(vt.get('reputation', 0))
    
    # 2. AbuseIPDB Features
    abuse = data.get('abuse', {}) or {}
    abuse_score = float(abuse.get('abuse_confidence_score', 0))
    total_reports = float(abuse.get('total_reports', 0))
    
    # 3. IPInfo Privacy Features
    ipinfo = data.get('ipinfo', {}) or {}
    privacy = ipinfo.get('privacy', {}) or {}
    
    has_vpn = 1.0 if privacy.get('vpn') else 0.0
    has_proxy = 1.0 if privacy.get('proxy') else 0.0
    has_tor = 1.0 if privacy.get('tor') else 0.0
    has_relay = 1.0 if privacy.get('relay') else 0.0
    
    # ASN type
    is_hosting = 0.0
    asn_type = ipinfo.get('asn_type')
    if asn_type == 'hosting':
        is_hosting = 1.0
    
    # 4. Domain Recon Features (Context Aware)
    recon = data.get('recon', {}) or {}
    
    # Don't penalize IP-only scans for missing SSL
    is_domain_scan = True if recon.get('domain') else False
    
    if is_domain_scan:
        has_ssl = 1.0 if recon.get('ssl') else 0.0
    else:
        # If it's an IP scan, missing SSL is neutral (0.5) instead of malicious (0.0)
        has_ssl = 0.5
        
    is_resolved = 1.0 if recon.get('ip') else 0.0
    
    # Feature vector
    feature_vector = [
        vt_malicious,    # 0
        vt_suspicious,   # 1
        vt_reputation,   # 2
        abuse_score,     # 3
        total_reports,   # 4
        has_vpn,         # 5
        has_proxy,       # 6
        has_tor,         # 7
        has_relay,       # 8
        is_hosting,      # 9
        has_ssl,         # 10
        is_resolved      # 11
    ]
    
    return feature_vector

def get_feature_names() -> List[str]:
    return [
        "VT Malicious", "VT Suspicious", "VT Reputation",
        "Abuse Score", "Total Reports", "VPN Flag",
        "Proxy Flag", "Tor Flag", "Relay Flag",
        "Hosting ASN", "SSL Support", "DNS Resolved"
    ]
