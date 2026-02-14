"""
abuseipdb_client.py — AbuseIPDB API client for IP abuse and blacklist checking.
Uses the AbuseIPDB REST API v2 via requests.
"""

import requests
from config import ABUSEIPDB_API_KEY
from display import print_success, print_error
from typing import Dict, Any, Optional


def search_ip(ip_address: str, max_age_days: int = 90) -> Optional[Dict[str, Any]]:
    """
    Get comprehensive IP abuse information from AbuseIPDB.
    Fields: abuse score, usage type, ISP, reports count, categories, detailed reports.

    Args:
        ip_address: IP to check
        max_age_days: Age in days to check reports (default 90, max 365)
    """
    if not ABUSEIPDB_API_KEY:
        print_error("AbuseIPDB API key not found in .env")
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": max_age_days,
        "verbose": ""  # Get all available data including reports
    }

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        ip_data = data.get('data', {})

        result = {
            'ip': ip_data.get('ipAddress'),
            'is_public': ip_data.get('isPublic'),
            'ip_version': ip_data.get('ipVersion'),
            'is_whitelisted': ip_data.get('isWhitelisted'),
            'abuse_confidence_score': ip_data.get('abuseConfidenceScore'),
            'country_code': ip_data.get('countryCode'),
            'country_name': ip_data.get('countryName'),
            'usage_type': ip_data.get('usageType'),
            'isp': ip_data.get('isp'),
            'domain': ip_data.get('domain'),
            'hostnames': ip_data.get('hostnames'),
            'total_reports': ip_data.get('totalReports'),
            'num_distinct_users': ip_data.get('numDistinctUsers'),
            'last_reported_at': ip_data.get('lastReportedAt'),
            'reports': ip_data.get('reports'),  # Detailed list of abuse reports
        }

        print_success(f"AbuseIPDB data retrieved for {ip_address}")
        return result

    except requests.exceptions.RequestException as e:
        print_error(f"AbuseIPDB API error: {e}")
        return None


# ==================== CONNECTIVITY TEST ====================
def test_connectivity() -> str:
    """Test AbuseIPDB API connectivity."""
    if not ABUSEIPDB_API_KEY:
        return '❌ Key Missing'
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
        resp = requests.get(url, headers=headers, params={"ipAddress": "8.8.8.8"}, timeout=5)
        return '✅ OK' if resp.status_code == 200 else f'❌ Error ({resp.status_code})'
    except Exception:
        return '❌ Connection Failed'
