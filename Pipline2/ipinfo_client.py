"""
ipinfo_client.py — IPInfo API client for IP geolocation and network intelligence.
Uses the IPInfo REST API via requests.
"""

import requests
from config import IPINFO_API_KEY
from display import print_success, print_error
from typing import Dict, Any, Optional


def search_ip(ip_address: str) -> Optional[Dict[str, Any]]:
    """
    Get comprehensive IP information from IPInfo.
    Fields: location, ASN, company, privacy detection, abuse contact, hosted domains.
    """
    if not IPINFO_API_KEY:
        print_error("IPInfo API key not found in .env")
        return None

    url = f"https://ipinfo.io/{ip_address}?token={IPINFO_API_KEY}"

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()

        result = {
            'ip': data.get('ip'),
            'hostname': data.get('hostname'),
            'city': data.get('city'),
            'region': data.get('region'),
            'country': data.get('country'),
            'loc': data.get('loc'),  # Latitude,Longitude
            'org': data.get('org'),  # ASN + Organization name
            'postal': data.get('postal'),
            'timezone': data.get('timezone'),
            # ASN details (if available on plan)
            'asn': data.get('asn', {}).get('asn') if isinstance(data.get('asn'), dict) else None,
            'asn_name': data.get('asn', {}).get('name') if isinstance(data.get('asn'), dict) else None,
            'asn_domain': data.get('asn', {}).get('domain') if isinstance(data.get('asn'), dict) else None,
            'asn_route': data.get('asn', {}).get('route') if isinstance(data.get('asn'), dict) else None,
            'asn_type': data.get('asn', {}).get('type') if isinstance(data.get('asn'), dict) else None,
            # Company details
            'company': data.get('company', {}).get('name') if isinstance(data.get('company'), dict) else None,
            'company_domain': data.get('company', {}).get('domain') if isinstance(data.get('company'), dict) else None,
            'company_type': data.get('company', {}).get('type') if isinstance(data.get('company'), dict) else None,
            # Privacy flags (VPN, proxy, tor, relay, hosting)
            'privacy': data.get('privacy'),
            # Abuse contact info
            'abuse': data.get('abuse'),
            # Domains hosted on this IP
            'domains': data.get('domains'),
        }

        print_success(f"IPInfo data retrieved for {ip_address}")
        return result

    except requests.exceptions.RequestException as e:
        print_error(f"IPInfo API error: {e}")
        return None


# ==================== CONNECTIVITY TEST ====================
def test_connectivity() -> str:
    """Test IPInfo API connectivity."""
    if not IPINFO_API_KEY:
        return '❌ Key Missing'
    try:
        url = f"https://ipinfo.io/8.8.8.8?token={IPINFO_API_KEY}"
        resp = requests.get(url, timeout=5)
        return '✅ OK' if resp.status_code == 200 else f'❌ Error ({resp.status_code})'
    except Exception:
        return '❌ Connection Failed'
