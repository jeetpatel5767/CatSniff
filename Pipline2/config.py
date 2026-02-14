"""
config.py — Centralized configuration, API key loading, input type detection, and utilities.
"""

import os
import re
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# ==================== API KEYS ====================
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
IPINFO_API_KEY = os.getenv('IPINFO_API_KEY', '')
ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')


# ==================== INPUT TYPE DETECTION ====================
def is_ip_address(value: str) -> bool:
    """Check if a string is a valid IPv4 address."""
    pattern = r'^\d{1,3}(\.\d{1,3}){3}$'
    if re.match(pattern, value):
        parts = value.split('.')
        return all(0 <= int(p) <= 255 for p in parts)
    return False


def is_file_hash(value: str) -> bool:
    """Check if a string looks like an MD5 / SHA1 / SHA256 hash."""
    value = value.strip().lower()
    return bool(re.match(r'^[a-f0-9]{32}$', value) or   # MD5
                re.match(r'^[a-f0-9]{40}$', value) or   # SHA1
                re.match(r'^[a-f0-9]{64}$', value))      # SHA256


def is_url(value: str) -> bool:
    """Check if a string looks like a URL (starts with http/https or hxxp/hxxps)."""
    v = value.lower()
    return v.startswith('http://') or v.startswith('https://') or \
           v.startswith('hxxp://') or v.startswith('hxxps://')


def refang(indicator: str) -> str:
    """Convert defanged indicators back to their original form.
    e.g., ncloudup[.]com -> ncloudup.com, hxxps://example[.]com -> https://example.com
    """
    indicator = indicator.replace('[.]', '.').replace('(.)', '.')
    indicator = indicator.replace('[:]', ':').replace('(:)', ':')
    indicator = indicator.replace('hxxps://', 'https://').replace('hxxp://', 'http://')
    return indicator


def detect_input_type(user_input: str) -> str:
    """Detect the type of user input and return one of: 'ip', 'hash', 'url', 'domain'."""
    cleaned = refang(user_input.strip())

    if is_ip_address(cleaned):
        return 'ip'
    if is_file_hash(cleaned):
        return 'hash'
    if is_url(cleaned):
        return 'url'
    return 'domain'


def clean_domain(value: str) -> str:
    """Extract clean domain from a URL or raw domain input."""
    value = refang(value.strip())
    value = re.sub(r'^https?://', '', value)
    value = value.split('/')[0]
    value = value.split('?')[0]
    return value.lower()
