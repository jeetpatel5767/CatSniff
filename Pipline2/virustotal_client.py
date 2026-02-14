"""
virustotal_client.py — VirusTotal integration using the virustotal-python library.
Extracts maximum data from IP, domain, URL, and file hash endpoints + relationships.
"""

import virustotal_python
from config import VIRUSTOTAL_API_KEY
from display import print_success, print_error, print_warning
from typing import Dict, Any, Optional, List
from base64 import urlsafe_b64encode


def _get_client():
    """Create and return a VirusTotal client instance."""
    if not VIRUSTOTAL_API_KEY:
        print_error("VirusTotal API key not found in .env")
        return None
    return virustotal_python.Virustotal(API_KEY=VIRUSTOTAL_API_KEY, TIMEOUT=15.0)


# ==================== IP ADDRESS ====================
def search_ip(ip_address: str) -> Optional[Dict[str, Any]]:
    """
    Get comprehensive IP information from VirusTotal.
    Endpoint: ip_addresses/{ip}
    """
    client = _get_client()
    if not client:
        return None

    try:
        with virustotal_python.Virustotal(API_KEY=VIRUSTOTAL_API_KEY, TIMEOUT=15.0) as vtotal:
            resp = vtotal.request(f"ip_addresses/{ip_address}")
            data = resp.data.get('attributes', resp.data)

            result = {
                'ip': ip_address,
                'country': data.get('country'),
                'continent': data.get('continent'),
                'network': data.get('network'),
                'asn': data.get('asn'),
                'as_owner': data.get('as_owner'),
                'regional_internet_registry': data.get('regional_internet_registry'),
                'whois': data.get('whois'),
                'whois_date': data.get('whois_date'),
                'reputation': data.get('reputation'),
                'last_analysis_stats': data.get('last_analysis_stats'),
                'last_analysis_date': data.get('last_analysis_date'),
                'last_modification_date': data.get('last_modification_date'),
                'total_votes': data.get('total_votes'),
                'tags': data.get('tags'),
                'jarm': data.get('jarm'),
            }

            print_success(f"VirusTotal IP data retrieved for {ip_address}")
            return result

    except virustotal_python.VirustotalError as e:
        print_error(f"VirusTotal API error: {e}")
        return None
    except Exception as e:
        print_error(f"VirusTotal unexpected error: {e}")
        return None


def get_ip_resolutions(ip_address: str) -> Optional[List[Dict]]:
    """
    Get domains that have resolved to this IP.
    Relationship: ip_addresses/{ip}/resolutions
    """
    try:
        with virustotal_python.Virustotal(API_KEY=VIRUSTOTAL_API_KEY, TIMEOUT=15.0) as vtotal:
            resp = vtotal.request(f"ip_addresses/{ip_address}/resolutions", params={"limit": 10})
            resolutions = []
            for item in resp.data:
                attrs = item.get('attributes', {})
                resolutions.append({
                    'host_name': attrs.get('host_name'),
                    'ip_address': attrs.get('ip_address'),
                    'date': attrs.get('date'),
                    'resolver': attrs.get('resolver'),
                })
            return resolutions
    except Exception:
        return None


def get_ip_communicating_files(ip_address: str) -> Optional[List[Dict]]:
    """
    Get files that communicate with this IP.
    Relationship: ip_addresses/{ip}/communicating_files
    """
    try:
        with virustotal_python.Virustotal(API_KEY=VIRUSTOTAL_API_KEY, TIMEOUT=15.0) as vtotal:
            resp = vtotal.request(f"ip_addresses/{ip_address}/communicating_files", params={"limit": 5})
            files = []
            for item in resp.data:
                attrs = item.get('attributes', {})
                files.append({
                    'sha256': attrs.get('sha256'),
                    'meaningful_name': attrs.get('meaningful_name'),
                    'type_description': attrs.get('type_description'),
                    'reputation': attrs.get('reputation'),
                    'last_analysis_stats': attrs.get('last_analysis_stats'),
                })
            return files
    except Exception:
        return None


# ==================== DOMAIN ====================
def search_domain(domain: str) -> Optional[Dict[str, Any]]:
    """
    Get comprehensive domain information from VirusTotal.
    Endpoint: domains/{domain}
    """
    try:
        with virustotal_python.Virustotal(API_KEY=VIRUSTOTAL_API_KEY, TIMEOUT=15.0) as vtotal:
            resp = vtotal.request(f"domains/{domain}")
            data = resp.data.get('attributes', resp.data)

            result = {
                'domain': domain,
                'categories': data.get('categories'),
                'creation_date': data.get('creation_date'),
                'last_update_date': data.get('last_update_date'),
                'last_dns_records': data.get('last_dns_records'),
                'last_dns_records_date': data.get('last_dns_records_date'),
                'last_https_certificate': data.get('last_https_certificate'),
                'last_https_certificate_date': data.get('last_https_certificate_date'),
                'popularity_ranks': data.get('popularity_ranks'),
                'registrar': data.get('registrar'),
                'reputation': data.get('reputation'),
                'last_analysis_stats': data.get('last_analysis_stats'),
                'last_analysis_date': data.get('last_analysis_date'),
                'whois': data.get('whois'),
                'whois_date': data.get('whois_date'),
                'tags': data.get('tags'),
                'total_votes': data.get('total_votes'),
                'last_modification_date': data.get('last_modification_date'),
                'jarm': data.get('jarm'),
                'last_analysis_results': data.get('last_analysis_results'),
            }

            print_success(f"VirusTotal domain data retrieved for {domain}")
            return result

    except virustotal_python.VirustotalError as e:
        print_error(f"VirusTotal API error for domain {domain}: {e}")
        return None
    except Exception as e:
        print_error(f"VirusTotal unexpected error: {e}")
        return None


def get_domain_resolutions(domain: str) -> Optional[List[Dict]]:
    """
    Get IPs that this domain has resolved to.
    Relationship: domains/{domain}/resolutions
    Returns list of resolved IPs — used to cascade into IPInfo/AbuseIPDB.
    """
    try:
        with virustotal_python.Virustotal(API_KEY=VIRUSTOTAL_API_KEY, TIMEOUT=15.0) as vtotal:
            resp = vtotal.request(f"domains/{domain}/resolutions", params={"limit": 10})
            resolutions = []
            for item in resp.data:
                attrs = item.get('attributes', {})
                resolutions.append({
                    'ip_address': attrs.get('ip_address'),
                    'host_name': attrs.get('host_name'),
                    'date': attrs.get('date'),
                    'resolver': attrs.get('resolver'),
                })
            return resolutions
    except Exception:
        return None


def get_domain_subdomains(domain: str) -> Optional[List[str]]:
    """
    Get subdomains of a domain.
    Relationship: domains/{domain}/subdomains
    """
    try:
        with virustotal_python.Virustotal(API_KEY=VIRUSTOTAL_API_KEY, TIMEOUT=15.0) as vtotal:
            resp = vtotal.request(f"domains/{domain}/subdomains", params={"limit": 20})
            subdomains = []
            for item in resp.data:
                sub_id = item.get('id', '')
                if sub_id:
                    subdomains.append(sub_id)
            return subdomains
    except Exception:
        return None


def get_domain_communicating_files(domain: str) -> Optional[List[Dict]]:
    """
    Get files that communicate with this domain.
    Relationship: domains/{domain}/communicating_files
    """
    try:
        with virustotal_python.Virustotal(API_KEY=VIRUSTOTAL_API_KEY, TIMEOUT=15.0) as vtotal:
            resp = vtotal.request(f"domains/{domain}/communicating_files", params={"limit": 5})
            files = []
            for item in resp.data:
                attrs = item.get('attributes', {})
                files.append({
                    'sha256': attrs.get('sha256'),
                    'meaningful_name': attrs.get('meaningful_name'),
                    'type_description': attrs.get('type_description'),
                    'reputation': attrs.get('reputation'),
                    'last_analysis_stats': attrs.get('last_analysis_stats'),
                })
            return files
    except Exception:
        return None


# ==================== URL ====================
def search_url(url: str) -> Optional[Dict[str, Any]]:
    """
    Submit a URL for analysis and retrieve the report.
    Endpoint: POST urls + GET urls/{url_id}
    """
    try:
        with virustotal_python.Virustotal(API_KEY=VIRUSTOTAL_API_KEY, TIMEOUT=15.0) as vtotal:
            # Submit URL for scanning
            try:
                vtotal.request("urls", data={"url": url}, method="POST")
            except Exception:
                pass  # URL may already be in VT database

            # Encode URL to get the ID
            url_id = urlsafe_b64encode(url.encode()).decode().strip("=")

            # Get the report
            resp = vtotal.request(f"urls/{url_id}")
            data = resp.data.get('attributes', resp.data)

            result = {
                'url': data.get('url'),
                'final_url': data.get('last_final_url'),
                'title': data.get('title'),
                'last_http_response_code': data.get('last_http_response_code'),
                'last_http_response_content_length': data.get('last_http_response_content_length'),
                'reputation': data.get('reputation'),
                'last_analysis_stats': data.get('last_analysis_stats'),
                'last_analysis_date': data.get('last_analysis_date'),
                'categories': data.get('categories'),
                'tags': data.get('tags'),
                'total_votes': data.get('total_votes'),
                'last_analysis_results': data.get('last_analysis_results'),
                'trackers': data.get('trackers'),
                'outgoing_links': data.get('outgoing_links'),
            }

            print_success(f"VirusTotal URL data retrieved")
            return result

    except virustotal_python.VirustotalError as e:
        print_error(f"VirusTotal API error for URL: {e}")
        return None
    except Exception as e:
        print_error(f"VirusTotal unexpected error: {e}")
        return None


# ==================== FILE HASH ====================
def search_file_hash(file_hash: str) -> Optional[Dict[str, Any]]:
    """
    Get comprehensive file hash information from VirusTotal.
    Endpoint: files/{hash}
    """
    try:
        with virustotal_python.Virustotal(API_KEY=VIRUSTOTAL_API_KEY, TIMEOUT=15.0) as vtotal:
            resp = vtotal.request(f"files/{file_hash}")
            data = resp.data.get('attributes', resp.data)

            result = {
                'hash': file_hash,
                'md5': data.get('md5'),
                'sha1': data.get('sha1'),
                'sha256': data.get('sha256'),
                'file_type': data.get('type_description'),
                'file_extension': data.get('type_extension'),
                'file_size': data.get('size'),
                'magic': data.get('magic'),
                'meaningful_name': data.get('meaningful_name'),
                'first_submission_date': data.get('first_submission_date'),
                'last_submission_date': data.get('last_submission_date'),
                'last_analysis_date': data.get('last_analysis_date'),
                'last_analysis_stats': data.get('last_analysis_stats'),
                'last_analysis_results': data.get('last_analysis_results'),
                'reputation': data.get('reputation'),
                'times_submitted': data.get('times_submitted'),
                'total_votes': data.get('total_votes'),
                'tags': data.get('tags'),
                'names': data.get('names'),
                'signature_info': data.get('signature_info'),
                'sandbox_verdicts': data.get('sandbox_verdicts'),
                'crowdsourced_ids_stats': data.get('crowdsourced_ids_stats'),
                'crowdsourced_yara_results': data.get('crowdsourced_yara_results'),
                'pe_info': data.get('pe_info'),
                'type_tag': data.get('type_tag'),
                'ssdeep': data.get('ssdeep'),
                'tlsh': data.get('tlsh'),
                'vhash': data.get('vhash'),
            }

            print_success(f"VirusTotal file hash data retrieved for {file_hash[:16]}...")
            return result

    except virustotal_python.VirustotalError as e:
        print_error(f"VirusTotal API error for hash: {e}")
        return None
    except Exception as e:
        print_error(f"VirusTotal unexpected error: {e}")
        return None


def get_file_contacted_ips(file_hash: str) -> Optional[List[Dict]]:
    """
    Get IPs contacted by this file (sandbox behavior).
    Relationship: files/{hash}/contacted_ips
    """
    try:
        with virustotal_python.Virustotal(API_KEY=VIRUSTOTAL_API_KEY, TIMEOUT=15.0) as vtotal:
            resp = vtotal.request(f"files/{file_hash}/contacted_ips", params={"limit": 10})
            ips = []
            for item in resp.data:
                attrs = item.get('attributes', {})
                ips.append({
                    'ip': item.get('id'),
                    'country': attrs.get('country'),
                    'as_owner': attrs.get('as_owner'),
                    'reputation': attrs.get('reputation'),
                    'last_analysis_stats': attrs.get('last_analysis_stats'),
                })
            return ips
    except Exception:
        return None


def get_file_contacted_domains(file_hash: str) -> Optional[List[Dict]]:
    """
    Get domains contacted by this file (sandbox behavior).
    Relationship: files/{hash}/contacted_domains
    """
    try:
        with virustotal_python.Virustotal(API_KEY=VIRUSTOTAL_API_KEY, TIMEOUT=15.0) as vtotal:
            resp = vtotal.request(f"files/{file_hash}/contacted_domains", params={"limit": 10})
            domains = []
            for item in resp.data:
                attrs = item.get('attributes', {})
                domains.append({
                    'domain': item.get('id'),
                    'registrar': attrs.get('registrar'),
                    'reputation': attrs.get('reputation'),
                    'last_analysis_stats': attrs.get('last_analysis_stats'),
                })
            return domains
    except Exception:
        return None


def get_file_dropped_files(file_hash: str) -> Optional[List[Dict]]:
    """
    Get files dropped by this file (sandbox behavior).
    Relationship: files/{hash}/dropped_files
    """
    try:
        with virustotal_python.Virustotal(API_KEY=VIRUSTOTAL_API_KEY, TIMEOUT=15.0) as vtotal:
            resp = vtotal.request(f"files/{file_hash}/dropped_files", params={"limit": 5})
            dropped = []
            for item in resp.data:
                attrs = item.get('attributes', {})
                dropped.append({
                    'sha256': attrs.get('sha256'),
                    'meaningful_name': attrs.get('meaningful_name'),
                    'type_description': attrs.get('type_description'),
                    'size': attrs.get('size'),
                    'last_analysis_stats': attrs.get('last_analysis_stats'),
                })
            return dropped
    except Exception:
        return None


# ==================== CONNECTIVITY TEST ====================
def test_connectivity() -> str:
    """Test VirusTotal API connectivity."""
    if not VIRUSTOTAL_API_KEY:
        return '❌ Key Missing'
    try:
        with virustotal_python.Virustotal(API_KEY=VIRUSTOTAL_API_KEY, TIMEOUT=5.0) as vtotal:
            vtotal.request("ip_addresses/8.8.8.8")
            return '✅ OK'
    except Exception:
        return '❌ Connection Failed'
