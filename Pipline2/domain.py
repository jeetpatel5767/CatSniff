"""
domain.py — Domain resolution and reconnaissance.
Handles DNS resolution (multi-method), SSL certificate checks,
WHOIS/hosting info, subdomain discovery, and protocol checks.
"""

import socket
import ssl
import requests
import dns.resolver
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from ipwhois import IPWhois
from typing import Optional
from display import print_sub_header, print_kv, print_success, print_error, print_warning


def get_ip_from_domain(domain: str) -> Optional[str]:
    """Resolves a domain name to an IP address using multiple methods."""
    # Method 1: socket (OS level)
    try:
        ip = socket.gethostbyname(domain)
        if ip:
            return ip
    except Exception:
        pass

    # Method 2: dns.resolver with default resolver
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            return str(rdata)
    except Exception:
        pass

    # Method 3: Try with Google / Cloudflare public DNS as fallback
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '8.8.4.4', '1.1.1.1']
        answers = resolver.resolve(domain, 'A')
        for rdata in answers:
            return str(rdata)
    except Exception as e:
        print_warning(f"DNS Resolution failed for {domain}: {e}")

    return None


def check_ssl_certificate(domain: str) -> Optional[dict]:
    """Retrieves SSL certificate information for a domain."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert_bin = ssock.getpeercert(binary_form=True)
                cert = x509.load_der_x509_certificate(cert_bin, default_backend())

                return {
                    'issuer': cert.issuer.rfc4514_string(),
                    'valid_from': str(cert.not_valid_before_utc),
                    'valid_to': str(cert.not_valid_after_utc),
                }
    except Exception:
        return None


def get_hosting_info(ip: str) -> Optional[dict]:
    """Retrieves WHOIS/hosting information for an IP."""
    try:
        whois = IPWhois(ip).lookup_rdap()
        network = whois.get("network", {})
        return {
            'isp': network.get('name', 'N/A'),
            'country': network.get('country', 'N/A'),
            'registered': network.get('events', [{}])[0].get('timestamp', 'N/A') if network.get('events') else 'N/A',
        }
    except Exception:
        return None


def find_subdomains(domain: str) -> list:
    """Checks for common subdomains via DNS brute-force."""
    common_subs = ["www", "mail", "ftp", "api", "dev", "test", "staging",
                   "admin", "blog", "shop", "app", "cdn", "vpn", "ns1", "ns2"]
    found = []
    for sub in common_subs:
        try:
            dns.resolver.resolve(f"{sub}.{domain}", "A")
            found.append(f"{sub}.{domain}")
        except Exception:
            pass
    return found


def check_protocols(domain: str) -> dict:
    """Checks support for HTTP and HTTPS."""
    result = {'http': False, 'https': False}
    try:
        requests.get(f"http://{domain}", timeout=3)
        result['http'] = True
    except Exception:
        pass
    try:
        requests.get(f"https://{domain}", timeout=3)
        result['https'] = True
    except Exception:
        pass
    return result


def run_domain_recon(domain: str) -> dict:
    """
    Run all domain reconnaissance checks and return structured results.
    This is called from main.py for domain/URL analysis flow.
    """
    results = {
        'domain': domain,
        'ip': None,
        'ssl': None,
        'hosting': None,
        'subdomains': [],
        'protocols': None,
    }

    # Resolve IP
    ip = get_ip_from_domain(domain)
    results['ip'] = ip

    if not ip:
        print_warning(f"Could not resolve '{domain}' to an IP address.")
        print_warning("The domain may be offline, taken down, or non-existent.")
        return results

    print_success(f"Resolved IP: {ip}")

    # SSL Certificate
    results['ssl'] = check_ssl_certificate(domain)

    # Hosting / WHOIS
    results['hosting'] = get_hosting_info(ip)

    # Subdomains
    results['subdomains'] = find_subdomains(domain)

    # Protocols
    results['protocols'] = check_protocols(domain)

    return results
