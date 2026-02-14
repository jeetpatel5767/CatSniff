"""
main.py — Entry point and orchestrator for the Security Threat Intelligence Scanner.
Routes user input to the appropriate analysis flow and displays formatted results.
"""

import virustotal_client
import ipinfo_client
import abuseipdb_client

from domain import run_domain_recon
from config import (
    detect_input_type, refang, clean_domain, is_ip_address,
    VIRUSTOTAL_API_KEY, IPINFO_API_KEY, ABUSEIPDB_API_KEY,
)
from display import (
    print_banner, print_section_header, print_sub_header, print_divider,
    print_kv, print_kv_highlight, print_table, print_analysis_stats,
    print_success, print_error, print_warning, print_info,
    print_scanning, print_api_status, print_complete, print_ip_cascade_header,
    G, R, C, Y, M, W, DG, LR, LC, B, D, RST,
)


# ==================== DISPLAY HELPERS ====================
def display_vt_ip(data: dict):
    """Display VirusTotal IP results."""
    if not data:
        print_error("No VirusTotal data available")
        return

    print_kv("Country", data.get('country'))
    print_kv("Continent", data.get('continent'))
    print_kv("Network", data.get('network'))
    print_kv("ASN", data.get('asn'))
    print_kv("AS Owner", data.get('as_owner'))
    print_kv("Registry", data.get('regional_internet_registry'))
    print_kv("Reputation", data.get('reputation'))
    print_kv("JARM", data.get('jarm'))
    print_kv("Tags", ', '.join(data['tags']) if data.get('tags') else None)

    votes = data.get('total_votes', {})
    if votes:
        print_kv("Votes", f"👍 {votes.get('harmless', 0)}  👎 {votes.get('malicious', 0)}")

    # Analysis stats with visual bar
    stats = data.get('last_analysis_stats')
    if stats:
        print_sub_header("Detection Results")
        print_analysis_stats(stats)

    # WHOIS (truncated)
    whois = data.get('whois')
    if whois:
        print_sub_header("WHOIS (first 500 chars)")
        for line in whois[:500].split('\n')[:10]:
            print(f"      {D}{W}{line.strip()}{RST}")


def display_vt_domain(data: dict):
    """Display VirusTotal domain results."""
    if not data:
        print_error("No VirusTotal data available")
        return

    print_kv("Domain", data.get('domain'))
    print_kv("Registrar", data.get('registrar'))
    print_kv("Reputation", data.get('reputation'))
    print_kv("Creation Date", data.get('creation_date'))
    print_kv("Last Update", data.get('last_update_date'))
    print_kv("JARM", data.get('jarm'))
    print_kv("Tags", ', '.join(data['tags']) if data.get('tags') else None)

    categories = data.get('categories')
    if categories:
        print_sub_header("Categories")
        for engine, cat in categories.items():
            print(f"      {G}▸ {C}{engine}:{RST} {W}{cat}{RST}")

    votes = data.get('total_votes', {})
    if votes:
        print_kv("Votes", f"👍 {votes.get('harmless', 0)}  👎 {votes.get('malicious', 0)}")

    # Analysis stats
    stats = data.get('last_analysis_stats')
    if stats:
        print_sub_header("Detection Results")
        print_analysis_stats(stats)

    # DNS Records
    dns_records = data.get('last_dns_records')
    if dns_records:
        print_sub_header("DNS Records")
        headers = ["Type", "Value", "TTL"]
        rows = []
        for rec in dns_records[:15]:
            val = rec.get('value', 'N/A')
            if len(str(val)) > 45:
                val = str(val)[:42] + "..."
            rows.append([rec.get('type', '?'), val, rec.get('ttl', 'N/A')])
        print_table(headers, rows)

    # Popularity
    pop_ranks = data.get('popularity_ranks')
    if pop_ranks:
        print_sub_header("Popularity Ranks")
        for source, info in pop_ranks.items():
            rank = info.get('rank', 'N/A') if isinstance(info, dict) else info
            print_kv(source, f"#{rank}", indent=6)

    # WHOIS
    whois = data.get('whois')
    if whois:
        print_sub_header("WHOIS (first 500 chars)")
        for line in whois[:500].split('\n')[:10]:
            print(f"      {D}{W}{line.strip()}{RST}")


def display_vt_url(data: dict):
    """Display VirusTotal URL results."""
    if not data:
        print_error("No VirusTotal data available")
        return

    print_kv("URL", data.get('url'))
    print_kv("Final URL", data.get('final_url'))
    print_kv("Title", data.get('title'))
    print_kv("HTTP Code", data.get('last_http_response_code'))
    print_kv("Content Length", data.get('last_http_response_content_length'))
    print_kv("Reputation", data.get('reputation'))
    print_kv("Tags", ', '.join(data['tags']) if data.get('tags') else None)

    categories = data.get('categories')
    if categories:
        print_sub_header("Categories")
        for engine, cat in categories.items():
            print(f"      {G}▸ {C}{engine}:{RST} {W}{cat}{RST}")

    stats = data.get('last_analysis_stats')
    if stats:
        print_sub_header("Detection Results")
        print_analysis_stats(stats)


def display_vt_file_hash(data: dict):
    """Display VirusTotal file hash results."""
    if not data:
        print_error("No VirusTotal data available")
        return

    print_kv("File Name", data.get('meaningful_name'))
    print_kv("File Type", data.get('file_type'))
    print_kv("Extension", data.get('file_extension'))
    print_kv("Size", f"{data['file_size']:,} bytes" if data.get('file_size') else None)
    print_kv("Magic", data.get('magic'))
    print_kv("Reputation", data.get('reputation'))
    print_kv("Times Submitted", data.get('times_submitted'))
    print_kv("Type Tag", data.get('type_tag'))

    # Hashes
    print_sub_header("Hashes")
    print_kv("MD5", data.get('md5'), indent=6)
    print_kv("SHA1", data.get('sha1'), indent=6)
    print_kv("SHA256", data.get('sha256'), indent=6)
    print_kv("SSDeep", data.get('ssdeep'), indent=6)
    print_kv("TLSH", data.get('tlsh'), indent=6)
    print_kv("VHash", data.get('vhash'), indent=6)

    # Tags
    print_kv("Tags", ', '.join(data['tags']) if data.get('tags') else None)

    # Names
    names = data.get('names')
    if names:
        print_kv("Known Names", ', '.join(names[:10]))

    votes = data.get('total_votes', {})
    if votes:
        print_kv("Votes", f"👍 {votes.get('harmless', 0)}  👎 {votes.get('malicious', 0)}")

    # Analysis stats
    stats = data.get('last_analysis_stats')
    if stats:
        print_sub_header("Detection Results")
        print_analysis_stats(stats)

    # Signature info
    sig = data.get('signature_info')
    if sig:
        print_sub_header("Signature Info")
        if isinstance(sig, dict):
            for key, val in sig.items():
                print_kv(key, val, indent=6)

    # Sandbox verdicts
    sandbox = data.get('sandbox_verdicts')
    if sandbox:
        print_sub_header("Sandbox Verdicts")
        if isinstance(sandbox, dict):
            for engine, verdict in sandbox.items():
                cat = verdict.get('category', 'N/A') if isinstance(verdict, dict) else verdict
                print_kv(engine, cat, indent=6)

    # Crowdsourced IDS
    ids_stats = data.get('crowdsourced_ids_stats')
    if ids_stats:
        print_sub_header("Crowdsourced IDS Stats")
        if isinstance(ids_stats, dict):
            for key, val in ids_stats.items():
                print_kv(key, val, indent=6)

    # YARA results
    yara = data.get('crowdsourced_yara_results')
    if yara and isinstance(yara, list):
        print_sub_header("YARA Rules Matched")
        for rule in yara[:5]:
            name = rule.get('rule_name', 'Unknown')
            src = rule.get('source', 'Unknown')
            print(f"      {G}▸ {Y}{name}{RST} {D}(source: {src}){RST}")


def display_ipinfo(data: dict):
    """Display IPInfo results."""
    if not data:
        print_error("No IPInfo data available")
        return

    print_kv("IP", data.get('ip'))
    print_kv("Hostname", data.get('hostname'))
    print_kv("City", data.get('city'))
    print_kv("Region", data.get('region'))
    print_kv("Country", data.get('country'))
    print_kv("Location", data.get('loc'))
    print_kv("Organization", data.get('org'))
    print_kv("Postal Code", data.get('postal'))
    print_kv("Timezone", data.get('timezone'))

    if data.get('company'):
        print_kv("Company", data.get('company'))
        print_kv("Company Domain", data.get('company_domain'))
        print_kv("Company Type", data.get('company_type'))

    privacy = data.get('privacy')
    if privacy and isinstance(privacy, dict):
        print_sub_header("Privacy Flags")
        for flag, value in privacy.items():
            color = R if value else G
            status = "YES" if value else "NO"
            print(f"      {color}{B}{status}{RST} {C}{flag}{RST}")


def display_abuseipdb(data: dict):
    """Display AbuseIPDB results."""
    if not data:
        print_error("No AbuseIPDB data available")
        return

    score = data.get('abuse_confidence_score', 0)
    if score >= 75:
        score_color = LR
    elif score >= 25:
        score_color = Y
    else:
        score_color = DG

    print_kv("IP", data.get('ip'))
    print_kv("Country", f"{data.get('country_name', 'N/A')} ({data.get('country_code', 'N/A')})")
    print_kv("ISP", data.get('isp'))
    print_kv("Domain", data.get('domain'))
    print_kv("Usage Type", data.get('usage_type'))
    print(f"    {G}▸ {C}Abuse Score:{RST} {score_color}{B}{score}%{RST}")
    print_kv("Total Reports", data.get('total_reports', 0))
    print_kv("Distinct Reporters", data.get('num_distinct_users', 0))
    print_kv("Whitelisted", data.get('is_whitelisted', False))
    print_kv("Last Reported", data.get('last_reported_at'))

    # Recent reports
    reports = data.get('reports', [])
    if reports:
        print_sub_header(f"Recent Abuse Reports (top 3 of {len(reports)})")
        for i, report in enumerate(reports[:3], 1):
            print(f"\n      {Y}{B}Report #{i}{RST}")
            print_kv("Date", report.get('reportedAt', 'N/A'), indent=6)
            print_kv("Reporter", report.get('reporterCountryName', 'N/A'), indent=6)
            categories = report.get('categories', [])
            print_kv("Categories", ', '.join(map(str, categories)) if categories else 'N/A', indent=6)
            comment = report.get('comment', '')
            if comment:
                short = comment[:120] + "..." if len(comment) > 120 else comment
                print_kv("Comment", short, indent=6)


def display_domain_recon(data: dict):
    """Display domain reconnaissance results."""
    if not data:
        return

    ip = data.get('ip')
    if ip:
        print_kv("Resolved IP", ip)
    else:
        print_warning("Could not resolve domain to IP")

    # SSL
    ssl_data = data.get('ssl')
    if ssl_data:
        print_sub_header("SSL Certificate")
        print_kv("Issuer", ssl_data.get('issuer'), indent=6)
        print_kv("Valid From", ssl_data.get('valid_from'), indent=6)
        print_kv("Valid To", ssl_data.get('valid_to'), indent=6)
    else:
        print_kv("SSL Certificate", "Not found on port 443")

    # Hosting
    hosting = data.get('hosting')
    if hosting:
        print_sub_header("Hosting / WHOIS")
        print_kv("ISP", hosting.get('isp'), indent=6)
        print_kv("Country", hosting.get('country'), indent=6)
        print_kv("Registered", hosting.get('registered'), indent=6)

    # Subdomains
    subs = data.get('subdomains', [])
    if subs:
        print_sub_header(f"Subdomains Found ({len(subs)})")
        for s in subs:
            print(f"      {G}✅ {DG}{s}{RST}")
    else:
        print_kv("Subdomains", "None found (common list scanned)")

    # Protocols
    protos = data.get('protocols')
    if protos:
        print_sub_header("Protocols")
        http_status = f"{G}✅ Supported{RST}" if protos.get('http') else f"{R}❌ Not Supported{RST}"
        https_status = f"{G}✅ Supported{RST}" if protos.get('https') else f"{R}❌ Not Supported{RST}"
        print(f"      HTTP:  {http_status}")
        print(f"      HTTPS: {https_status}")





def display_relationship_table(title: str, items: list, columns: list):
    """Display a relationship result as a table."""
    if not items:
        return
    print_sub_header(title)
    headers = [col['header'] for col in columns]
    rows = []
    for item in items:
        row = [str(item.get(col['key'], 'N/A'))[:45] for col in columns]
        rows.append(row)
    print_table(headers, rows)


# ==================== IP ANALYSIS FLOW ====================
def analyze_ip(ip_address: str):
    """Full analysis for an IP address — queries all 3 APIs."""
    print_scanning(ip_address, "IP Address")

    # VirusTotal
    print_section_header("VirusTotal — IP Intelligence", "🔬")
    vt_data = virustotal_client.search_ip(ip_address)
    display_vt_ip(vt_data)

    # VT Relationships
    resolutions = virustotal_client.get_ip_resolutions(ip_address)
    if resolutions:
        display_relationship_table("Domains Resolving to this IP", resolutions,
                                   [{'header': 'Domain', 'key': 'host_name'},
                                    {'header': 'Date', 'key': 'date'}])

    comm_files = virustotal_client.get_ip_communicating_files(ip_address)
    if comm_files:
        display_relationship_table("Communicating Files", comm_files,
                                   [{'header': 'SHA256', 'key': 'sha256'},
                                    {'header': 'Name', 'key': 'meaningful_name'},
                                    {'header': 'Type', 'key': 'type_description'}])



    # IPInfo
    print_section_header("IPInfo — Geolocation & Network", "🌍")
    ipinfo_data = ipinfo_client.search_ip(ip_address)
    display_ipinfo(ipinfo_data)

    # AbuseIPDB
    print_section_header("AbuseIPDB — Abuse Reports", "🚩")
    abuse_data = abuseipdb_client.search_ip(ip_address)
    display_abuseipdb(abuse_data)


# ==================== DOMAIN ANALYSIS FLOW ====================
def analyze_domain_flow(domain: str):
    """
    Full analysis for a domain.
    1. Domain recon (DNS, SSL, WHOIS, subdomains, protocols)
    2. VirusTotal domain intelligence
    3. Extract resolved IPs from VT resolutions
    4. Cascade each IP into IPInfo + AbuseIPDB
    """
    print_scanning(domain, "Domain")

    # Domain Recon
    print_section_header("Domain Reconnaissance", "🔎")
    recon_data = run_domain_recon(domain)
    display_domain_recon(recon_data)

    # VirusTotal Domain
    print_section_header("VirusTotal — Domain Intelligence", "🔬")
    vt_data = virustotal_client.search_domain(domain)
    display_vt_domain(vt_data)

    # VT Subdomains
    vt_subs = virustotal_client.get_domain_subdomains(domain)
    if vt_subs:
        print_sub_header(f"VirusTotal Subdomains ({len(vt_subs)})")
        for sub in vt_subs:
            print(f"      {G}▸ {DG}{sub}{RST}")

    # VT Communicating files
    comm_files = virustotal_client.get_domain_communicating_files(domain)
    if comm_files:
        display_relationship_table("Communicating Files", comm_files,
                                   [{'header': 'SHA256', 'key': 'sha256'},
                                    {'header': 'Name', 'key': 'meaningful_name'},
                                    {'header': 'Type', 'key': 'type_description'}])



    # Get resolved IPs — cascade into IPInfo + AbuseIPDB
    resolved_ips = set()

    # From domain recon
    if recon_data.get('ip'):
        resolved_ips.add(recon_data['ip'])

    # From VT resolutions
    vt_resolutions = virustotal_client.get_domain_resolutions(domain)
    if vt_resolutions:
        display_relationship_table("IP Resolutions (VirusTotal)", vt_resolutions,
                                   [{'header': 'IP Address', 'key': 'ip_address'},
                                    {'header': 'Date', 'key': 'date'}])
        for res in vt_resolutions:
            ip = res.get('ip_address')
            if ip:
                resolved_ips.add(ip)

    # Cascade: for each resolved IP, query IPInfo + AbuseIPDB
    if resolved_ips:
        # Only cascade the first 3 IPs to avoid rate limits
        cascade_ips = list(resolved_ips)[:3]
        for ip in cascade_ips:
            print_ip_cascade_header(ip, source=domain)

            print_section_header(f"IPInfo — {ip}", "🌍")
            ipinfo_data = ipinfo_client.search_ip(ip)
            display_ipinfo(ipinfo_data)

            print_section_header(f"AbuseIPDB — {ip}", "🚩")
            abuse_data = abuseipdb_client.search_ip(ip)
            display_abuseipdb(abuse_data)
    else:
        print_warning("No resolved IPs found — IPInfo and AbuseIPDB checks skipped.")


# ==================== URL ANALYSIS FLOW ====================
def analyze_url_flow(url: str):
    """
    Full analysis for a URL.
    1. VirusTotal URL analysis
    2. Extract domain from URL → run domain flow for IP cascade
    """
    print_scanning(url, "URL")

    # VirusTotal URL
    print_section_header("VirusTotal — URL Analysis", "🔬")
    vt_data = virustotal_client.search_url(url)
    display_vt_url(vt_data)


    # Extract domain and cascade
    domain = clean_domain(url)
    if domain:
        print_info(f"Extracted domain: {domain} — running domain cascade...")
        analyze_domain_flow(domain)


# ==================== FILE HASH ANALYSIS FLOW ====================
def analyze_hash_flow(file_hash: str):
    """
    Full analysis for a file hash.
    1. VirusTotal file analysis
    2. Extract contacted IPs/domains from sandbox behavior
    3. Cascade contacted IPs → IPInfo + AbuseIPDB
    """
    print_scanning(file_hash, "File Hash")

    # VirusTotal File
    print_section_header("VirusTotal — File Analysis", "🔬")
    vt_data = virustotal_client.search_file_hash(file_hash)
    display_vt_file_hash(vt_data)



    # Contacted IPs
    contacted_ips = virustotal_client.get_file_contacted_ips(file_hash)
    if contacted_ips:
        display_relationship_table("Contacted IPs (Sandbox)", contacted_ips,
                                   [{'header': 'IP', 'key': 'ip'},
                                    {'header': 'Country', 'key': 'country'},
                                    {'header': 'AS Owner', 'key': 'as_owner'}])

        # Cascade first 3 contacted IPs
        for item in contacted_ips[:3]:
            ip = item.get('ip')
            if ip:
                print_ip_cascade_header(ip, source="file sandbox")

                print_section_header(f"IPInfo — {ip}", "🌍")
                ipinfo_data = ipinfo_client.search_ip(ip)
                display_ipinfo(ipinfo_data)

                print_section_header(f"AbuseIPDB — {ip}", "🚩")
                abuse_data = abuseipdb_client.search_ip(ip)
                display_abuseipdb(abuse_data)

    # Contacted Domains
    contacted_domains = virustotal_client.get_file_contacted_domains(file_hash)
    if contacted_domains:
        display_relationship_table("Contacted Domains (Sandbox)", contacted_domains,
                                   [{'header': 'Domain', 'key': 'domain'},
                                    {'header': 'Registrar', 'key': 'registrar'},
                                    {'header': 'Reputation', 'key': 'reputation'}])

    # Dropped Files
    dropped = virustotal_client.get_file_dropped_files(file_hash)
    if dropped:
        display_relationship_table("Dropped Files (Sandbox)", dropped,
                                   [{'header': 'SHA256', 'key': 'sha256'},
                                    {'header': 'Name', 'key': 'meaningful_name'},
                                    {'header': 'Type', 'key': 'type_description'}])


# ==================== API CONNECTIVITY TEST ====================
def test_all_apis() -> dict:
    """Test connectivity for all configured APIs."""
    results = {
        'VirusTotal': virustotal_client.test_connectivity(),
        'IPInfo': ipinfo_client.test_connectivity(),
        'AbuseIPDB': abuseipdb_client.test_connectivity(),

    }
    return results


# ==================== MAIN ====================
def main():
    """Main interactive loop."""
    print_banner()

    # Test API connectivity
    print_info("Testing API connectivity...")
    api_status = test_all_apis()
    print_api_status(api_status)

    while True:
        # Get input
        print(f"\n{G}{B}  ┌──────────────────────────────────────────────────────────┐{RST}")
        print(f"{G}{B}  │{RST}  {C}Enter IP, Domain, URL, or File Hash to analyze{RST}         {G}{B}│{RST}")
        print(f"{G}{B}  │{RST}  {D}Type 'quit' or 'exit' to stop{RST}                          {G}{B}│{RST}")
        print(f"{G}{B}  └──────────────────────────────────────────────────────────┘{RST}")

        try:
            user_input = input(f"\n  {G}{B}⟩{RST} {C}Target ▸ {RST}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Y}Interrupted. Exiting...{RST}")
            break

        if not user_input:
            print_warning("No input provided. Try again.")
            continue

        if user_input.lower() in ('quit', 'exit', 'q'):
            print(f"\n  {G}{B}🐱 CatSniff shutting down... stay safe!{RST}\n")
            break

        # Refang the input
        cleaned = refang(user_input)

        # Detect type
        input_type = detect_input_type(cleaned)

        print(f"\n  {D}{G}Detected type: {C}{B}{input_type.upper()}{RST}")

        # Route to appropriate analysis
        try:
            if input_type == 'ip':
                analyze_ip(cleaned)
            elif input_type == 'domain':
                domain = clean_domain(cleaned)
                analyze_domain_flow(domain)
            elif input_type == 'url':
                analyze_url_flow(cleaned)
            elif input_type == 'hash':
                analyze_hash_flow(cleaned)
        except Exception as e:
            print_error(f"Analysis failed: {e}")

        print_complete()


if __name__ == "__main__":
    main()
