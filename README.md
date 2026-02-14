
<!-- ═══════════════════════════════════════════════════════════════════ -->
<!-- ░░░░░░░░░░░░░░░░░░░░░ C A T S N I F F ░░░░░░░░░░░░░░░░░░░░░░░░ -->
<!-- ═══════════════════════════════════════════════════════════════════ -->

<div align="center">

```
     ██████╗ █████╗ ████████╗███████╗███╗   ██╗██╗███████╗███████╗
    ██╔════╝██╔══██╗╚══██╔══╝██╔════╝████╗  ██║██║██╔════╝██╔════╝
    ██║     ███████║   ██║   ███████╗██╔██╗ ██║██║█████╗  █████╗  
    ██║     ██╔══██║   ██║   ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  
    ╚██████╗██║  ██║   ██║   ███████║██║ ╚████║██║██║     ██║     
     ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     
```

### 🐱 `CatSniff` — *Malicious IP & Domain Threat Intelligence Pipeline*

[![Python](https://img.shields.io/badge/Python-3.8%2B-00ff41?style=for-the-badge&logo=python&logoColor=00ff41&labelColor=0d1117)](https://python.org)
[![SQLite](https://img.shields.io/badge/SQLite-Database-00ff41?style=for-the-badge&logo=sqlite&logoColor=00ff41&labelColor=0d1117)](https://sqlite.org)
[![VirusTotal](https://img.shields.io/badge/VirusTotal-API-ff6600?style=for-the-badge&logo=virustotal&logoColor=ff6600&labelColor=0d1117)](https://virustotal.com)
[![License](https://img.shields.io/badge/License-Educational-00ff41?style=for-the-badge&labelColor=0d1117)](LICENSE)

> *Sniff out the threats. Hunt the malicious. Stay invisible.*

```
╔══════════════════════════════════════════════════════════════╗
║  [■] IOC Ingestion    [■] Threat Feed Parsing               ║
║  [■] API Enrichment   [■] VirusTotal · IPInfo · AbuseIPDB   ║
║  [■] SQLite Caching   [■] Domain Recon · IP Geolocation     ║
╚══════════════════════════════════════════════════════════════╝
```

</div>

---

## `>> cat /etc/catsniff/about.conf`

A **two-part threat intelligence system** that ingests IOCs (Indicators of Compromise) from public threat feeds and enriches them with **live API data** from **VirusTotal**, **IPInfo**, and **AbuseIPDB**.

```
 ┌─────────────────────┐      ┌──────────────────────┐
 │   Pipline1           │      │   Pipline2            │
 │   ━━━━━━━━━━━━━━━━   │      │   ━━━━━━━━━━━━━━━━━   │
 │   Data Ingestion     │─────▶│   API Scanner          │
 │   Threat Feed → DB   │      │   VT + IPInfo + AIPDB  │
 └─────────────────────┘      └──────────────────────┘
              │                          │
              └──────────┬───────────────┘
                         ▼
                ┌─────────────────┐
                │  enrichment.py  │
                │  ━━━━━━━━━━━━━  │
                │  THE BRIDGE     │
                └─────────────────┘
```

---

## `>> tree --dirsfirst /CatSniff`

```
CatSniff/                              ← Root (you are here)
│
├── Pipline1/                          ← 🔻 Data Pipeline — IOC Ingestion
│   ├── db/
│   │   ├── schema.sql                 ← Database schema
│   │   └── raw_iocs.db               ← SQLite database (auto-created)
│   ├── app/
│   │   ├── main.py                    ← Ingest IOCs from threat feeds
│   │   ├── fetcher.py                 ← Fetch data from URLs or local files
│   │   ├── extractor.py              ← Extract IPs, domains, URLs via regex
│   │   ├── normalizer.py             ← Clean & normalize IOCs
│   │   ├── detector.py               ← Detect content type (JSON/HTML/text)
│   │   ├── storage.py                ← Store IOCs in DB + lookup + caching
│   │   ├── enrichment.py             ← 🔗 Bridge: connects DB → API scanner
│   │   ├── migrate.py                ← One-time migration script
│   │   └── check_db.py               ← Inspect database contents
│   ├── requirements.txt
│   └── README.md
│
├── Pipline2/                          ← 🔻 API Scanner — Live Threat Analysis
│   ├── main.py                        ← Interactive CLI scanner
│   ├── virustotal_client.py           ← VirusTotal API client
│   ├── ipinfo_client.py              ← IPInfo API client
│   ├── abuseipdb_client.py           ← AbuseIPDB API client
│   ├── domain.py                      ← Domain reconnaissance
│   ├── config.py                      ← API keys & input detection
│   ├── display.py                     ← Terminal display formatting
│   ├── .env                           ← API keys (⚠ DO NOT commit)
│   └── requirements.txt
│
└── README.md                          ← You're reading this
```

---

## `>> cat /proc/catsniff/color_scheme`

The CLI uses a custom **hacker-themed color palette** powered by `colorama`:

```python
from colorama import Fore, Style

G  = Fore.GREEN          # ██ Hacker green
R  = Fore.RED            # ██ Error / malicious
C  = Fore.CYAN           # ██ Info / headers
Y  = Fore.YELLOW         # ██ Warning
M  = Fore.MAGENTA        # ██ Highlights
W  = Fore.WHITE          # ██ Normal text
DG = Fore.LIGHTGREEN_EX  # ██ Light green
LR = Fore.LIGHTRED_EX    # ██ Bright red
LC = Fore.LIGHTCYAN_EX   # ██ Bright cyan
B  = Style.BRIGHT        #    Bold
D  = Style.DIM           #    Dim
RST = Style.RESET_ALL    #    Reset
```

```python
# ==================== BANNER ====================
def print_banner():
    """Print the hacker-themed startup banner."""
    banner = f"""
{G}{B}
     ██████╗ █████╗ ████████╗███████╗███╗   ██╗██╗███████╗███████╗
    ██╔════╝██╔══██╗╚══██╔══╝██╔════╝████╗  ██║██║██╔════╝██╔════╝
    ██║     ███████║   ██║   ███████╗██╔██╗ ██║██║█████╗  █████╗  
    ██║     ██╔══██║   ██║   ╚════██║██║╚██╗██║██║██╔══╝  ██╔══╝  
    ╚██████╗██║  ██║   ██║   ███████║██║ ╚████║██║██║     ██║     
     ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝╚═╝╚═╝     ╚═╝     
{RST}
    """
    print(banner)
```

---

## `>> ./how_it_works.sh`

### ⚡ Pipeline 1 — Data Ingestion (`Pipline1`)

Fetches IOC lists from public threat feeds and stores them in SQLite:

```
 ┌──────────────┐    ┌───────┐    ┌──────────────┐    ┌───────────┐    ┌──────────┐
 │ Threat Feed  │───▶│ Fetch │───▶│ Extract IOCs │───▶│ Normalize │───▶│ Store DB │
 │    URL       │    │       │    │ IPs/Domains  │    │  & Clean  │    │ SQLite   │
 └──────────────┘    └───────┘    └──────────────┘    └───────────┘    └──────────┘
```

**Database holds:**
| Table | Contents | Count |
|---|---|---|
| `ip_iocs` | Malicious IP addresses from threat feeds | **2,152+** |
| `domain_iocs` | Malicious domains & URLs from threat feeds | **219,618+** |

---

### ⚡ Pipeline 2 — API Scanner (`Pipline2`)

Interactive CLI tool that queries **3 security APIs**:

```
 ┌────────────┐    ┌────────────┐    ┌──────────┐    ┌────────────┐    ┌─────────┐
 │ User Input │───▶│ VirusTotal │───▶│  IPInfo  │───▶│ AbuseIPDB  │───▶│ Display │
 │ IP/Domain  │    │  Scan      │    │  GeoLoc  │    │  Abuse Rpt │    │ Results │
 └────────────┘    └────────────┘    └──────────┘    └────────────┘    └─────────┘
```

---

### 🔗 The Bridge — `enrichment.py`

Connects both pipelines into one unified threat intelligence flow:

```
 ┌─────────────────────────────────────────────────────────────────┐
 │                     ENRICHMENT BRIDGE                          │
 ├─────────────────────────────────────────────────────────────────┤
 │                                                                 │
 │  1. ░░ Check if IOC exists in threat feed DB                   │
 │     └──▶ flag: in_threat_feed = true/false                     │
 │                                                                 │
 │  2. ░░ Call VirusTotal + IPInfo + AbuseIPDB                    │
 │     └──▶ Fetch live threat data from all 3 APIs                │
 │                                                                 │
 │  3. ░░ Cache API results in DB (reuses for 24 hours)           │
 │     └──▶ Saves $$$ on rate-limited APIs                        │
 │                                                                 │
 │  4. ░░ Return combined JSON response                           │
 │     └──▶ One unified threat report                             │
 │                                                                 │
 └─────────────────────────────────────────────────────────────────┘
```

---

## `>> sudo ./setup.sh` — Quick Start Guide

> ⚠️ **Prerequisites:** Python 3.8+ and `pip` installed on your system.

---

### `[STEP 1]` — Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/CatSniff.git
cd CatSniff
```

---

### `[STEP 2]` — Set Up Pipeline 1 (Data Ingestion)

```bash
# Navigate to Pipeline 1
cd Pipline1

# (Optional) Create a virtual environment
python -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

### `[STEP 3]` — Set Up Pipeline 2 (API Scanner)

```bash
# Navigate to Pipeline 2 (from the root)
cd Pipline2

# (Optional) Create a virtual environment
python -m venv venv

# Activate it
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

### `[STEP 4]` — Configure API Keys

Create or edit the `.env` file inside `Pipline2/`:

```env
# ═══════════════════════════════════════════
# ░░░ C A T S N I F F — A P I   K E Y S ░░░
# ═══════════════════════════════════════════

VIRUSTOTAL_API_KEY=your_virustotal_key_here
IPINFO_API_KEY=your_ipinfo_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
```

**🔑 Get your keys from:**

| Service | Signup URL |
|---------|-----------|
| 🦠 VirusTotal | [virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey) |
| 🌐 IPInfo | [ipinfo.io/account/token](https://ipinfo.io/account/token) |
| 🛡️ AbuseIPDB | [abuseipdb.com/account/api](https://www.abuseipdb.com/account/api) |

---

### `[STEP 5]` — Initialize the Database

```bash
# From CatSniff root, navigate to Pipeline 1
cd Pipline1

# Ingest IOCs from a threat feed URL
python app/main.py https://example.com/threat-feed.txt

# Or from a local file
python app/main.py data/malicious_ips.txt
```

This extracts all IPs, domains, and URLs and stores them into the SQLite database at `db/raw_iocs.db`.

---

### `[STEP 6]` — Run the Interactive CLI Scanner

```bash
cd Pipline2
python main.py
```

```
 ┌──────────────────────────────────────────────┐
 │  Enter IP / Domain / URL / Hash to scan      │
 │  ▸ 8.8.8.8                                   │
 │                                               │
 │  [■] Querying VirusTotal...                   │
 │  [■] Querying IPInfo...                       │
 │  [■] Querying AbuseIPDB...                    │
 │  [✓] Scan complete.                           │
 └──────────────────────────────────────────────┘
```

---

### `[STEP 7]` — Use the Enrichment Bridge

```bash
cd Pipline1

# Enrich an IP (checks DB + calls all 3 APIs)
python app/enrichment.py 8.8.8.8

# Enrich a domain (checks DB + VT + cascades resolved IPs)
python app/enrichment.py kavachdownload.in
```

Returns combined JSON:
```json
{
  "in_threat_feed": true,
  "virustotal": { "detection_score": "5/90", "reputation": -2 },
  "ipinfo": { "country": "US", "org": "AS15169 Google LLC" },
  "abuseipdb": { "abuse_score": 0, "total_reports": 14 }
}
```

---

## `>> cat /var/log/commands.log`

| Command | Description |
|---------|-------------|
| `python app/main.py <url\|file>` | ░░ Ingest a threat feed into the DB |
| `python app/check_db.py` | ░░ View database stats and sample data |
| `python app/enrichment.py <ip>` | ░░ Enrich an IP with all 3 APIs |
| `python app/enrichment.py <domain>` | ░░ Enrich a domain with all 3 APIs |
| `python app/migrate.py` | ░░ Migrate old `raw_iocs` data to new tables |
| `python main.py` | ░░ Launch the interactive CLI scanner |

---

## `>> SELECT * FROM schema_info;`

| Table | Contents | Count |
|-------|----------|-------|
| `ip_iocs` | Malicious IP addresses from threat feeds | **2,152+** |
| `domain_iocs` | Malicious domains & URLs from threat feeds | **219,618+** |
| `enrichment_results` | Cached API responses (auto-filled) | *grows on use* |
| `sources` | Tracked threat feed sources | *varies* |

---

## `>> cat /proc/catsniff/search_flow`

```
┌─────────────────────────────────────────────────────────────────────┐
│                        IP SEARCH FLOW                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  User searches "8.8.8.8" with IP mode selected                     │
│    │                                                                │
│    ├──▶ Query ip_iocs table (fast DB lookup)                       │
│    │    └── Found? ──▶ Flag as "in threat feed"                    │
│    │                                                                │
│    ├──▶ Check enrichment cache                                     │
│    │    ├── Cached & fresh? ──▶ Return immediately                 │
│    │    └── Not cached? ──▶ Call VT + IPInfo + AbuseIPDB           │
│    │                                                                │
│    └──▶ Cache results ──▶ Return JSON                              │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                      DOMAIN SEARCH FLOW                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  User searches "kavachdownload.in" with Domain mode selected       │
│    │                                                                │
│    ├──▶ Query domain_iocs table (fast DB lookup)                   │
│    │    └── Found? ──▶ Flag as "in threat feed"                    │
│    │                                                                │
│    ├──▶ Call VT domain ──▶ Extract resolved IPs                    │
│    │    └── For each IP ──▶ Call IPInfo + AbuseIPDB                │
│    │                                                                │
│    └──▶ Cache everything ──▶ Return JSON                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## `>> cat /etc/catsniff/rate_limits.conf`

```
╔════════════════════════════════════════════════════════╗
║  SERVICE           FREE TIER LIMIT        STATUS      ║
╠════════════════════════════════════════════════════════╣
║  🦠 VirusTotal     4 req/minute           [ACTIVE]    ║
║  🌐 IPInfo         50,000 req/month       [ACTIVE]    ║
║  🛡️ AbuseIPDB      1,000 req/day          [ACTIVE]    ║
╚════════════════════════════════════════════════════════╝
```

> 💡 **Tip:** The enrichment bridge caches API results for **24 hours** to minimize API calls and stay within free-tier limits.

---

## `>> cat /etc/catsniff/troubleshooting.conf`

<details>
<summary><b>🔧 Common Issues & Fixes</b></summary>

### ❌ `ModuleNotFoundError: No module named 'requests'`
```bash
pip install -r requirements.txt
```

### ❌ `API key not found` or `401 Unauthorized`
Make sure your `.env` file is in the `Pipline2/` directory and contains valid keys.

### ❌ `Database is locked`
Close any other processes accessing `raw_iocs.db` (e.g., DB Browser for SQLite).

### ❌ `DNS resolution failed for domain`
Some domains may be taken down. This is expected for malicious domains. The tool will report the failure and continue.

### ❌ `Rate limit exceeded`
Wait for the cooldown period to pass. VirusTotal is the strictest at **4 requests/minute**.

</details>

---

<div align="center">

```
╔══════════════════════════════════════════════════════════╗
║                                                          ║
║   ░█████╗░░█████╗░████████╗░██████╗███╗░░██╗██╗███████╗ ║
║   ██╔══██╗██╔══██╗╚══██╔══╝██╔════╝████╗░██║██║██╔════╝ ║
║   ██║░░╚═╝███████║░░░██║░░░╚█████╗░██╔██╗██║██║█████╗░░ ║
║   ██║░░██╗██╔══██║░░░██║░░░░╚═══██╗██║╚████║██║██╔══╝░░ ║
║   ╚█████╔╝██║░░██║░░░██║░░░██████╔╝██║░╚███║██║██║░░░░░ ║
║   ░╚════╝░╚═╝░░╚═╝░░░╚═╝░░░╚═════╝░╚═╝░░╚══╝╚═╝╚═╝░░░ ║
║                                                          ║
║          >> Sniff. Detect. Neutralize. <<                ║
║                                                          ║
╚══════════════════════════════════════════════════════════╝
```

*For educational and security research purposes only.*

**`[EOF]`**

</div>
