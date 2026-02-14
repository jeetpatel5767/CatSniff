# Security API Integration Tool

A simple Python tool to query multiple security APIs and extract maximum field data for threat intelligence analysis.

## 🔧 APIs Integrated

1. **VirusTotal** - Malware analysis and threat intelligence
2. **IPInfo** - IP geolocation and network information
3. **AbuseIPDB** - IP abuse and blacklist checking
4. **MalwareBazaar** - Malware samples and threat hunting

## 📋 Setup

### 1. Create Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure API Keys

Edit the `.env` file and add your API keys:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
IPINFO_API_KEY=your_ipinfo_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
MALWAREBAZAAR_API_KEY=your_malwarebazaar_api_key_here
```

**Where to get API keys:**
- VirusTotal: https://www.virustotal.com/gui/my-apikey
- IPInfo: https://ipinfo.io/account/token
- AbuseIPDB: https://www.abuseipdb.com/account/api
- MalwareBazaar: https://bazaar.abuse.ch/api/

## 🚀 Usage

### Run the script

```bash
python main.py
```

### Example Code

```python
from main import SecurityAPIClient
import json

client = SecurityAPIClient()

# Analyze an IP address
result = client.analyze_ip('8.8.8.8')
print(json.dumps(result, indent=2))

# Analyze a domain
result = client.analyze_domain('google.com')
print(json.dumps(result, indent=2))

# Analyze a file hash
hash_value = '094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d'
result = client.analyze_file_hash(hash_value)
print(json.dumps(result, indent=2))
```

## 📊 Maximum Fields Extracted

### VirusTotal (IP)
- Country, continent, network, ASN, AS owner
- WHOIS data, reputation score
- Last analysis statistics and dates
- Tags, votes, JARM fingerprint

### VirusTotal (Domain)
- DNS records, HTTPS certificates
- Domain categories, popularity ranks
- Registrar, creation/update dates
- WHOIS data, reputation, tags

### VirusTotal (File Hash)
- MD5, SHA1, SHA256 hashes
- File type, size, magic bytes
- Detection results from 70+ antivirus engines
- Submission history, reputation
- Sandbox verdicts, signatures
- Tags, names, crowdsourced IDS stats

### IPInfo
- Geolocation (city, region, country, coordinates)
- ASN details (number, name, domain, route, type)
- Company information
- Privacy detection (VPN, proxy, Tor, hosting)
- Abuse contact information
- Domains hosted on IP

### AbuseIPDB
- Abuse confidence score (0-100)
- Country, ISP, usage type
- Total reports and distinct reporters
- Detailed abuse reports with categories
- Whitelist status, last reported date

### MalwareBazaar
- File hashes (MD5, SHA1, SHA256)
- File name, size, MIME type
- Malware signature (family name)
- Origin country, reporter
- First/last seen dates
- Tags, code signing info
- Delivery method, threat intelligence
- VirusTotal link

## 📝 About MalwareBazaar API

MalwareBazaar uses **POST requests** instead of GET. The wget command you provided:

```bash
wget --header "Auth-Key: YOUR-AUTH-KEY-HERE" \
     --post-data "query=get_info&hash=094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d" \
     https://mb-api.abuse.ch/api/v1/ -O-
```

Translates to this Python code (already implemented in `main.py`):

```python
headers = {"Auth-Key": "YOUR-AUTH-KEY-HERE"}
data = {
    "query": "get_info",
    "hash": "094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d"
}
response = requests.post("https://mb-api.abuse.ch/api/v1/", headers=headers, data=data)
```

## 🎯 Project Structure

```
test proj/
├── .env                    # API keys (not committed to git)
├── requirements.txt        # Python dependencies
├── main.py                # Main script with all API integrations
└── README.md              # This file
```

## ⚠️ Important Notes

- **Keep `.env` file secure** - Never commit API keys to version control
- **Rate limits** - Each API has different rate limits, check their documentation
- **Free tier limitations** - Some APIs have feature restrictions on free plans
- **API key security** - Use environment variables in production environments

## 📄 License

This is a simple tool for educational and security research purposes.
