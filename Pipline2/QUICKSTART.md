# Quick Start Guide

## 🚀 Get Started in 3 Steps

### Step 1: Setup Environment
```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Step 2: Add API Keys
Edit `.env` file and replace placeholders with your actual API keys:
```env
VIRUSTOTAL_API_KEY=your_actual_key_here
IPINFO_API_KEY=your_actual_key_here
ABUSEIPDB_API_KEY=your_actual_key_here
MALWAREBAZAAR_API_KEY=your_actual_key_here
```

### Step 3: Run Analysis
```bash
python main.py
```

## 💡 Quick Examples

### Analyze an IP
```python
from main import SecurityAPIClient
import json

client = SecurityAPIClient()
result = client.analyze_ip('8.8.8.8')
print(json.dumps(result, indent=2))
```

### Analyze a Domain
```python
result = client.analyze_domain('google.com')
print(json.dumps(result, indent=2))
```

### Analyze a File Hash
```python
hash_value = '094fd325049b8a9cf6d3e5ef2a6d4cc6a567d7d49c35f8bb8dd9e3c6acf3d78d'
result = client.analyze_file_hash(hash_value)
print(json.dumps(result, indent=2))
```

## 🔑 Get API Keys

- **VirusTotal**: https://www.virustotal.com/gui/my-apikey
- **IPInfo**: https://ipinfo.io/account/token
- **AbuseIPDB**: https://www.abuseipdb.com/account/api
- **MalwareBazaar**: https://bazaar.abuse.ch/api/

## 📊 What Data You'll Get

- **IP Analysis**: Location, ASN, reputation, abuse reports, privacy detection
- **Domain Analysis**: DNS records, WHOIS, certificates, reputation
- **File Hash Analysis**: Malware signatures, detections, sandbox verdicts

That's it! Simple and powerful. 🎯
