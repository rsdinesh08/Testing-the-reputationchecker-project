import base64
import requests
import time
import whois
from urllib.parse import urlparse
import datetime
from bs4 import BeautifulSoup

# API Keys
VIRUSTOTAL_API_KEY = "6bc5b0dbfafd846382a830e08811377ad8f0eb567ceb5a2fe52548660b29a923"
URLSCAN_API_KEY = "0b9c5508-baae-4c81-bf80-98f3447d0116"
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyC7lehwhPJjPL5_4xN54jFSxLMTP6L-Y-I"

# Google Safe Browsing Check
def check_google_safe_browsing(url: str):
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {"clientId": "yourcompanyname", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    params = {"key": GOOGLE_SAFE_BROWSING_API_KEY}
    try:
        response = requests.post(api_url, json=payload, params=params)
        data = response.json()
        if "matches" in data:
            return "Google Safe Browsing flagged this URL as malicious"
        else:
            return "Google Safe Browsing did not flag this URL"
    except Exception as e:
        return f"Error checking Google Safe Browsing: {e}"

# WHOIS Lookup
def check_whois_lookup(domain: str):
    try:
        domain_info = whois.whois(domain)
        return {
            "Domain Name": domain_info.domain_name or "N/A",
            "Registrar": domain_info.registrar or "N/A",
            "Creation Date": domain_info.creation_date or "N/A",
            "Expiration Date": domain_info.expiration_date or "N/A",
            "Updated Date": domain_info.last_updated or "N/A",
            "Name Servers": ", ".join(domain_info.name_servers) if domain_info.name_servers else "N/A"
        }
    except Exception as e:
        return {"error": f"WHOIS lookup failed: {e}"}

# VirusTotal Check (detailed vendors)
def check_virustotal(url: str):
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        response = requests.get(f"{api_url}/{encoded_url}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            total_vendors = sum(stats.values())
            last_analysis_date = datetime.datetime.utcfromtimestamp(
                data['data']['attributes']['last_analysis_date']
            ).strftime('%Y-%m-%d %H:%M:%S')

            malicious = []
            suspicious = []
            for vendor, result in data['data']['attributes']['last_analysis_results'].items():
                if result['category'] == "malicious":
                    malicious.append(f"{vendor}: {result['result']}")
                elif result['category'] == "suspicious":
                    suspicious.append(f"{vendor}: {result['result']}")

            return {
                "VirusTotal - Detection Count": f"{stats['malicious']} Malicious / {total_vendors} Vendors",
                "VirusTotal - Status": data['data']['attributes']['status'],
                "VirusTotal - Malicious Vendors": malicious,
                "VirusTotal - Suspicious Vendors": suspicious,
                "VirusTotal - Validate Link": f"https://www.virustotal.com/gui/url/{encoded_url}/detection"
            }
        else:
            return {"error": f"VirusTotal API error: {response.status_code}"}
    except Exception as e:
        return {"error": f"VirusTotal lookup failed: {e}"}

# URLScan.io Check
def check_urlscan_io(url: str):
    api_url = "https://urlscan.io/api/v1/scan/"
    headers = {"API-Key": URLSCAN_API_KEY}
    payload = {"url": url, "visibility": "public"}
    try:
        response = requests.post(api_url, headers=headers, json=payload)
        if response.status_code == 200:
            data = response.json()
            scan_uuid = data.get('uuid')
            result_url = f"https://urlscan.io/result/{scan_uuid}/"
            time.sleep(10)
            result_response = requests.get(result_url)
            if result_response.status_code == 200:
                result_data = result_response.json()
                screenshot = result_data.get("screenshotURL", "No Screenshot URL")
                return {
                    "URLScan - Result Page": result_url,
                    "URLScan - Screenshot": screenshot
                }
            else:
                return {
                    "URLScan - Result Page": result_url,
                    "URLScan - Screenshot": "No Screenshot URL"
                }
        else:
            return {"URLScan.io Error": f"Status Code: {response.status_code}"}
    except Exception as e:
        return {"URLScan.io Error": str(e)}

# Talos Intelligence Check
def check_talos(domain: str):
    try:
        headers = {
            "User-Agent": "Mozilla/5.0"
        }
        url = f"https://talosintelligence.com/reputation_center/lookup?search={domain}"
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            result_data = {}

            for section in soup.find_all('div', class_='section col-xs-12'):
                title_tag = section.find('div', class_='section-header')
                if not title_tag:
                    continue
                title = title_tag.text.strip().upper()

                content_lines = []
                for row in section.find_all('div', class_='row'):
                    label = row.find('div', class_='section-label')
                    value = row.find('div', class_='section-value')
                    if label and value:
                        content_lines.append(f"{label.text.strip()}: {value.text.strip()}")

                if content_lines:
                    result_data[title] = "\n".join(content_lines)

            result_data["Talos Intelligence - Validate Link"] = url
            return result_data
        else:
            return {"Talos Error": f"HTTP Error {response.status_code}"}
    except Exception as e:
        return {"Talos Error": str(e)}

# Final reputation check
def check_reputation(url: str):
    domain = urlparse(url).hostname
    result = {}

    # Reputation Sources
    result["Google Safe Browsing"] = check_google_safe_browsing(url)
    result["WHOIS Lookup"] = check_whois_lookup(domain)
    
    vt = check_virustotal(url)
    result.update(vt if isinstance(vt, dict) else {"VirusTotal Error": vt})

    us = check_urlscan_io(url)
    result.update(us if isinstance(us, dict) else {"URLScan Error": us})

    talos = check_talos(domain)
    result.update(talos if isinstance(talos, dict) else {"Talos Error": talos})

    return result
