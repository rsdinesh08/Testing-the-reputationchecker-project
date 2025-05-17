import base64
import requests
import time
import whois
from urllib.parse import urlparse

# Replace these placeholders with your actual API keys
VIRUSTOTAL_API_KEY = "6bc5b0dbfafd846382a830e08811377ad8f0eb567ceb5a2fe52548660b29a923"
URLSCAN_API_KEY = "0b9c5508-baae-4c81-bf80-98f3447d0116"
ALIENVAULT_OTX_API_KEY = "da53f09bf18c70e54e524f25734d038e1d4337d9febb0cce7d6e3047c2b06afa"
GOOGLE_SAFE_BROWSING_API_KEY = "AIzaSyC7lehwhPJjPL5_4xN54jFSxLMTP6L-Y-I"


# Function to check URL reputation with Google Safe Browsing
def check_google_safe_browsing(url: str):
    api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
    payload = {
        "client": {
            "clientId": "yourcompanyname",
            "clientVersion": "1.0"
        },
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
        if response.status_code == 200:
            data = response.json()
            if "matches" in data:
                return "Google Safe Browsing flagged this URL as malicious"
            else:
                return "Google Safe Browsing did not flag this URL as malicious"
        else:
            return f"Error checking Google Safe Browsing: {response.status_code}"
    except requests.exceptions.RequestException as e:
        return f"Error checking Google Safe Browsing: {e}"


# Function to perform WHOIS lookup and return domain details
def check_whois_lookup(domain: str):
    try:
        domain_info = whois.whois(domain)
        if domain_info:
            whois_data = {
                "Domain Name": domain_info.domain_name or "N/A",
                "Registrar": domain_info.registrar or "N/A",
                "Creation Date": domain_info.creation_date or "N/A",
                "Expiration Date": domain_info.expiration_date or "N/A",
                "Updated Date": domain_info.last_updated or "N/A",
                "Name Servers": ", ".join(domain_info.name_servers) if domain_info.name_servers else "N/A"
            }
            return whois_data
        else:
            return {
                "error": "No WHOIS information available for this domain"
            }
    except Exception as e:
        return {
            "error": f"Error performing WHOIS lookup: {e}"
        }


# Function to check VirusTotal for the reputation of the URL
def check_virustotal(url: str):
    api_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        response = requests.get(f"{api_url}/{encoded_url}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            if data['data']['attributes']['last_analysis_stats']['malicious'] > 0:
                return "VirusTotal flagged this URL as malicious"
            else:
                return "VirusTotal did not flag this URL as malicious"
        else:
            return f"Error checking VirusTotal: {response.status_code}"
    except requests.exceptions.RequestException as e:
        return f"Error checking VirusTotal: {e}"


# Function to scan URL with URLScan.io and check its reputation
def check_urlscan_io(url: str):
    api_url = "https://urlscan.io/api/v1/scan/"
    headers = {
        "API-Key": URLSCAN_API_KEY
    }
    payload = {
        "url": url,
        "visibility": "public"
    }
    try:
        response = requests.post(api_url, headers=headers, json=payload)
        if response.status_code == 200:
            data = response.json()
            scan_uuid = data.get('uuid')
            time.sleep(10)  # Wait for the scan to complete
            result_response = requests.get(f"https://urlscan.io/api/v1/result/{scan_uuid}/")
            if result_response.status_code == 200:
                result_data = result_response.json()
                if result_data['verdicts']['overall']['malicious']:
                    return "URLScan.io flagged this URL as malicious"
                else:
                    return "URLScan.io did not flag this URL as malicious"
            else:
                return f"Error retrieving URLScan.io result: {result_response.status_code}"
        else:
            return f"Error initiating URLScan.io scan: {response.status_code}"
    except requests.exceptions.RequestException as e:
        return f"Error with URLScan.io: {e}"


# Function to check AlienVault OTX for the domain reputation
def check_alienvault_otx(domain: str):
    api_url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list"
    headers = {
        "X-OTX-API-KEY": ALIENVAULT_OTX_API_KEY
    }
    try:
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            data = response.json().get("url_list", [])
            if data:
                return data
            else:
                return "No URLs found in AlienVault OTX for this domain"
        else:
            return f"Error checking AlienVault OTX: {response.status_code}"
    except requests.exceptions.RequestException as e:
        return f"Error checking AlienVault OTX: {e}"


# Main function to check the reputation for the given URL
def check_reputation(url: str):
    domain = urlparse(url).hostname
    results = {}
    results['Google Safe Browsing'] = check_google_safe_browsing(url)
    results['WHOIS Lookup'] = check_whois_lookup(domain)
    results['VirusTotal'] = check_virustotal(url)
    results['URLScan.io'] = check_urlscan_io(url)
    results['AlienVault OTX'] = check_alienvault_otx(domain)
    return results

