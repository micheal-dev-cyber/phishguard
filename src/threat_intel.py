import requests
import base64
import os
import time
import requests
import streamlit as st

def get_url_reputation(url):
    """Queries VirusTotal for URL reputation."""
    api_key = st.secrets.get("VT_API_KEY") # Security best practice
    headers = {"x-apikey": api_key}
    # VirusTotal requires base64 encoding of the URL
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        stats = data['data']['attributes']['last_analysis_stats']
        return stats # Returns {'malicious': 0, 'suspicious': 0, ...}
    return None

try:
    import streamlit as st
    VT_API_KEY = st.secrets.get(
        "VIRUSTOTAL_API_KEY", os.getenv("VIRUSTOTAL_API_KEY", "")
    )
except Exception:
    VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")

VT_BASE_URL = "https://www.virustotal.com/api/v3"


def encode_url(url: str) -> str:
    """Encode URL to base64 for VirusTotal API."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def check_url_virustotal(url: str) -> dict:
    """Check a single URL against VirusTotal."""

    if not VT_API_KEY:
        return {
            "url": url,
            "status": "error",
            "error": "VirusTotal API key not configured",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "total_vendors": 0,
            "threat_names": [],
        }

    headers = {
        "x-apikey": VT_API_KEY,
        "Accept": "application/json",
    }

    try:
        # Encode URL
        url_id = encode_url(url)

        # Check if URL already analyzed
        response = requests.get(
            f"{VT_BASE_URL}/urls/{url_id}",
            headers=headers,
            timeout=15
        )

        if response.status_code == 404:
            # URL not in database — submit for analysis
            submit = requests.post(
                f"{VT_BASE_URL}/urls",
                headers=headers,
                data={"url": url},
                timeout=15
            )

            if submit.status_code != 200:
                return {
                    "url": url,
                    "status": "error",
                    "error": f"Submission failed: {submit.status_code}",
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 0,
                    "total_vendors": 0,
                    "threat_names": [],
                }

            # Wait for analysis
            time.sleep(3)

            # Get analysis ID and fetch results
            analysis_id = submit.json().get("data", {}).get("id", "")
            if analysis_id:
                result = requests.get(
                    f"{VT_BASE_URL}/analyses/{analysis_id}",
                    headers=headers,
                    timeout=15
                )
                if result.status_code == 200:
                    data = result.json().get("data", {})
                    stats = data.get("attributes", {}).get("stats", {})
                    return {
                        "url": url,
                        "status": "analyzed",
                        "malicious":     stats.get("malicious", 0),
                        "suspicious":    stats.get("suspicious", 0),
                        "harmless":      stats.get("harmless", 0),
                        "total_vendors": sum(stats.values()),
                        "threat_names":  [],
                    }

        if response.status_code != 200:
            return {
                "url": url,
                "status": "error",
                "error": f"API error: {response.status_code}",
                "malicious": 0,
                "suspicious": 0,
                "harmless": 0,
                "total_vendors": 0,
                "threat_names": [],
            }

        # Parse results
        data  = response.json().get("data", {})
        attrs = data.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        # Get threat names from vendors
        results_by_engine = attrs.get("last_analysis_results", {})
        threat_names = list(set([
            v.get("result", "")
            for v in results_by_engine.values()
            if v.get("category") == "malicious" and v.get("result")
        ]))[:5]  # Top 5 threat names

        malicious  = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        harmless   = stats.get("harmless", 0)
        undetected = stats.get("undetected", 0)
        total      = malicious + suspicious + harmless + undetected

        # Determine threat level
        if malicious >= 5:
            status = "malicious"
        elif malicious >= 1 or suspicious >= 3:
            status = "suspicious"
        else:
            status = "clean"

        return {
            "url":           url,
            "status":        status,
            "malicious":     malicious,
            "suspicious":    suspicious,
            "harmless":      harmless,
            "total_vendors": total,
            "threat_names":  threat_names,
            "vt_link":       f"https://www.virustotal.com/gui/url/{encode_url(url)}",
        }

    except requests.exceptions.Timeout:
        return {
            "url": url,
            "status": "error",
            "error": "Request timed out",
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "total_vendors": 0,
            "threat_names": [],
        }
    except Exception as e:
        return {
            "url": url,
            "status": "error",
            "error": str(e),
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "total_vendors": 0,
            "threat_names": [],
        }


def check_multiple_urls(urls: list, max_urls: int = 5) -> list:
    """Check multiple URLs — limit to 5 to stay within free API limits."""
    results = []
    for url in urls[:max_urls]:
        result = check_url_virustotal(url)
        results.append(result)
        time.sleep(1)  # Respect rate limits
    return results


def get_threat_summary(vt_results: list) -> dict:
    """Summarize threat intelligence results."""
    total_malicious  = sum(r.get("malicious", 0)  for r in vt_results)
    total_suspicious = sum(r.get("suspicious", 0) for r in vt_results)
    confirmed_threats = [r for r in vt_results if r.get("status") == "malicious"]
    suspicious_urls   = [r for r in vt_results if r.get("status") == "suspicious"]

    return {
        "total_malicious":  total_malicious,
        "total_suspicious": total_suspicious,
        "confirmed_threats": confirmed_threats,
        "suspicious_urls":   suspicious_urls,
        "clean_urls": [r for r in vt_results if r.get("status") == "clean"],
        "has_threats": total_malicious > 0 or total_suspicious > 0,
    }