import requests
import os

def lookup_cve(cve_id: str) -> dict:
    """Verify a CVE ID against NVD and get CVSS score."""
    api_key = os.getenv("NVD_API_KEY", "")
    headers = {"apiKey": api_key} if api_key else {}
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        r = requests.get(url, headers=headers, timeout=10)
        data = r.json()
        if not data.get("vulnerabilities"):
            return {"verified": False, "cve_id": cve_id}
        vuln = data["vulnerabilities"][0]["cve"]
        metrics = vuln.get("metrics", {})
        cvss_score = None
        if "cvssMetricV31" in metrics:
            cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
        elif "cvssMetricV30" in metrics:
            cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
        return {
            "verified":    True,
            "cve_id":      cve_id,
            "cvss_score":  cvss_score,
            "description": vuln["descriptions"][0]["value"][:300]
        }
    except Exception as e:
        return {"verified": False, "cve_id": cve_id, "error": str(e)}


def search_cves_by_keyword(keyword: str, severity: str = "CRITICAL") -> list:
    """Search NVD for CVEs matching a keyword."""
    api_key = os.getenv("NVD_API_KEY", "")
    headers = {"apiKey": api_key} if api_key else {}
    url = (f"https://services.nvd.nist.gov/rest/json/cves/2.0"
           f"?keywordSearch={keyword}&cvssV3Severity={severity}&resultsPerPage=5")
    try:
        r = requests.get(url, headers=headers, timeout=10)
        data = r.json()
        results = []
        for v in data.get("vulnerabilities", []):
            cve = v["cve"]
            results.append({
                "cve_id":      cve["id"],
                "description": cve["descriptions"][0]["value"][:200]
            })
        return results
    except Exception:
        return []
