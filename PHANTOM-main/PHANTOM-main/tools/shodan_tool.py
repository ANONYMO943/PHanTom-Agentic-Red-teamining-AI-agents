"""
Shodan passive intelligence tool.
For localhost/demo targets, returns a realistic mock profile
so the demo always shows passive recon working.
"""
import os


# Mock data for localhost demo — what Shodan would return for a real Flask app
LOCALHOST_PROFILE = {
    "target":      "127.0.0.1",
    "org":         "Demo Environment (Local)",
    "country":     "Local Network",
    "open_ports":  [5000, 80],
    "vulns":       [],
    "hostnames":   ["localhost"],
    "isp":         "Loopback",
    "last_update": "demo-session",
    "ssl_sans":    [],
    "tags":        ["self-signed", "development"],
    "note":        "Local target — passive profile from PHANTOM demo dataset"
}


def query_shodan(target: str) -> dict:
    """Query Shodan for passive intel on target IP."""

    # For localhost/demo targets, return realistic profile
    if target in ("127.0.0.1", "localhost", "0.0.0.0", "::1"):
        return LOCALHOST_PROFILE.copy()

    api_key = os.getenv("SHODAN_API_KEY", "")
    if not api_key or api_key == "your_key_here":
        return {"error": "No Shodan API key set", "target": target}

    try:
        import shodan
        api = shodan.Shodan(api_key)
        host = api.host(target)
        return {
            "target":       target,
            "org":          host.get("org", "unknown"),
            "country":      host.get("country_name", "unknown"),
            "open_ports":   host.get("ports", []),
            "vulns":        list(host.get("vulns", [])),
            "hostnames":    host.get("hostnames", []),
            "isp":          host.get("isp", "unknown"),
            "last_update":  host.get("last_update", ""),
            "ssl_sans":     [],
            "tags":         host.get("tags", []),
        }
    except Exception as e:
        return {"error": str(e), "target": target}
