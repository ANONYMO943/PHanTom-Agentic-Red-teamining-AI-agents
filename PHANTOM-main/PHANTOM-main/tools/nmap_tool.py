import socket

def run_nmap(target: str, ports: str = "22,80,443,5432,8080,8443,3306,5000") -> dict:
    """Scan open ports — uses nmap if installed, falls back to socket scan."""
    try:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(hosts=target, ports=ports, arguments="-sV --version-intensity 3")
        results = {"target": target, "open_ports": [], "scanner": "nmap"}
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                for port in nm[host][proto].keys():
                    port_data = nm[host][proto][port]
                    if port_data["state"] == "open":
                        results["open_ports"].append({
                            "port":    int(port),
                            "service": port_data.get("name", "unknown"),
                            "version": port_data.get("version", ""),
                            "product": port_data.get("product", ""),
                            "state":   "open"
                        })
        return results
    except Exception as e:
        print(f"[RECON] nmap unavailable ({e}) — using socket fallback")
        return _socket_scan(target, ports)


def _socket_scan(target: str, ports: str) -> dict:
    """Fallback: simple socket-based port scanner."""
    SERVICE_MAP = {
        22: "ssh", 80: "http", 443: "https", 3306: "mysql",
        5432: "postgresql", 8080: "http-alt", 8443: "https-alt",
        5000: "http", 3000: "http", 6379: "redis", 27017: "mongodb"
    }
    port_list = [int(p.strip()) for p in ports.split(",")]
    open_ports = []
    for port in port_list:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((target, port))
            sock.close()
            if result == 0:
                open_ports.append({
                    "port":    port,
                    "service": SERVICE_MAP.get(port, "unknown"),
                    "version": "",
                    "product": "",
                    "state":   "open"
                })
        except Exception:
            pass
    return {"target": target, "open_ports": open_ports, "scanner": "socket"}
