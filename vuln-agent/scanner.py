"""
scanner.py — Network & Host Scanner
Uses Python socket (no nmap required) + PowerShell for Windows OS detection.
"""

import socket
import subprocess
import ipaddress
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime

import config

logger = logging.getLogger(__name__)

# Common service names by port
PORT_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "smb",
    512: "exec", 513: "login", 514: "shell", 587: "smtp-submission",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5900: "vnc",
    6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}


@dataclass
class PortInfo:
    port: int
    service: str
    banner: str = ""
    state: str = "open"


@dataclass
class SoftwareInfo:
    name: str
    version: str
    publisher: str


@dataclass
class ScanResult:
    ip: str
    dns_name: str = ""
    os: str = "Unknown"
    open_ports: list[PortInfo] = field(default_factory=list)
    installed_software: list[SoftwareInfo] = field(default_factory=list)
    scan_time: datetime = field(default_factory=datetime.now)
    error: str = ""


def resolve_dns(ip: str) -> str:
    """Reverse DNS lookup for an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return ""


def detect_os_local() -> str:
    """Detect OS on the local machine using PowerShell (Windows)."""
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "$ProgressPreference='SilentlyContinue';"
             "(Get-ComputerInfo | Select-Object -ExpandProperty OsName)"],
            capture_output=True, text=True, timeout=10
        )
        os_name = result.stdout.strip()
        if os_name:
            return os_name
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Fallback: platform module
    import platform
    return f"{platform.system()} {platform.release()}"


def detect_os_ttl(ip: str) -> str:
    """Estimate OS from ping TTL (heuristic, not definitive)."""
    try:
        import platform
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", "1000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
        result = subprocess.run(
            cmd,
            capture_output=True, text=True, timeout=5
        )
        output = result.stdout
        if "TTL=" in output or "ttl=" in output:
            ttl_str = output.lower().split("ttl=")[-1].split()[0].strip()
            ttl = int(ttl_str)
            if ttl <= 64:
                return "Linux/Unix (TTL<=64)"
            elif ttl <= 128:
                return "Windows (TTL<=128)"
            else:
                return "Network Device / Unknown"
    except Exception:
        pass
    return "Unknown"


def get_installed_software(ip: str) -> list[SoftwareInfo]:
    """
    Enumerate installed programs via PowerShell registry query (localhost only).
    Queries both 64-bit and 32-bit uninstall registry hives.
    Returns empty list for remote targets — no credentials available.
    """
    if ip not in ("127.0.0.1", "localhost", "::1"):
        return []

    import json

    ps_cmd = (
        "$keys = @("
        "  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',"
        "  'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'"
        ");"
        "($keys | ForEach-Object { Get-ItemProperty $_ -ErrorAction SilentlyContinue } |"
        " Where-Object { $_.DisplayName } |"
        " Select-Object DisplayName,DisplayVersion,Publisher) | ConvertTo-Json -Compress"
    )

    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=30,
        )
        if not result.stdout.strip():
            return []
        raw = json.loads(result.stdout.strip())
        if isinstance(raw, dict):   # Single entry comes back as dict, not list
            raw = [raw]
        return [
            SoftwareInfo(
                name=(item.get("DisplayName") or "").strip(),
                version=(item.get("DisplayVersion") or "").strip(),
                publisher=(item.get("Publisher") or "").strip(),
            )
            for item in raw
            if (item.get("DisplayName") or "").strip()
        ]
    except Exception as e:
        logger.warning(f"Software inventory failed: {e}")
        return []


def grab_banner(ip: str, port: int) -> str:
    """Attempt to grab a service banner."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(config.BANNER_GRAB_TIMEOUT)
            s.connect((ip, port))
            # Send HTTP probe only on plain HTTP ports — 443/8443 require TLS
            # handshake first; sending raw HTTP bytes gets no response and wastes timeout.
            if port in (80, 8080):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
            return banner[:200]  # Truncate long banners
    except Exception:
        return ""


def scan_port(ip: str, port: int) -> PortInfo | None:
    """Attempt TCP connect to a single port. Returns PortInfo if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(config.CONNECT_TIMEOUT)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = PORT_SERVICES.get(port, f"port-{port}")
                banner = grab_banner(ip, port)
                return PortInfo(port=port, service=service, banner=banner)
    except OSError as e:
        # Log unexpected OS-level errors (e.g. EMFILE: too many open files)
        # so incomplete scans are visible rather than silently returning fewer results.
        logger.warning(f"OS error scanning {ip}:{port}: {e}")
    except Exception:
        pass
    return None


def _refine_os_from_ports(ttl_os: str, open_ports: list[PortInfo]) -> str:
    """
    Refine a TTL-based OS guess using open port fingerprints.
    Windows-specific ports (RPC/SMB/NetBIOS/RDP/WinRM) raise confidence
    and replace the generic TTL label with a more descriptive string.
    Called after port scan completes so port data is available.
    """
    port_nums = {p.port for p in open_ports}

    windows_ports = {135: "RPC", 139: "NetBIOS", 445: "SMB",
                     3389: "RDP", 5985: "WinRM", 5986: "WinRM-SSL"}
    linux_ports   = {22: "SSH", 111: "rpcbind"}

    matched_win = {name for p, name in windows_ports.items() if p in port_nums}
    matched_lin = {name for p, name in linux_ports.items() if p in port_nums}

    if "Windows" in ttl_os and len(matched_win) >= 2:
        services = "/".join(sorted(matched_win))
        return f"Windows ({services} fingerprint)"
    elif "Windows" in ttl_os and matched_win:
        service = next(iter(matched_win))
        return f"Windows ({service} fingerprint)"
    elif "Linux" in ttl_os and matched_lin:
        services = "/".join(sorted(matched_lin))
        return f"Linux/Unix ({services} fingerprint)"

    return ttl_os  # fallback: keep original TTL guess


def scan_target(ip: str) -> ScanResult:
    """Full scan of a single target IP."""
    logger.info(f"Scanning {ip}...")
    result = ScanResult(ip=ip)

    # DNS resolution
    result.dns_name = resolve_dns(ip)

    # OS detection + software inventory
    is_localhost = ip in ("127.0.0.1", "localhost", "::1")
    if is_localhost:
        result.os = detect_os_local()
        result.installed_software = get_installed_software(ip)
        logger.info(f"  {ip}: {len(result.installed_software)} installed programs found")
    else:
        result.os = detect_os_ttl(ip)

    # Port scan — parallel threads for speed (1024 ports in ~3s vs ~17min)
    # Use fewer workers for remote targets to avoid triggering IDS/firewall rules.
    # Loopback (127.0.0.1) traffic bypasses Windows Firewall by design — safe to
    # use more workers there.  Both values are configurable in config.py.
    workers = config.SCAN_WORKERS_LOCAL if is_localhost else config.SCAN_WORKERS_REMOTE
    ports = list(config.SCAN_PORTS)
    logger.info(f"  Scanning {len(ports)} ports in parallel ({workers} workers)...")
    open_ports: list[PortInfo] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in as_completed(futures):
            port_info = future.result()
            if port_info:
                open_ports.append(port_info)
                logger.debug(f"  {ip}:{port_info.port} open ({port_info.service})")

    open_ports.sort(key=lambda p: p.port)  # Sort by port number
    result.open_ports = open_ports

    # Refine remote OS label using discovered ports (more reliable than TTL alone)
    if not is_localhost:
        result.os = _refine_os_from_ports(result.os, open_ports)

    logger.info(f"  {ip}: {len(open_ports)} open ports found")
    return result


def scan_all_targets() -> list[ScanResult]:
    """Scan all targets from config.TARGETS."""
    results = []
    for target in config.TARGETS:
        try:
            # Handle CIDR notation (e.g., 192.168.1.0/24)
            network = ipaddress.ip_network(target, strict=False)
            for host in network.hosts():
                results.append(scan_target(str(host)))
        except ValueError:
            # Not CIDR — treat as single IP/hostname
            results.append(scan_target(target))
    return results


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    print("Running standalone scanner test on localhost...\n")
    result = scan_target("127.0.0.1")
    print(f"IP:       {result.ip}")
    print(f"DNS:      {result.dns_name or '(none)'}")
    print(f"OS:       {result.os}")
    print(f"Open ports ({len(result.open_ports)}):")
    for p in result.open_ports:
        print(f"  {p.port:5d}/tcp  {p.service:<20} {p.banner[:60]!r}")
