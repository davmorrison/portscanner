import argparse
import concurrent.futures
import ipaddress
import os
import socket
import ssl
import sys
import time
from datetime import datetime

try:
    from scapy.all import IP, TCP, sr1, conf as scapy_conf
    scapy_conf.verb = 0
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

COMMON_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 79, 80, 81, 88, 110, 111, 113, 119, 123,
    135, 137, 138, 139, 143, 161, 162, 179, 194, 201, 264, 389, 443, 444,
    445, 465, 500, 502, 512, 513, 514, 515, 520, 523, 548, 554, 587, 591,
    593, 631, 636, 646, 691, 860, 873, 902, 989, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1080, 1099, 1177, 1194, 1234, 1241, 1311, 1337, 1352,
    1433, 1434, 1494, 1500, 1521, 1701, 1723, 1725, 1741, 1755, 1812, 1813,
    1863, 1900, 1935, 2000, 2001, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
    2100, 2181, 2222, 2375, 2376, 2483, 2484, 2601, 2604, 3000, 3001, 3128,
    3260, 3268, 3269, 3283, 3306, 3307, 3389, 3690, 3703, 4000, 4045, 4111,
    4443, 4444, 4500, 4567, 4664, 4712, 4899, 5000, 5001, 5009, 5051, 5060,
    5061, 5093, 5222, 5269, 5351, 5353, 5355, 5357, 5432, 5555, 5601, 5631,
    5632, 5666, 5672, 5800, 5900, 5901, 5984, 5985, 5986, 6000, 6001, 6379,
    6443, 6588, 6646, 6665, 6666, 6667, 6668, 6669, 6679, 6697, 6881, 6969,
    7000, 7001, 7070, 7077, 7099, 7100, 7199, 7443, 7474, 7547, 7657, 7777,
    7778, 8000, 8008, 8009, 8010, 8020, 8060, 8080, 8081, 8086, 8087, 8088,
    8089, 8090, 8091, 8095, 8118, 8123, 8140, 8161, 8181, 8200, 8222, 8280,
    8300, 8333, 8383, 8443, 8500, 8530, 8531, 8554, 8649, 8686, 8765, 8834,
    8880, 8888, 8899, 9000, 9001, 9002, 9042, 9050, 9080, 9090, 9091, 9100,
    9200, 9300, 9418, 9443, 9999, 10000, 10050, 10051, 10250, 10255, 11211,
    11371, 12345, 13720, 14000, 15672, 16992, 16993, 17185, 18080, 19150,
    20000, 22222, 23023, 23423, 24800, 25565, 27017, 27018, 27019, 28017,
    30000, 32400, 32768, 33060, 33389, 37777, 44818, 47808, 49152, 50000,
    50070, 54321, 55553, 60000, 61616,
]

FALLBACK_SERVICES = {
    1433: "ms-sql-s", 1521: "oracle", 3000: "ppp/dev", 3306: "mysql",
    3389: "ms-wbt-server", 5000: "upnp/http-alt", 5432: "postgresql",
    5900: "vnc", 5985: "wsman-http", 5986: "wsman-https", 6379: "redis",
    6443: "kubernetes-api", 7000: "afs3-fileserver", 8000: "http-alt",
    8008: "http-alt", 8080: "http-proxy", 8081: "http-alt",
    8086: "influxdb", 8443: "https-alt", 8888: "http-alt", 9000: "cslistener",
    9042: "cassandra", 9090: "zeus-admin", 9092: "kafka", 9200: "elasticsearch",
    9300: "elasticsearch-cluster", 11211: "memcached", 15672: "rabbitmq-mgmt",
    25565: "minecraft", 27017: "mongodb", 32400: "plex",
}

HTTP_LIKE_PORTS = {80, 81, 443, 591, 3000, 5000, 8000, 8008, 8009, 8080,
                    8081, 8086, 8088, 8090, 8443, 8880, 8888, 9000, 9090}

LOCK_PRINT = None  # set in main() to a threading.Lock for tidy concurrent prints

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def c(text, color, use_color=True):
    """Wrap text in an ANSI color code if colors are enabled."""
    if not use_color:
        return text
    codes = {
        "green": "\033[92m", "red": "\033[91m", "yellow": "\033[93m",
        "cyan": "\033[96m", "bold": "\033[1m", "reset": "\033[0m",
    }
    return f"{codes.get(color, '')}{text}{codes['reset']}"


def parse_ports(spec, top_n=None):
    """Parse a port spec like '22,80,443' or '1-1000' or '20-25,80,8000-8100'.
    If spec is None, fall back to COMMON_PORTS (optionally trimmed to top_n).
    """
    if spec is None:
        ports = COMMON_PORTS if top_n is None else COMMON_PORTS[:top_n]
        return sorted(set(ports))

    ports = set()
    for chunk in spec.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start, end = chunk.split("-", 1)
            start, end = int(start), int(end)
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            ports.add(int(chunk))

    bad = [p for p in ports if p < 1 or p > 65535]
    if bad:
        raise ValueError(f"Invalid port(s): {bad[:5]}{'...' if len(bad) > 5 else ''}")
    return sorted(ports)


def resolve_target(target):
    """Resolve a hostname to an IP. Raises socket.gaierror on failure."""
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        return socket.gethostbyname(target)


def service_name(port):
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return FALLBACK_SERVICES.get(port, "unknown")


def grab_banner(ip, port, timeout):
    """Best-effort service banner grab. Returns a short string or None."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))

            # TLS ports: try to pull the certificate's common name / issuer.
            if port in (443, 8443, 465, 993, 995, 636):
                try:
                    ctx = ssl.create_default_context()
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                    with ctx.wrap_socket(s, server_hostname=ip) as tls:
                        cert = tls.getpeercert(binary_form=False) or {}
                        subj = dict(x[0] for x in cert.get("subject", []))
                        cn = subj.get("commonName")
                        if cn:
                            return f"TLS cert CN={cn}"
                        return "TLS/SSL service"
                except Exception:
                    pass  # fall through to plain grab attempt below

            # HTTP-ish ports: send a minimal request and read the status line.
            if port in HTTP_LIKE_PORTS:
                try:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    s.settimeout(min(timeout, 2))
                    data = s.recv(2048)
                    if data:
                        first_line = data.split(b"\r\n", 1)[0].decode(errors="replace")
                        server_hdr = ""
                        for line in data.decode(errors="replace").split("\r\n"):
                            if line.lower().startswith("server:"):
                                server_hdr = " " + line.split(":", 1)[1].strip()
                                break
                        return f"{first_line}{server_hdr}"
                except Exception:
                    pass

            # Generic: many services (SSH, FTP, SMTP, POP3, IMAP...) send a
            # banner immediately on connect without any prompt needed.
            try:
                s.settimeout(min(timeout, 2))
                data = s.recv(1024)
                if data:
                    return data.decode(errors="replace").strip().split("\n")[0][:120]
            except socket.timeout:
                return None
    except Exception:
        return None
    return None


# --------------------------------------------------------------------------
# Scan engines
# --------------------------------------------------------------------------

def connect_scan_port(ip, port, timeout, want_banner):
    """TCP connect scan for a single port. Returns (port, state, banner)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                banner = grab_banner(ip, port, timeout) if want_banner else None
                return port, "open", banner
            else:
                return port, "closed", None
    except socket.timeout:
        return port, "filtered", None
    except OSError:
        return port, "filtered", None


def syn_scan_port(ip, port, timeout, want_banner):
    """TCP SYN (half-open) scan for a single port using scapy.
    Returns (port, state, banner).
    """
    src_port = None
    try:
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        resp = sr1(pkt, timeout=timeout, verbose=0)

        if resp is None:
            return port, "filtered", None

        if resp.haslayer(TCP):
            flags = resp.getlayer(TCP).flags
            if flags & 0x12 == 0x12:  # SYN+ACK
                # Politely tear down the half-open connection.
                rst = IP(dst=ip) / TCP(dport=port, flags="R",
                                        seq=resp.getlayer(TCP).ack)
                sr1(rst, timeout=1, verbose=0)
                banner = grab_banner(ip, port, timeout) if want_banner else None
                return port, "open", banner
            elif flags & 0x14 == 0x14:  # RST+ACK
                return port, "closed", None

        return port, "filtered", None
    except Exception:
        return port, "filtered", None


# --------------------------------------------------------------------------
# Main scan orchestration
# --------------------------------------------------------------------------

def run_scan(ip, ports, scan_types, timeout, threads, want_banner, use_color, quiet=False):
    results = {}  # port -> {"state": ..., "banner": ..., "via": [scan types that saw it open]}

    for scan_type in scan_types:
        engine = connect_scan_port if scan_type == "connect" else syn_scan_port
        label = "TCP Connect" if scan_type == "connect" else "SYN"

        if not quiet:
            print(c(f"\nRunning {label} scan on {len(ports)} ports...", "cyan", use_color))

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as pool:
            futures = {
                pool.submit(engine, ip, port, timeout, want_banner): port
                for port in ports
            }
            for fut in concurrent.futures.as_completed(futures):
                port, state, banner = fut.result()
                existing = results.get(port)
                if existing is None:
                    results[port] = {"state": state, "banner": banner, "via": [label]}
                else:
                    # If any scan type says "open", prefer that result.
                    if state == "open" or existing["state"] != "open":
                        if state == "open":
                            existing["state"] = "open"
                            existing["banner"] = existing["banner"] or banner
                    existing["via"].append(label)

    return results


def print_results(ip, target_label, results, elapsed, use_color, out_file=None):
    lines = []

    def emit(s=""):
        lines.append(s)
        print(s)

    emit(c(f"\nScan report for {target_label} ({ip})", "bold", use_color))
    emit("-" * 60)

    open_ports = sorted(p for p, r in results.items() if r["state"] == "open")
    closed_ports = [p for p, r in results.items() if r["state"] == "closed"]
    filtered_ports = [p for p, r in results.items() if r["state"] == "filtered"]

    if open_ports:
        emit(f"{'PORT':<10}{'STATE':<12}{'SERVICE':<16}{'BANNER / VERSION'}")
        for port in open_ports:
            r = results[port]
            state_str = c("open", "green", use_color)
            svc = service_name(port)
            banner = r["banner"] or ""
            emit(f"{str(port) + '/tcp':<10}{state_str:<{12 + (len(state_str)-4) if use_color else 12}}{svc:<16}{banner}")
    else:
        emit("No open ports found among the ports scanned.")

    emit("")
    emit(
        f"Summary: {c(str(len(open_ports)) + ' open', 'green', use_color)}, "
        f"{c(str(len(closed_ports)) + ' closed', 'red', use_color)}, "
        f"{c(str(len(filtered_ports)) + ' filtered', 'yellow', use_color)} "
        f"({len(results)} scanned)"
    )
    emit(f"Scan completed in {elapsed:.2f} seconds.")

    if out_file:
        with open(out_file, "w") as f:
            f.write("\n".join(_strip_ansi(l) for l in lines) + "\n")
        print(f"\nResults written to {out_file}")


def _strip_ansi(s):
    import re
    return re.sub(r"\033\[[0-9;]*m", "", s)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="portscan",
        description="A single-file, nmap-inspired TCP port scanner. "
                     "For authorized use on systems you own or have permission to test.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(__doc__.split("Usage")[1] if __doc__ and "Usage" in __doc__ else None),
    )
    p.add_argument("target", help="IP address, hostname, or CIDR (e.g. 10.0.0.0/24) to scan")
    p.add_argument("-p", "--ports", dest="ports",
                    help="Ports to scan, e.g. '22,80,443' or '1-1000'. "
                         "Default: curated common-ports list.")
    p.add_argument("--top-ports", type=int, default=None,
                    help="Scan only the top N ports from the built-in common list.")

    scan_group = p.add_mutually_exclusive_group()
    scan_group.add_argument("-sT", "--connect", action="store_true",
                             help="TCP Connect scan (default; no privileges required).")
    scan_group.add_argument("-sS", "--syn", action="store_true",
                             help="TCP SYN scan (requires root/admin + scapy).")
    scan_group.add_argument("--both", action="store_true",
                             help="Run both Connect and SYN scans.")

    p.add_argument("-sV", "--banner", dest="banner", action="store_true", default=True,
                    help="Grab service banners on open ports (default: on).")
    p.add_argument("--no-banner", dest="banner", action="store_false",
                    help="Disable banner grabbing (faster).")

    p.add_argument("-T", "--threads", type=int, default=100,
                    help="Number of concurrent worker threads (default: 100).")
    p.add_argument("--timeout", type=float, default=1.0,
                    help="Per-port timeout in seconds (default: 1.0).")
    p.add_argument("-oN", "--output", metavar="FILE",
                    help="Write plain-text results to FILE.")
    p.add_argument("--no-color", action="store_true", help="Disable colored output.")
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress progress messages.")

    return p


def main():
    args = build_parser().parse_args()
    use_color = (not args.no_color) and sys.stdout.isatty()

    # Determine which scan type(s) to run.
    scan_types = []
    if args.both:
        scan_types = ["connect", "syn"]
    elif args.syn:
        scan_types = ["syn"]
    else:
        scan_types = ["connect"]  # default

    if "syn" in scan_types:
        is_root = hasattr(os, "geteuid") and os.geteuid() == 0
        if not SCAPY_AVAILABLE:
            print(c("Warning: scapy is not installed, so SYN scanning is unavailable.", "yellow", use_color))
            print("  Install it with:  pip install scapy")
            scan_types = [t for t in scan_types if t != "syn"]
            if not scan_types:
                scan_types = ["connect"]
            print("Falling back to TCP Connect scan.\n")
        elif not is_root:
            print(c("Warning: SYN scanning requires root/administrator privileges.", "yellow", use_color))
            scan_types = [t for t in scan_types if t != "syn"]
            if not scan_types:
                scan_types = ["connect"]
            print("Falling back to TCP Connect scan.\n")

    try:
        ip = resolve_target(args.target)
    except socket.gaierror:
        print(c(f"Error: could not resolve target '{args.target}'", "red", use_color))
        sys.exit(1)

    try:
        ports = parse_ports(args.ports, args.top_ports)
    except ValueError as e:
        print(c(f"Error: {e}", "red", use_color))
        sys.exit(1)

    if not args.quiet:
        print(c(f"Starting portscan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "bold", use_color))
        print(f"Target: {args.target} ({ip})  |  Ports: {len(ports)}  |  "
              f"Scan type(s): {', '.join(scan_types)}  |  Banner grab: {args.banner}")

    start = time.time()
    results = run_scan(
        ip=ip,
        ports=ports,
        scan_types=scan_types,
        timeout=args.timeout,
        threads=args.threads,
        want_banner=args.banner,
        use_color=use_color,
        quiet=args.quiet,
    )
    elapsed = time.time() - start

    print_results(ip, args.target, results, elapsed, use_color, args.output)


if __name__ == "__main__":
    main()
