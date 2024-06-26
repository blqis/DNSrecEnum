import nmap
from utils import log

NMAP_TOP_PORTS = "21,22,23,25,80,110,139,443,445,3389"

# Function to scan open ports using NMAP on the 10 most common ports
def scan_ports(ip, verbose):
    try:
        nm = nmap.PortScanner()
        nm.scan(ip, NMAP_TOP_PORTS)
        if verbose:
            open_ports = {port: nm[ip]['tcp'][port]['state'] for port in nm[ip]['tcp'] if nm[ip]['tcp'][port]['state'] == 'open'}
            log(f"Scanned ports for IP {ip}: {open_ports}", "debug")
        return nm[ip] if ip in nm.all_hosts() else None
    except nmap.PortScannerError as e:
        log(f"{e}", "error")
        log("Make sure to install the 'python-nmap' package, as well as the 'nmap' command.", "info")