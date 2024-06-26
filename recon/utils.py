from datetime import datetime
from colorama import Fore, Style, init
import whois
import csv
import subprocess
import os
import importlib.metadata

init(autoreset=True)

# Color-coded logging
def log(message, level="info"):
    colors = {
        "info": Fore.BLUE,
        "success": Fore.GREEN,
        "warning": Fore.YELLOW,
        "error": Fore.RED,
        "debug": Fore.CYAN
    }
    if level != "success":
        print(f"{colors.get(level, Fore.WHITE)}{message}{Style.RESET_ALL}")
    else:
        print(f"\n{colors.get(level, Fore.WHITE)}{message}{Style.RESET_ALL}\n")

# WHOIS wrapper
def search_whois(domain, verbose):
    try:
        w = whois.query(domain)
        if verbose:
            log(f"WHOIS information for {domain}: {w.__dict__}", "success")
        return w.__dict__
    except Exception as e:
        if verbose:
            log(f"WHOIS search failed for {domain}: {e}", "error")
        return {}

# GOWITNESS to capture screenshots of web services
def capture_screenshot(url, output_path):
    try:
        result = subprocess.run(['gowitness', 'single', url, '-o', output_path, '--screenshot-path', os_path_join("screenshots/"), '--disable-db'], capture_output=True, text=True, check=True)
        log(f"Captured screenshot for {url} saved to {output_path}", "success")
    except subprocess.CalledProcessError as e:
        log(f"Failed to capture screenshot for {url}: {e}", "error")
        log(f"Make sure to install Gowitness.\n")

# Results saved to a formatted CSV file
def save_results(results, output):
    nl = '\n'
    with open(output, "w", newline="") as csvfile:
        fieldnames = ["FQDN", "IP Address", "Open Ports", "DNS Records", "WHOIS Info", "Screenshot"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow({
                "FQDN": result[0],
                "IP Address": result[1],
                "Open Ports": ',\n'.join([f"{port}:{details['name']}" for port, details in result[2].items()]),
                "DNS Records": ',\n\n'.join([f"{record}:{',' + nl.join(values)}" for record, values in result[3].items()]),
                "WHOIS Info": ',\n'.join([f"{key}:{value}" for key, value in result[4].items()]) if result[4] else '',
                "Screenshot": result[5]
            })
    log(f"Results saved to {output}", "success")

# Error handling for missing dependencies and tools
def check_dependencies():
    requirements_file = os_path_join("requirements.txt")
    if not os.path.isfile(requirements_file):
        log(f"Requirements file not found at {requirements_file}", "error")
        exit(1)

    with open(requirements_file, 'r') as f:
        required_packages = f.read().splitlines()

    for package in required_packages:
        package_name = package.split('==')[0]
        try:
            importlib.metadata.version(package_name)
        except importlib.metadata.PackageNotFoundError:
            log(f"Required package '{package_name}' is not installed.", "error")
            log(f"Make sure to install {package_name}.", "info")
            exit(1)
        except importlib.metadata.VersionConflict:
            log(f"Version conflict for package '{package_name}'.", "error")
            exit(1)

    try:
        whois.query("google.com")
    except Exception as e:
        log(f"Whois lookup failed: {e}", "error")
        log("Make sure to install the 'python-whois-extended' package, as well as the 'whois' command.", "info")
        exit(1)
    
    try:
        subprocess.run(['gowitness', 'version'], capture_output=True, check=True)
    except subprocess.CalledProcessError as e:
        log("Gowitness is not installed or not in the PATH environment variable.", "error")
        log("Make sure to install Gowitness.", "info")
        exit(1)
    except ModuleNotFoundError:
        log("Some modules may not be installed.", "error")
        log("Make sure to run 'pip install -r ../requirements.txt'", "info")
        exit(1)

    try:
        subprocess.run(['nmap', '--version'], capture_output=True, check=True)
    except subprocess.CalledProcessError as e:
        log("Nmap is not installed or not in the PATH environment variable.", "error")
        log("Make sure to install Nmap.", "info")
        exit(1)

# Utility functions
def os_path_join(dirname, *args):
    return os.path.join(os.path.dirname(__file__), '..', dirname, *args)

def is_directory(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)
