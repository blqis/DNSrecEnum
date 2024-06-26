import asyncio
import concurrent.futures
import argparse
from datetime import datetime
import time
import os
from domain import check_domain_existence, resolve_domain, query_subdomains
from dns_records import get_dns_records
from scan import scan_ports
from utils import capture_screenshot, log, save_results, search_whois, check_dependencies, os_path_join


async def main(name, verbose, output, screenshot_dir=None, seclist=False, ICANN=False, threads=100):
    time_start = time.time()
    date_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    log(f"\nStarting recon for {name}...\n", "info")

    results = []

    if ICANN:
        with open(os_path_join("lists", "tlds.txt"), "r") as f:
            TLDS = f.read().splitlines()
    else:
        TLDS = ["com", "org", "net", "fr", "de", "uk", "cn", "ru", "jp", "br"]

    loop = asyncio.get_event_loop()
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        try:
            # For each TLD, check domain existence, resolve IPs, get DNS records, search WHOIS info, and query subdomains
            for tld in TLDS:
                domain = f"{name}.{tld}"
                if await check_domain_existence(domain, verbose):
                    ips = await resolve_domain(domain, verbose)
                    dns_records = await get_dns_records(domain, verbose)
                    whois_info = search_whois(domain, verbose)

                    subdomains = await query_subdomains(domain, verbose, seclist)
                    for subdomain in subdomains:
                        sub_ips = await resolve_domain(subdomain, verbose)
                        sub_dns_records = await get_dns_records(subdomain, verbose)
                        ips.extend(sub_ips)
                        for record in sub_dns_records:
                            dns_records[record].extend(sub_dns_records[record])

                    # Scan open ports and capture screenshots for web services accordingly
                    ip_tasks = [loop.run_in_executor(executor, scan_ports, ip, verbose) for ip in set(ips)]
                    scan_results = await asyncio.gather(*ip_tasks)

                    for ip, scan_result in zip(set(ips), scan_results):
                        if scan_result:
                            open_ports = {port: details for port, details in scan_result['tcp'].items() if details['state'] == 'open'}
                            if screenshot_dir != None:
                                screenshot_path = os_path_join(screenshot_dir, f"{domain}_{ip}_{date_str}.png")
                            else:
                                screenshot_path = os_path_join("screenshots", f"{domain}_{ip}_{date_str}.png")
                            if 80 in open_ports:
                                loop.run_in_executor(executor, capture_screenshot, f"http://{domain}", screenshot_path)
                            if 443 in open_ports:
                                loop.run_in_executor(executor, capture_screenshot, f"https://{domain}", screenshot_path)

                            # Remove empty DNS records
                            dns_records = {record: values for record, values in dns_records.items() if values}
                            
                            results.append([domain, ip, open_ports, dns_records, whois_info, screenshot_path])

        except KeyboardInterrupt:
            log("Process interrupted by user", "error")
            log(f"Recon interrupted after {time.time() - time_start:.2f} seconds")
            quit()

        except FileNotFoundError as e:
            log(f"File not found: {e}", "error")
            log("There seems to be a missing dependency.", "info")
            quit()

    output_file = output or os_path_join("results", f"{name}_{date_str}.csv")
    save_results(results, output_file)
    time_end = time.time()
    log(f"Recon finished in {time_end - time_start:.2f} seconds", "success")


# Option parsing and error handling
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recon - A simple recon tool for domain enumeration and information gathering")
    parser.add_argument("name", type=str, help="Target company name")
    parser.add_argument("-v", "--verbose", action="store_true", help="Increase output verbosity")
    parser.add_argument("-o", "--output", type=str, help="Output file name")
    parser.add_argument("-s", "--screenshot-dir", type=str, help="Directory to save screenshots")
    parser.add_argument("--seclist", action="store_true", help="Use a SecList for subdomain enumeration")
    parser.add_argument("--icann", action="store_true", help="Use all tlds from the ICANN instead of a predefined list")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads to use")

    args = parser.parse_args()

    check_dependencies()

    try:
        asyncio.run(main(args.name, args.verbose, args.output, args.screenshot_dir, args.seclist, args.icann, args.threads))
    except KeyboardInterrupt:
        log("Process interrupted by user", "error")
