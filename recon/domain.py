import asyncio
import os
import dns.asyncresolver
import aiohttp
from utils import log, os_path_join

# Check if a domain exists by one of its records
async def check_domain_existence(domain, verbose):
    resolver = dns.asyncresolver.Resolver()
    record_types = ['A', 'AAAA', 'CNAME', 'MX']
    
    for record_type in record_types:
        try:
            answers = await resolver.resolve(domain, record_type)
            if verbose:
                log(f"Domain {domain} exists, found {record_type} record: {answers[0].to_text()}", "success")
            return True
        except dns.resolver.NXDOMAIN:
            if verbose:
                log(f"Domain {domain} does not exist (NXDOMAIN)", "warning")
            return False
        except (dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            if verbose:
                log(f"Domain {domain} does not have a {record_type} record", "warning")
            continue
        except dns.resolver.Timeout:
            if verbose:
                log(f"Timeout while checking {domain} for {record_type} record", "warning")
            continue

    if verbose:
        log(f"Domain {domain} does not have any A, AAAA, CNAME, or MX records", "warning")
    return False

# Resolve a domain to its IPs (IPv4)
async def resolve_domain(domain, verbose):
    resolver = dns.asyncresolver.Resolver()
    try:
        answers = await resolver.resolve(domain, 'A')
        ips = [answer.to_text() for answer in answers]
        if verbose:
            log(f"Resolved domain {domain} to IPs: {ips}", "debug")
        return ips
    except:
        if verbose:
            log(f"Failed to resolve domain {domain}", "error")
        return []

# For a given domain, query common subdomains using HTTP GET requests and a SecList
async def query_subdomains(domain, verbose, seclist=False):
    subdomains = []
    async with aiohttp.ClientSession() as session:
        async def fetch(subdomain):
            try:
                async with session.get(f"http://{subdomain}.{domain}") as response:
                    if response.status == 200:
                        subdomains.append(f"{subdomain}.{domain}")
                        if verbose:
                            log(f"Found subdomain: {subdomain}.{domain}", "success")
            except:
                pass

        if seclist:
            with open(os_path_join("lists", "seclist_top1million_5000.txt"), "r") as f:
                subdomains_list = f.read().splitlines()
            await asyncio.gather(*[fetch(sub) for sub in subdomains_list])
        else:
            await asyncio.gather(*[fetch(sub) for sub in ["www", "mail", "ftp", "webmail", "smtp", "remote", "secure", "ns1", "ns2"]])

    return subdomains
