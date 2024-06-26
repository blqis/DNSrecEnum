import asyncio
import dns.asyncresolver
from utils import log

DNS_RECORDS = ['A', 'AAAA', 'AFSDB', 'APL', 'CAA', 'CDNSKEY', 'CDS', 'CERT',
               'CNAME', 'CSYNC', 'DHCID', 'DLV', 'DNAME', 'DNSKEY', 'DS', 'EUI48',
               'EUI64', 'HINFO', 'HIP', 'HTTPS', 'IPSECKEY', 'KEY', 'KX', 'LOC', 'MX',
               'NAPTR', 'NS', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'OPENPGPKEY', 'PTR', 'RP',
               'RRSIG', 'SIG', 'SMIMEA', 'SOA', 'SRV', 'SSHFP', 'SVCB', 'TA', 'TKEY',
               'TLSA', 'TSIG', 'TXT', 'URI', 'ZONEMD']

# Fetches DNS records for a domain
async def get_dns_records(domain, verbose):
    records = {}
    resolver = dns.asyncresolver.Resolver()

    async def fetch_records(record_type):
        try:
            answers = await resolver.resolve(domain, record_type)
            records[record_type] = [answer.to_text() for answer in answers]
            if verbose:
                log(f"Retrieved {record_type} records for domain {domain}: {records[record_type]}", "debug")
        except:
            records[record_type] = []
            # if verbose:
            #     log(f"No {record_type} records found for domain {domain}", "warning")

    await asyncio.gather(*[fetch_records(rt) for rt in DNS_RECORDS])
    return records
