# Recon

This is a Python reconnaissance tool that performs various operations to gather information about a target company:
- Checks the existence of domains and subdomains
- Domains to IP addresses resolution
- DNS enumeration
- WHOIS lookups
- Portscanning
- Captures screenshots of web pages
- CSV output

## Requirements
As wrappers are required for this tool to function properly, make sure to install:
- `nmap`,
- `whois`,
- `gowitness`,
- `chromium` or `google-chrome`

before proceeding.

For Python dependencies (make sure you are in the `/recon/` folder):

    pip install -r ../requirements.txt

## Usage
```shell
Recon - A simple recon tool for domain enumeration and information
gathering

        python3 recon <name> [options]

positional arguments:
  name                  Target company name

options:
  -h, --help            show this help message and exit
  -v, --verbose         Increase output verbosity
  -o OUTPUT, --output OUTPUT
                        Output file name
  -s SCREENSHOT_DIR, --screenshot-dir SCREENSHOT_DIR
                        Directory to save screenshots
  --seclist             Use a SecList for subdomain enumeration
  --icann               Use all tlds from the ICANN instead of a predefined
                        list
  -t THREADS, --threads THREADS
                        Number of threads to use
```
```shell
# Verbosity

python3 recon.py examplecompany -v

# Use all tlds in the ICANN

python3 recon.py examplecompany --icann 

# Use a SecList of the 5000 most common subdomains

python3 recon.py examplecompany --seclist
```

## Project structure

    Recon/
    │
    ├── recon/
    │   ├── recon.py
    │   ├── domain.py
    │   ├── dns_records.py
    │   ├── scan.py
    │   ├── utils.py
    │
    ├── lists/
    │   ├── seclist_top1million_5000.txt
    │   ├── tlds.txt
    |
    ├── results/
    |
    ├── screenshots/
    │
    ├── requirements.txt
    └── README.md

