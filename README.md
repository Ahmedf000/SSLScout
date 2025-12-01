# SSL Scout

SSL/TLS certificate security analyzer tool.

## What It Does
- Checks SSL certificate expiration dates
- Identifies certificate issuers (CA)
- Detects encryption algorithms and key strength  
- Verifies OCSP revocation checking availability
- Extracts and resolves subdomains from certificates
- Saves detailed reports to files

## Quick Start

# Clone and install
git clone https://github.com/yourusername/SSLScout.git
cd SSLScout
pip install -r requirements.txt

# Run a scan
python main.py -d example.com
