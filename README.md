# Origin IP Discovery Script

## Overview

This script is designed to identify potential origin IPs of a given domain by:
1. Querying DNS records (A, MX).
2. Resolving IP addresses for discovered subdomains and email servers.
3. Fetching historical IP data from SecurityTrails (if API key provided).
4. Performing backend testing to match content, TLS certificates, and headers.
5. Highlighting suspected origin IPs while filtering out CDN and load balancer IPs.

## Prerequisites

Ensure the following tools are installed on your system:
- `dig`
- `curl`
- `jq`
- `whois`
- `subfinder` (for subdomain enumeration)

For advanced features like historical IP lookup, an API key for **SecurityTrails** is required.

## Usage

```bash
./origin-ip.sh -d <domain> [-c <censys_api>] [-s <securitytrails_api>] [-h <hunter_api>] [-z <zoomeye_api>]


Options:

    -d <domain>: Target domain name (required).
    -c <censys_api>: API credentials for Censys (optional).
    -s <securitytrails_api>: API key for SecurityTrails (optional).
    -h <hunter_api>: API key for Hunter (optional).
    -z <zoomeye_api>: API key for ZoomEye (optional).


Example:

./origin-ip.sh -d example.com -s YOUR_SECURITYTRAILS_API_KEY


# Origin IP Discovery Script

## Overview

This script is designed to identify potential origin IPs of a given domain by:
1. Querying DNS records (A, MX).
2. Resolving IP addresses for discovered subdomains and email servers.
3. Fetching historical IP data from SecurityTrails (if API key provided).
4. Performing backend testing to match content, TLS certificates, and headers.
5. Highlighting suspected origin IPs while filtering out CDN and load balancer IPs.

## Prerequisites

Ensure the following tools are installed on your system:
- `dig`
- `curl`
- `jq`
- `whois`
- `subfinder` (for subdomain enumeration)

For advanced features like historical IP lookup, an API key for **SecurityTrails** is required.

## Usage

```bash
./origin-ip.sh -d <domain> [-c <censys_api>] [-s <securitytrails_api>] [-h <hunter_api>] [-z <zoomeye_api>]

Options:

    -d <domain>: Target domain name (required).
    -c <censys_api>: API credentials for Censys (optional).
    -s <securitytrails_api>: API key for SecurityTrails (optional).
    -h <hunter_api>: API key for Hunter (optional).
    -z <zoomeye_api>: API key for ZoomEye (optional).

Example:

./origin-ip.sh -d example.com -s YOUR_SECURITYTRAILS_API_KEY

Features

    MX Records Analysis:
        Queries MX records of the domain and resolves associated IPs.
        Useful for identifying hosting infrastructure not behind CDNs.

    Subdomain Enumeration:
        Uses subfinder to find subdomains and resolves their A records.

    Historical IP Collection:
        Optionally fetches historical IPs using SecurityTrails API.

    Backend Testing:
        Verifies direct IP access by checking:
            HTTP/HTTPS response codes.
            TLS certificate matching.
            Content similarity using SHA-256 hash comparison.
            Accessibility of common endpoints (e.g., /robots.txt, /admin).
            Server banners.

    Filtering CDN/Load Balancer IPs:
        Uses ASN information to filter known CDN providers (e.g., Cloudflare, AWS, Akamai).

    Output:
        Lists suspected true origin IPs and highlights mismatches.

Sample Output:

Querying MX Records for example.com...
MX Records Discovered:
10 alt1.aspmx.l.google.com
5 aspmx.l.google.com
Resolving IPs for MX Records...
Resolved alt1.aspmx.l.google.com to 172.217.197.27
Resolved aspmx.l.google.com to 173.194.219.27

Enumerating Subdomains...
Subdomains Discovered:
sub1.example.com
sub2.example.com

Collecting Potential IPs...
Testing Backend IPs...
Testing IP: 192.0.2.1
Content Matches Target Domain: 192.0.2.1
TLS Certificate Matches: 192.0.2.1 (CN=example.com)
Endpoint Accessible (/robots.txt): 192.0.2.1
Suspected True Origin IP: 192.0.2.1


Limitations

    Dynamic Content: Content hashes may differ for highly dynamic websites.
    TLS Certificate Mismatches: Origin servers may not present the expected certificate.
    MX Record Filtering: Email server IPs often do not relate to web server infrastructure.


***TLS certificates on origin servers might not always match the domain name.***

## Disclaimer

This script is intended for ethical and authorized use only. By using this script, you agree to the following:

1. **Authorization**:
   - Ensure you have explicit permission to test the target domain and its associated infrastructure.
   - Unauthorized usage may violate applicable laws and regulations.

2. **Responsibility**:
   - The user assumes all responsibility for the use of this script.
   - The authors of this script are not liable for any damages or legal issues arising from its use.

3. **Ethical Use**:
   - This script is designed for security researchers, penetration testers, and system administrators to identify potential vulnerabilities in a controlled and ethical environment.

4. **Compliance**:
   - Ensure compliance with all relevant local, national, and international laws.
   - Adhere to the target organization's terms of service and acceptable use policies.

If you are unsure about your authorization or the legality of your activities, consult with legal counsel before proceeding.
