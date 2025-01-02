#!/bin/bash

while getopts "d:c:s:h:z:" opt; do
  case $opt in
    d)
      domain=$OPTARG
      ;;
    c)
      CENSYS_API_ID_CENSYS_API_SECRET=$OPTARG
      ;;
    s)
      SECURITYTRAILS_API=$OPTARG
      ;;
    h)
      HUNTER_API=$OPTARG
      ;;
    z)
      ZOOMEYE_API=$OPTARG
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

if [[ -z $domain ]]; then
  echo "Usage: $0 -d domain.com"
  exit 1
fi

echo -e "\033[96mFetching Target Domain Content...\033[0m"
curl -s "https://$domain" > target_content.html
target_hash=$(sha256sum target_content.html | awk '{print $1}')
echo -e "Target Content Hash: $target_hash"

echo -e "\033[96mQuerying MX Records for $domain...\033[0m"
mx_records=$(dig +short MX $domain)
if [[ -z "$mx_records" ]]; then
  echo "No MX records found for $domain."
else
  echo -e "MX Records Discovered:\n$mx_records"
fi

# Resolve IPs for MX records
echo -e "\033[96mResolving IPs for MX Records...\033[0m"
mx_ips=""
for mx in $(echo "$mx_records" | awk '{print $2}'); do
  ip=$(dig +short $mx A)
  if [[ -n "$ip" ]]; then
    mx_ips="$mx_ips $ip"
    echo "Resolved $mx to $ip"
  fi
done

if [[ -z "$mx_ips" ]]; then
  echo "No IPs resolved for MX records."
else
  echo -e "Resolved IPs for MX Records:\n$mx_ips"
fi

echo -e "\033[96mEnumerating Subdomains...\033[0m"
subdomains=$(subfinder -d $domain -silent)
if [[ -z "$subdomains" ]]; then
  echo "No subdomains found for $domain."
else
  echo -e "Subdomains Discovered:\n$subdomains"
fi

echo -e "\033[96mCollecting Potential IPs...\033[0m"
all_ips="$mx_ips"

# Collect A records
dns_ips=$(echo "$subdomains" | xargs -I{} dig @1.1.1.1 {} A +short)
all_ips="$all_ips $dns_ips"

# Fetch historical IPs using SecurityTrails API
if [[ -n "$SECURITYTRAILS_API" ]]; then
  historical_ips=$(curl -s --request GET --url "https://api.securitytrails.com/v1/history/$domain/dns/a" --header "apikey: $SECURITYTRAILS_API" | jq -r '.records[].values[].ip' 2>/dev/null)
  all_ips="$all_ips $historical_ips"
fi

# Deduplicate and categorize IPs
all_ips=$(echo "$all_ips" | tr ' ' '\n' | sort -u)
cdn_asns=("AS13335" "AS16509" "AS20940") # Cloudflare, AWS, Akamai
direct_ips=""
cdn_ips=""

for ip in $all_ips; do
  asn=$(whois $ip | grep "OriginAS" | awk '{print $2}')
  if [[ " ${cdn_asns[@]} " =~ " ${asn} " ]]; then
    cdn_ips="$cdn_ips $ip"
  else
    direct_ips="$direct_ips $ip"
  fi
done

# Prepare Python script for similarity analysis
cat <<EOF > similarity_analysis.py
import sys
from difflib import SequenceMatcher

def compute_similarity(file1, file2):
    with open(file1, 'r', encoding='utf-8') as f1, open(file2, 'r', encoding='utf-8') as f2:
        content1 = f1.read()
        content2 = f2.read()
        similarity = SequenceMatcher(None, content1, content2).ratio()
    return similarity

if __name__ == "__main__":
    target_file = sys.argv[1]
    ip_file = sys.argv[2]
    similarity = compute_similarity(target_file, ip_file)
    print(f"{similarity:.2f}")
EOF

echo -e "\033[96mTesting Backend IPs...\033[0m"
for ip in $direct_ips; do
  # Retrieve ASN for the IP
  asn=$(whois $ip | grep "OriginAS" | awk '{print $2}')
  echo -e "\033[93mTesting IP: $ip (ASN: $asn)\033[0m"

  # Fetch content from IP
  curl -s -H "Host: $domain" "http://$ip" > ip_content.html
  ip_hash=$(sha256sum ip_content.html | awk '{print $1}')

  # Hash-based match
  if [[ "$ip_hash" == "$target_hash" ]]; then
    echo -e "\033[92mContent Hash Matches Target Domain: $ip\033[0m"
  else
    echo -e "\033[91mContent Hash Does Not Match: $ip\033[0m"
  fi

  # Banner Grabbing
  banner=$(curl -s -I -H "Host: $domain" "http://$ip" | grep "Server:")
  if [[ -n "$banner" ]]; then
    echo -e "\033[96mBanner Grabbing Result:\033[0m $banner"
  else
    echo -e "\033[91mNo Banner Retrieved: $ip\033[0m"
  fi

  # Check for specific headers (CDN Detection)
  headers=$(curl -s -I -H "Host: $domain" "http://$ip")
  if echo "$headers" | grep -qi "CF-Ray"; then
    echo -e "\033[91mExcluded: Cloudflare Detected ($ip) - CF-Ray Header Found\033[0m"
    continue
  fi
  if echo "$headers" | grep -qi "X-Akamai-Staging"; then
    echo -e "\033[91mExcluded: Akamai Detected ($ip) - X-Akamai-Staging Header Found\033[0m"
    continue
  fi
  if echo "$headers" | grep -qi "x-ms-routing-name"; then
    echo -e "\033[91mExcluded: Azure Front Door Detected ($ip) - x-ms-routing-name Header Found\033[0m"
    continue
  fi

  # Perform similarity analysis using Python
  similarity=$(python3 similarity_analysis.py target_content.html ip_content.html)
  echo -e "Similarity Score: $similarity"

  # Threshold for similarity (avoiding bc)
  if (( $(python3 -c "print(1 if $similarity > 0.8 else 0)") )); then
    echo -e "\033[92mSuspected True Origin IP: $ip (Similarity: $similarity)\033[0m"
  else
    echo -e "\033[91mNot a Match: $ip (Similarity: $similarity)\033[0m"
  fi
done

# Cleanup
rm -f target_content.html ip_content.html similarity_analysis.py
