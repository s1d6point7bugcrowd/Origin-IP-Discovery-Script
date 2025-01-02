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
all_ips=""

# Collect A records
dns_ips=$(echo "$subdomains" | xargs -I{} dig @1.1.1.1 {} A +short)
all_ips="$all_ips $dns_ips $mx_ips"

# Fetch historical IPs
if [[ -n "$SECURITYTRAILS_API" ]]; then
  historical_ips=$(curl -s --request GET --url "https://api.securitytrails.com/v1/history/$domain/dns/a" --header "apikey: $SECURITYTRAILS_API" | jq -r '.records[].values[].ip' 2>/dev/null)
  all_ips="$all_ips $historical_ips"
fi

# Deduplicate and categorize IPs
all_ips=$(echo "$all_ips" | tr ' ' '\n' | sort -u)
cdn_asns=("AS13335" "AS16509" "AS20940") # Cloudflare, AWS, Akamai
direct_ips=""
cdn_ips=""
suspected_ips=""

for ip in $all_ips; do
  asn=$(whois $ip | grep "OriginAS" | awk '{print $2}')
  if [[ " ${cdn_asns[@]} " =~ " ${asn} " ]]; then
    cdn_ips="$cdn_ips $ip"
  else
    direct_ips="$direct_ips $ip"
  fi
done

# Fetch target domain content hash
echo -e "\033[96mFetching Target Domain Content Hash...\033[0m"
target_content=$(curl -s "https://$domain")
target_hash=$(echo -n "$target_content" | sha256sum | awk '{print $1}')

echo -e "Target Content Hash: $target_hash"

# Backend Testing
echo -e "\033[96mTesting Backend IPs...\033[0m"
for ip in $direct_ips; do
  if [[ -z "$ip" ]]; then
    continue
  fi

  echo -e "\033[93mTesting IP: $ip\033[0m"

  # Test HTTP Response
  http_result=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $domain" "http://$ip")
  https_result=$(curl -k -s -o /dev/null -w "%{http_code}" -H "Host: $domain" "https://$ip")

  # Content Analysis
  ip_content=$(curl -s -H "Host: $domain" "http://$ip")
  ip_hash=$(echo -n "$ip_content" | sha256sum | awk '{print $1}')
  if [[ "$ip_hash" == "$target_hash" ]]; then
    echo -e "\033[92mContent Matches Target Domain: $ip\033[0m"
  else
    echo -e "\033[91mContent Does Not Match: $ip\033[0m"
  fi

  # Test TLS Certificate with Curl
  tls_cert=$(curl -k -v -H "Host: $domain" https://$ip 2>&1 | grep "subject:" | awk -F'subject: ' '{print $2}')
  if [[ "$tls_cert" == *"$domain"* ]]; then
    echo -e "\033[92mTLS Certificate Matches: $ip ($tls_cert)\033[0m"
  else
    echo -e "\033[91mTLS Certificate Mismatch: $ip ($tls_cert)\033[0m"
  fi

  # Banner Grabbing
  banner=$(curl -s -I -H "Host: $domain" "http://$ip" | grep "Server:")
  if [[ -n "$banner" ]]; then
    echo -e "\033[96mBanner Grabbing Result:\033[0m $banner"
  else
    echo -e "\033[91mNo Banner Retrieved: $ip\033[0m"
  fi

  # Test Specific Endpoints
  endpoint_hits=0
  for endpoint in "/robots.txt" "/admin" "/api/status"; do
    endpoint_result=$(curl -s -o /dev/null -w "%{http_code}" -H "Host: $domain" "http://$ip$endpoint")
    if [[ "$endpoint_result" == "200" || "$endpoint_result" == "301" ]]; then
      echo -e "\033[92mEndpoint Accessible ($endpoint): $ip\033[0m"
      endpoint_hits=$((endpoint_hits + 1))
    fi
  done

  # Evaluate if IP is a suspected true origin
  if [[ ("$http_result" == "200" || "$http_result" == "301") || ("$https_result" == "200" || "$https_result" == "301") ]] && [[ "$ip_hash" == "$target_hash" ]] && [[ $endpoint_hits -gt 0 ]]; then
    suspected_ips="$suspected_ips $ip"
    echo -e "\033[92mSuspected True Origin IP: $ip\033[0m"
  fi
done

echo -e "\033[91mCDN and Load Balancer IPs:\033[0m"
if [[ -z "$cdn_ips" ]]; then
  echo "No CDN or Load Balancer IPs detected."
else
  echo "$cdn_ips" | tr ' ' '\n'
fi

echo -e "\033[96mSuspected True Origin IPs:\033[0m"
if [[ -z "$suspected_ips" ]]; then
  echo "No suspected true origin IPs identified."
else
  echo "$suspected_ips" | tr ' ' '\n'
fi
