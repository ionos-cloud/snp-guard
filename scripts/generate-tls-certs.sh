#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 IONOS SE
# Author: Roman Penyaev <r.peniaev@gmail.com>

set -euo pipefail

# Arrays to hold multiple IPs and DNS entries
ips=()
dns_servers=()

# Function to show help
show_help() {
    cat <<EOF
Usage: $0 --output DIR [--ip IP1 --ip IP2 ...] [--dns DNS1 --dns DNS2 ...]

Options:
  --output DIR      Output directory for keys and certificates (required)
  --ip IP           IP address for SAN (optional, can repeat)
  --dns DNS         DNS name for SAN (optional, can repeat)
  -h, --help        Show this help message and exit
EOF
}

# Parse arguments
output_dir=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --output)
            shift
            [[ $# -eq 0 ]] && { echo "Error: --output requires an argument"; exit 1; }
            output_dir="$1"
            ;;
        --ip)
            shift
            [[ $# -eq 0 ]] && { echo "Error: --ip requires an argument"; exit 1; }
            ips+=("$1")
            ;;
        --dns)
            shift
            [[ $# -eq 0 ]] && { echo "Error: --dns requires an argument"; exit 1; }
            dns_servers+=("$1")
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
    shift
done

# Check required argument
if [[ -z "$output_dir" ]]; then
    echo "Error: --output is required"
    show_help
    exit 1
fi

# Create directories
mkdir -p "$output_dir"

tls_key="$output_dir/server.key"
tls_crt="$output_dir/server.crt"
ca_pem="$output_dir/ca.pem"

# Build subjectAltName string
san_entries=("IP:127.0.0.1" "DNS:localhost")  # default entries
for ip in "${ips[@]}"; do
    san_entries+=("IP:$ip")
done
for dns in "${dns_servers[@]}"; do
    san_entries+=("DNS:$dns")
done
san_str=$(IFS=, ; echo "${san_entries[*]}")

# Generate the self-signed certificate. The certificate is only valid
# as a server (or client) certificate. It cannot be used to issue
# other certificates, thus "basicConstraints=CA:FALSE", if not set
# client returns "CaUsedAsEndEntity"
openssl req -x509 -nodes -newkey rsa:4096 \
    -keyout "$tls_key" \
    -out "$tls_crt" \
    -days 365 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=$san_str" \
    -addext "basicConstraints=CA:FALSE"

# Copy certificate as CA pem for trust usage
cp "$tls_crt" "$ca_pem"

echo "TLS certificate generated:"
echo "  Key:  $tls_key"
echo "  Cert: $tls_crt"
echo "  CA:   $ca_pem"
echo "  SAN:  $san_str"
