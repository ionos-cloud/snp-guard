#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 IONOS SE
# Author: Roman Penyaev <r.peniaev@gmail.com>

set -e

PREREQ=""
prereqs() { echo "$PREREQ"; }

case "$1" in
    prereqs) prereqs; exit 0 ;;
esac

# Required by initramfs-tools
. /usr/share/initramfs-tools/hook-functions

# SEV-SNP guest driver
force_load sev-guest

# SnpGuard client
copy_exec /usr/bin/snpguard-client /usr/bin

# Deliver ip, see the attest.sh for details
copy_exec /usr/sbin/ip /usr/sbin

# Config files
copy_file config /etc/snpguard/attest.url
# ca.pem is only present when the server uses a self-signed or private CA.
# When the server uses a public CA (e.g. platform-managed TLS on fly.io),
# no ca.pem is embedded and the client falls back to its built-in webpki
# root CA bundle at runtime.
if [ -f /etc/snpguard/ca.pem ]; then
    copy_file config /etc/snpguard/ca.pem
fi
copy_file config /etc/snpguard/identity.pub
copy_file config /etc/snpguard/vmk.sealed
