#!/bin/sh
PREREQ="udev network"

prereqs() { echo "$PREREQ"; }

case "$1" in
    prereqs) prereqs; exit 0 ;;
esac

. /scripts/functions

panic() {
    echo
    echo "PANIC:"
    echo "PANIC: $*" >&2
    echo "PANIC:"
    echo
    exec sh
}

# Ensure udev settled
udevadm settle

# Set up network
configure_networking || panic "snpguard attest: networking failed"

# Check for the config file created by ipconfig
NETCONF="/run/net-$DEVICE.conf"
if [ -f "$NETCONF" ]; then
    # Source the variables (IPV4GATEWAY, IPV4NETMASK, etc.)
    . "$NETCONF"

    if [ "$IPV4NETMASK" = "255.255.255.255" ] && [ -n "$IPV4GATEWAY" ]; then
        # Standard 'ipconfig' can fail with "SIOCADDRT: Network is
        # unreachable" because a /32 mask tells the kernel the gateway
        # is not on the local subnet.  We force a 'scope link' route
        # to tell the kernel the gateway is physically attached to the
        # interface, which satisfies the requirement for a default
        # route
        echo "snpguard attest: /32 mask detected on $DEVICE. Check routing..."

        # Check if the route is actually missing before applying fix
        if ! ip route | grep -q default; then
            echo "snpguard attest: no default route. Gateway $IPV4GATEWAY is unreachable. Adding on-link route"

            ip route add "$IPV4GATEWAY" dev "$DEVICE" scope link
            ip route add default via "$IPV4GATEWAY" dev "$DEVICE"

            echo "snpguard attest: routing table repaired"
        else
            echo "snpguard attest: default route exists. Seems everything is fine"
        fi
    fi
fi

# Determine root
if [ -z "$ROOT" ]; then
    ROOT="$(sed -n 's/.*\broot=\([^ ]*\).*/\1/p' /proc/cmdline)"
fi

[ -n "$ROOT" ] || panic "snpguard attest: no root= specified"

REAL_ROOT="$(resolve_device "$ROOT")" || panic "snpguard attest: cannot resolve root device"

# Attestation
VMK="$(/usr/bin/snpguard-client attest \
    --url "$(cat /etc/snpguard/attest.url)" \
    --ca-cert /etc/snpguard/ca.pem \
    --sealed-blob /etc/snpguard/vmk.sealed)" || panic "snpguard attest: attestation failed"

# Unlock root
echo -n "$VMK" | cryptsetup luksOpen "$REAL_ROOT" root_crypt --key-file=- \
    || panic "snpguard attest: cryptsetup failed"

unset VMK

echo "snpguard attest: successfully attested"

# Ensure the ROOT variable is overridden
echo "ROOT=/dev/mapper/root_crypt" >> /conf/param.conf
