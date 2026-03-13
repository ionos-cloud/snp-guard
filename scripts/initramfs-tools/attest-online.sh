#!/bin/sh
# ONLINE ATTESTATION SCRIPT
# ==========================
# Unseals the rootfs VMK by performing a full remote attestation handshake
# with the SnpGuard server on every boot.  Network access is required for
# every boot when using this script.
#
# LUKS slot layout:
#   Slot 0 - sealed VMK (unlocked via online attestation, snpguard service)
#
# Boot flow:
#   1. Configure networking (udevadm settle + DHCP + /32 routing workaround).
#   2. Resolve the root block device from the kernel command line.
#   3. Perform remote attestation: the snpguard-client generates an AMD
#      SEV-SNP attestation report, sends it to the server together with the
#      sealed VMK blob, and receives the VMK decrypted and re-encrypted
#      under an ephemeral session key.
#   4. Unlock the root filesystem by passing the VMK to cryptsetup.
#
# For a variant that avoids network on every boot see attest-offline.sh.

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

# ---------------------------------------------------------------------------
# Step 1 - Configure networking
# ---------------------------------------------------------------------------
# Network must be available before contacting the attestation server.
# udevadm settle ensures all block/net devices are enumerated before
# configure_networking (initramfs-tools built-in) runs DHCP.
#
# Cloud providers that assign a /32 address (single-host subnet) require an
# explicit on-link route to the gateway because the kernel would otherwise
# refuse to add a default route (the gateway appears off-subnet).  This
# workaround reads the variables written by ipconfig into /run/net-$DEVICE.conf
# and injects the missing routes when the condition is detected.
echo "snpguard attest: setting up network..."
udevadm settle
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

# ---------------------------------------------------------------------------
# Step 2 - Resolve root block device
# ---------------------------------------------------------------------------
# The root= parameter on the kernel command line may be a device path, UUID,
# or LABEL.  resolve_device() (from /scripts/functions) normalises it to an
# absolute /dev path.
if [ -z "$ROOT" ]; then
    ROOT="$(sed -n 's/.*\broot=\([^ ]*\).*/\1/p' /proc/cmdline)"
fi

[ -n "$ROOT" ] || panic "snpguard attest: no root= specified"

REAL_ROOT="$(resolve_device "$ROOT")" || panic "snpguard attest: cannot resolve root device"

# ---------------------------------------------------------------------------
# Step 3 - Online attestation
# ---------------------------------------------------------------------------
echo "snpguard attest: performing remote attestation..."
VMK="$(/usr/bin/snpguard-client attest \
    --url "$(cat /etc/snpguard/attest.url)" \
    --ca-cert /etc/snpguard/ca.pem \
    report \
    --sealed-blob /etc/snpguard/vmk.sealed)" || panic "snpguard attest: attestation failed"

# ---------------------------------------------------------------------------
# Step 4 - Unlock root filesystem
# ---------------------------------------------------------------------------
echo "snpguard attest: unlocking root filesystem..."
echo -n "$VMK" | cryptsetup luksOpen "$REAL_ROOT" root_crypt --key-file=- \
    || panic "snpguard attest: cryptsetup failed"

unset VMK

echo "snpguard attest: successfully attested"

# Ensure the ROOT variable is overridden
echo "ROOT=/dev/mapper/root_crypt" >> /conf/param.conf
