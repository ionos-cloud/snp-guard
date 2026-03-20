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
#   2. Resolve the root block device by LUKS label (snpguard-luks).
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

echo
echo "================================================================"
echo "  snpguard: ONLINE attestation starting"
echo "================================================================"
echo

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
# Record boot slot on LAUNCH_ARTIFACTS
# ---------------------------------------------------------------------------
# Write /.booted on LAUNCH_ARTIFACTS so that "attest renew" always
# overwrites the inactive slot, making repeated calls idempotent.
# Skipped silently if the partition is absent.
if [ -e /dev/disk/by-label/LAUNCH_ARTIFACTS ]; then
    LA_DEV="$(readlink -f /dev/disk/by-label/LAUNCH_ARTIFACTS)"
    LA_MNT="$(mktemp -d)"
    if mount -t ext4 "$LA_DEV" "$LA_MNT" 2>/dev/null; then
        if [ -L "$LA_MNT/artifacts" ]; then
            SLOT="$(readlink "$LA_MNT/artifacts")"
            rm -f "$LA_MNT/.booted"
            ln -s "$SLOT" "$LA_MNT/.booted"
            sync
        fi
        umount "$LA_MNT" 2>/dev/null || true
    fi
    rmdir "$LA_MNT" 2>/dev/null || true
fi

# ---------------------------------------------------------------------------
# Step 2 - Resolve root block device by LUKS label
# ---------------------------------------------------------------------------
REAL_ROOT="$(readlink -f /dev/disk/by-label/snpguard-luks)" \
    || panic "snpguard attest: LUKS device with label snpguard-luks not found"

# ---------------------------------------------------------------------------
# Step 3 - Online attestation
# ---------------------------------------------------------------------------
echo "snpguard attest: performing remote attestation..."
VMK="$(/usr/bin/snpguard-client attest \
    --url "$(cat /etc/snpguard/attest.url)" \
    report \
    --sealed-blob /etc/snpguard/vmk.sealed)" || panic "snpguard attest: attestation failed"

# ---------------------------------------------------------------------------
# Step 4 - Unlock root filesystem
# ---------------------------------------------------------------------------
echo "snpguard attest: unlocking root filesystem..."
echo -n "$VMK" | cryptsetup luksOpen "$REAL_ROOT" cryptroot --key-file=- \
    || panic "snpguard attest: cryptsetup failed"

unset VMK

echo "snpguard attest: successfully attested"

echo
echo "================================================================"
echo "  snpguard: ONLINE attestation done"
echo "================================================================"
echo

# Ensure the ROOT variable is overridden
echo "ROOT=/dev/mapper/cryptroot" >> /conf/param.conf
