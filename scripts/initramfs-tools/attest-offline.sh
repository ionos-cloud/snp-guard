#!/bin/sh
# OFFLINE ATTESTATION SCRIPT
# ===========================
# Attempts to unseal the rootfs using a hardware-bound key derived from the
# SEV-SNP chip (VCEK) mixed with the launch measurement.  On first boot or
# after chip migration, falls back to online attestation to obtain the VMK,
# then enrolls the derived key into LUKS slot 1 for all subsequent boots.
#
# LUKS slot layout:
#   Slot 0 - sealed VMK (unlocked via online attestation, snpguard service)
#   Slot 1 - hardware-bound derived key (unlocked offline, no network needed)
#
# The derived key is unique to the combination of this physical AMD chip
# (identified by the VCEK), the launch measurement (firmware + kernel +
# initrd digest), the image ID registered with the attestation server, and
# the guest launch policy.  It cannot be reproduced on a different chip, with
# a different image, or under a different launch policy.
#
# Fields mixed into the derived key and why each one matters:
#   --mix-measurement   Launch digest covering OVMF + kernel + initrd +
#                       cmdline.  Implicitly covers id_key_digest and
#                       author_key_digest because the signed ID block that
#                       produces those digests commits to the measurement.
#                       The server matches attestation records by all three.
#   --mix-image-id      UUID identifying the registered image.  The server
#                       explicitly filters attestation records by image_id
#                       (report.image_id); without this flag a derived key
#                       computed from a different registration would still
#                       match the measurement but not the server record.
#   --mix-policy        Guest launch policy bitmask (controls hypervisor
#                       capabilities: debug mode, live migration, SMT, etc.).
#                       Mixing the policy ensures that launching the image
#                       under a different policy (e.g. with debug mode
#                       enabled) invalidates the offline key and forces
#                       re-enrollment via online attestation.
#   --vmpl 0            Explicitly derive the key at VMPL 0, matching the
#                       server requirement (reports from VMPL > 0 are
#                       rejected).  The default is already 0, but stating
#                       it explicitly documents the intent.
#
# Network is required exactly once:
#   - On the very first boot (slot 1 not yet enrolled).
#   - After chip migration (VCEK changes -> derived key differs -> slot 1 must
#     be re-enrolled).  Once re-enrolled on the new chip, subsequent boots
#     proceed offline again.

PREREQ="udev"
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

# Determine root device
if [ -z "$ROOT" ]; then
    ROOT="$(sed -n 's/.*\broot=\([^ ]*\).*/\1/p' /proc/cmdline)"
fi

[ -n "$ROOT" ] || panic "snpguard attest: no root= specified"

REAL_ROOT="$(resolve_device "$ROOT")" || panic "snpguard attest: cannot resolve root device"

# ---------------------------------------------------------------------------
# Step 1 - Derive hardware-bound key from the SEV-SNP chip
# ---------------------------------------------------------------------------
# The key is bound to the physical chip (VCEK), the launch measurement, the
# image ID, and the guest policy.  It can only be reproduced by an identical
# guest image running on the same physical AMD chip under the same launch
# policy.  If the VM is migrated to a different chip, this step still succeeds
# (the chip is reachable) but the derived value will differ from the one
# enrolled in slot 1, causing step 2 to fail and triggering the online
# fallback below.
echo "snpguard attest: deriving hardware-bound key from SEV-SNP chip..."
DERIVE_KEY="$(/usr/bin/snpguard-client derive-key \
    --mix-measurement \
    --mix-image-id \
    --mix-policy \
    --vmpl 0 \
    2>/dev/null)" \
    || DERIVE_KEY=""

# ---------------------------------------------------------------------------
# Step 2 - Try offline boot via LUKS slot 1
# ---------------------------------------------------------------------------
# Slot 1 is populated on the first successful online attestation (step 4).
# Failure here is expected on first boot and after chip migration.
if [ -n "$DERIVE_KEY" ]; then
    echo "snpguard attest: trying offline key (LUKS slot 1)..."
    if printf '%s' "$DERIVE_KEY" | \
            cryptsetup luksOpen --key-slot 1 "$REAL_ROOT" root_crypt --key-file=- 2>/dev/null; then
        echo "snpguard attest: offline attestation successful"
        unset DERIVE_KEY
        echo "ROOT=/dev/mapper/root_crypt" >> /conf/param.conf
        exit 0
    fi
    echo "snpguard attest: offline key did not match - first boot or chip migration detected"
fi

# ---------------------------------------------------------------------------
# Step 3 - Configure networking
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
echo "snpguard attest: setting up network for online attestation..."
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
# Step 4 - Online attestation fallback
# ---------------------------------------------------------------------------
echo "snpguard attest: performing online attestation..."
VMK="$(/usr/bin/snpguard-client attest \
    --url "$(cat /etc/snpguard/attest.url)" \
    --ca-cert /etc/snpguard/ca.pem \
    report \
    --sealed-blob /etc/snpguard/vmk.sealed)" \
    || panic "snpguard attest: online attestation failed"

printf '%s' "$VMK" | cryptsetup luksOpen "$REAL_ROOT" root_crypt --key-file=- \
    || panic "snpguard attest: cryptsetup failed with online VMK"

echo "snpguard attest: online attestation successful"

# ---------------------------------------------------------------------------
# Step 5 - Enrol derived key into LUKS slot 1
# ---------------------------------------------------------------------------
# After a successful online attestation, persist the hardware-bound key so
# that all future boots can proceed without network.  On chip migration the
# stale slot 1 (from the old chip) is removed before enrolling the new key.
if [ -n "$DERIVE_KEY" ]; then
    echo "snpguard attest: enrolling hardware-bound key in LUKS slot 1..."
    VMK_FILE="$(mktemp)"
    DERIVE_KEY_FILE="$(mktemp)"
    printf '%s' "$VMK"        > "$VMK_FILE"
    printf '%s' "$DERIVE_KEY" > "$DERIVE_KEY_FILE"

    # Remove any stale slot 1 first (silently ignore if absent)
    cryptsetup luksKillSlot --key-file="$VMK_FILE" "$REAL_ROOT" 1 2>/dev/null || true

    cryptsetup luksAddKey --key-slot=1 --key-file="$VMK_FILE" "$REAL_ROOT" "$DERIVE_KEY_FILE" \
        && echo "snpguard attest: slot 1 enrolled; subsequent boots will proceed offline" \
        || echo "snpguard attest: WARNING: slot 1 enrolment failed (non-fatal, will retry on next boot)"

    rm -f "$VMK_FILE" "$DERIVE_KEY_FILE"
    unset DERIVE_KEY
fi

unset VMK

# Ensure the ROOT variable is overridden
echo "ROOT=/dev/mapper/root_crypt" >> /conf/param.conf
