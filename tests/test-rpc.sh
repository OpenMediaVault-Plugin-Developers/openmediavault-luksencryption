#!/usr/bin/env bash
# test-rpc.sh — Integration tests for openmediavault-luksencryption RPC methods.
#
# Usage: sudo ./tests/test-rpc.sh
#
# Creates temporary loop-backed LUKS containers and exercises every LuksMgmt
# RPC method: create/delete, enumerate/list/details, unlock/lock (including
# "allow discards" and mounting the filesystem inside on unlock), key
# management, header backup/restore, auto-unlock at boot via /etc/crypttab
# and stale entry cleanup.  Everything is removed on exit and /etc/crypttab
# and /etc/fstab are restored.  No real disks are touched.
#
# Requirements:
#   - Run as root
#   - OMV with the luksencryption plugin installed
#   - cryptsetup, losetup, dmsetup, blkid, systemd-cryptsetup, mkfs.ext4
#   - mkfs.btrfs, lvm2 (optional; the BTRFS / LVM mount tests are skipped without them)
#
# Clevis auto-unlock: set TANG_URL (e.g. TANG_URL=http://tang.lan) to test
# binding to a real Tang server; TPM2 binding is tested when /dev/tpmrm0
# exists.  Either installs clevis via the plugin's salt state.

set -uo pipefail

if [ "$(id -u)" -ne 0 ]; then
    echo "Must be run as root." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Colours / counters
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

PASS=0
FAIL=0
declare -a FAILED_TESTS=()

section() { echo -e "\n${CYAN}${BOLD}=== $* ===${NC}" >&2; }
info()    { echo -e "  ${YELLOW}»${NC} $*" >&2; }

_pass() { echo -e "  ${GREEN}PASS${NC}  $1" >&2; ((PASS++)) || true; }
_fail() {
    echo -e "  ${RED}FAIL${NC}  $1" >&2
    [ -n "${2:-}" ] && echo -e "         ${RED}→${NC} $2" >&2
    ((FAIL++)) || true
    FAILED_TESTS+=("$1")
}

# Pass/fail on the exit status of a shell condition.
check() {
    local desc=$1 detail=$2
    shift 2
    if "$@"; then
        _pass "$desc"
    else
        _fail "$desc" "$detail"
    fi
}

# ---------------------------------------------------------------------------
# RPC helpers
# ---------------------------------------------------------------------------

# Raw RPC call; output to stdout, errors to stderr.
rpc() {
    local svc=$1 method=$2 params=${3:-'{}'}
    omv-rpc -u admin "$svc" "$method" "$params"
}

# Assert an RPC succeeds.  Result JSON is stored in RPC_OUT.
# Optional 5th arg: grep pattern that must appear in output.
RPC_OUT=""
assert_rpc() {
    local desc=$1 svc=$2 method=$3 params=${4:-'{}'} pattern=${5:-}
    local out ec=0
    out=$(omv-rpc -u admin "$svc" "$method" "$params" 2>&1) || ec=$?
    if [ $ec -ne 0 ]; then
        _fail "$desc" "$(echo "$out" | tail -3)"
        RPC_OUT=""
        return 1
    fi
    if [ -n "$pattern" ] && ! echo "$out" | grep -q "$pattern"; then
        _fail "$desc" "Pattern '$pattern' not found in: ${out:0:200}"
        RPC_OUT=""
        return 1
    fi
    _pass "$desc"
    RPC_OUT="$out"
    return 0
}

# Assert an RPC fails (non-zero exit or contains "exception").
assert_rpc_fails() {
    local desc=$1 svc=$2 method=$3 params=${4:-'{}'}
    local out ec=0
    out=$(omv-rpc -u admin "$svc" "$method" "$params" 2>&1) || ec=$?
    if [ $ec -eq 0 ] && ! echo "$out" | grep -qi "exception"; then
        _fail "$desc" "Expected failure but RPC succeeded: ${out:0:200}"
        return 1
    fi
    _pass "$desc"
    return 0
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Print field $2 of the enumerateContainers entry for device $1.
# Booleans are printed lowercase; a missing container prints nothing.
container_field() {
    rpc "$SVC" enumerateContainers '{}' 2>/dev/null | python3 -c "
import sys, json
for c in json.load(sys.stdin):
    if c.get('devicefile') == sys.argv[1]:
        v = c.get(sys.argv[2])
        print(str(v).lower() if isinstance(v, bool) else v)" "$1" "$2" 2>/dev/null || true
}

# Print field $2 of the getContainersList row whose uuid is $1.
list_field() {
    rpc "$SVC" getContainersList "$LIST_PARAMS" 2>/dev/null | python3 -c "
import sys, json
for c in json.load(sys.stdin)['data']:
    if c.get('uuid') == sys.argv[1]:
        v = c.get(sys.argv[2])
        print('null' if v is None else str(v).lower() if isinstance(v, bool) else v)" "$1" "$2" 2>/dev/null || true
}

# Print field $1 of a JSON object read from stdin.
json_field() {
    python3 -c "import sys, json; print(json.load(sys.stdin).get(sys.argv[1], ''))" "$1" 2>/dev/null || true
}

# Print the options column of the crypttab entry for UUID $1 (empty if none).
crypttab_options() {
    awk -v dev="UUID=$1" '$1 !~ /^#/ && $2 == dev { print $4 }' /etc/crypttab 2>/dev/null
}

# Print the key file column of the crypttab entry for UUID $1 (empty if none).
crypttab_keyfile() {
    awk -v dev="UUID=$1" '$1 !~ /^#/ && $2 == dev { print $3 }' /etc/crypttab 2>/dev/null
}

# Print the Clevis pins bound to device $1, one per line.
clevis_pins() {
    clevis luks list -d "$1" 2>/dev/null | awk '{ print $2 }'
}

# True if passphrase $2 unlocks device $1.
key_works() {
    echo -n "$2" | cryptsetup open --test-passphrase "$1" --key-file=- >/dev/null 2>&1
}
key_fails() { ! key_works "$@"; }

# True if key file $2 unlocks device $1.
keyfile_works() {
    cryptsetup open --test-passphrase "$1" --key-file "$2" >/dev/null 2>&1
}

# True if the dm-crypt mapping named $1 has discards passed through.
dm_allows_discards() {
    dmsetup table "$1" 2>/dev/null | grep -q "allow_discards"
}
dm_denies_discards() {
    [ -e "/dev/mapper/$1" ] && ! dm_allows_discards "$1"
}

# True if device $1 reports a non-zero discard limit.
reports_discard() {
    local max
    max=$(lsblk -dno DISC-MAX "$1" 2>/dev/null | tr -d ' ')
    [ -n "$max" ] && [ "$max" != "0B" ]
}

is_luks()  { cryptsetup isLuks "$1" >/dev/null 2>&1; }
not_luks() { ! is_luks "$1"; }

# Assert that a comma-separated option list contains / lacks an option.
has_opt()  { [[ ",$1," == *",$2,"* ]]; }
lacks_opt() { ! has_opt "$1" "$2"; }

# Create a sparse image of size $1 (default $LOOP_SIZE), attach it to a loop
# device and print the device.  Runs in a subshell, so the caller records the
# image for cleanup.
new_loop() {
    local img
    img=$(mktemp /var/tmp/omv-luks-test.XXXXXX)
    truncate -s "${1:-$LOOP_SIZE}" "$img"
    losetup --find --show "$img" || { rm -f "$img"; return 1; }
}

# Format device $1 directly (not via RPC) with passphrase $2 and type $3,
# using a cheap PBKDF so the test runs quickly.
quick_format() {
    echo -n "$2" | cryptsetup luksFormat -q --type "$3" \
        --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
        "$1" --key-file=- >/dev/null
    udevadm settle
}

mapper_of()    { echo "$(basename "$1")-crypt"; }
boot_unit_of() { echo "systemd-cryptsetup@$(systemd-escape "luks-$1").service"; }

# True if a filesystem is mounted on directory $1.
is_mounted()  { findmnt -n "$1" >/dev/null 2>&1; }
not_mounted() { ! is_mounted "$1"; }
mount_count() { findmnt -n "$1" 2>/dev/null | wc -l; }

# Mount the /etc/fstab entry for directory $2 as soon as /dev/mapper/$1
# appears, the way systemd may mount it while openContainer is still running.
race_mount() {
    local i
    for i in $(seq 600); do
        if [ -e "/dev/mapper/$1" ]; then
            is_mounted "$2" || mount "$2" >/dev/null 2>&1 || true
            is_mounted "$2" && return 0
        fi
        sleep 0.05
    done
    return 1
}

# Unlock device $1 directly (not via RPC) with passphrase $2.
quick_open() {
    echo -n "$2" | cryptsetup open "$1" "$(mapper_of "$1")" --key-file=- >/dev/null
    udevadm settle
}

# Register an OMV mount point for the filesystem with UUID $1 (type $2) on
# directory $3, both in the OMV database (which openContainer consults) and
# in /etc/fstab (which the mount itself uses).  Prints the mntent UUID.
add_mntent() {
    local fsname="/dev/disk/by-uuid/$1" out
    mkdir -p "$3"
    out=$(rpc FsTab set "{\"uuid\":\"$NEW_UUID\",\"fsname\":\"$fsname\",\"dir\":\"$3\",\"type\":\"$2\",\"opts\":\"defaults,nofail\",\"freq\":0,\"passno\":0}") || return 1
    printf '%s\t%s\t%s\tdefaults,nofail\t0 0\n' "$fsname" "$3" "$2" >> /etc/fstab
    systemctl daemon-reload
    echo "$out" | json_field uuid
}

# Unlock UUID $1 via systemd-cryptsetup using its crypttab entry, as happens
# at boot.  Returns non-zero if the unit could not be started.  No password
# agent runs on this terminal, so a prompt can only be answered by clevis.
boot_unlock() {
    systemctl daemon-reload
    timeout 60 systemctl --no-ask-password start "$(boot_unit_of "$1")" >/dev/null 2>&1
}
boot_lock() {
    systemctl stop "$(boot_unit_of "$1")" >/dev/null 2>&1 || true
    cryptsetup close "luks-$1" >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SVC="LuksMgmt"
LIST_PARAMS='{"start":0,"limit":null,"sortfield":null,"sortdir":null}'
KEY_DIR="/etc/luks-keys"
LOOP_SIZE="64M"
LABEL="omvtest$$"
NEW_UUID="fa4b1c66-ef79-11e5-87a0-0002b3a176b4"  # OMV_CONFIGOBJECT_NEW_UUID
MNT_EXT4="/srv/omv-luks-test-$$-ext4"
MNT_BTRFS="/srv/omv-luks-test-$$-btrfs"
MNT_LVM="/srv/omv-luks-test-$$-lvm"
VG_NAME="omv-luks-$$"   # hyphens are doubled in /dev/mapper names
LV_NAME="data-lv"

PASS_A="omv-luks-a-$$"
PASS_A2="omv-luks-a2-$$"
PASS_A3="omv-luks-a3-$$"
PASS_B="omv-luks-b-$$"
PASS_C="omv-luks-c-$$"
PASS_D="omv-luks-d-$$"
PASS_E="omv-luks-e-$$"
WRONG="wrong-passphrase-$$"

# ---------------------------------------------------------------------------
# State — populated during tests, consumed by cleanup
# ---------------------------------------------------------------------------
declare -a IMG_FILES=()
declare -a LOOPS=()
declare -a UUIDS=()
declare -a TMP_FILES=()
declare -a MNTENTS=()
DEV_A=""; DEV_B=""; DEV_C=""; DEV_D=""; DEV_E=""
UUID_A=""; UUID_B=""; UUID_C=""; UUID_D=""; UUID_E=""
STALE_UUID=""
CRYPTTAB_BACKUP=""
CRYPTTAB_EXISTED=0
FSTAB_BACKUP=""
RACER=""

# ---------------------------------------------------------------------------
# Cleanup — always runs on exit
# ---------------------------------------------------------------------------
cleanup() {
    section "Cleanup"

    local u d f m
    [ -n "$RACER" ] && kill "$RACER" >/dev/null 2>&1
    for m in "$MNT_EXT4" "$MNT_BTRFS" "$MNT_LVM"; do
        umount -R "$m" >/dev/null 2>&1 || true
        rmdir "$m" >/dev/null 2>&1 || true
    done
    vgchange -a n "$VG_NAME" >/dev/null 2>&1 || true
    for u in "${MNTENTS[@]}"; do
        rpc FsTab delete "{\"uuid\":\"$u\"}" >/dev/null 2>&1 || true
    done
    if [ -n "$FSTAB_BACKUP" ]; then
        info "Restoring /etc/fstab"
        cp -p "$FSTAB_BACKUP" /etc/fstab
        rm -f "$FSTAB_BACKUP"
    fi
    for u in "${UUIDS[@]}" "$STALE_UUID"; do
        [ -n "$u" ] || continue
        boot_lock "$u"
        rm -f "$KEY_DIR/$u"
    done
    for d in "${LOOPS[@]}"; do
        cryptsetup close "$(mapper_of "$d")" >/dev/null 2>&1 || true
    done
    if [ -n "$CRYPTTAB_BACKUP" ]; then
        info "Restoring /etc/crypttab"
        if [ "$CRYPTTAB_EXISTED" -eq 1 ]; then
            cp -p "$CRYPTTAB_BACKUP" /etc/crypttab
        else
            rm -f /etc/crypttab
        fi
        rm -f "$CRYPTTAB_BACKUP"
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
    for d in "${LOOPS[@]}"; do
        info "Detaching $d"
        losetup -d "$d" >/dev/null 2>&1 || true
    done
    for f in "${IMG_FILES[@]}" "${TMP_FILES[@]}"; do
        rm -f "$f"
    done

    echo >&2
    echo -e "${BOLD}Results: ${GREEN}${PASS} passed${NC}, ${RED}${FAIL} failed${NC}" >&2
    if [ ${#FAILED_TESTS[@]} -gt 0 ]; then
        echo -e "${RED}Failed tests:${NC}" >&2
        for t in "${FAILED_TESTS[@]}"; do
            echo -e "  - $t" >&2
        done
        exit 1
    fi
    exit 0
}
trap cleanup EXIT

# ===========================================================================
# Setup
# ===========================================================================

section "Setup"

CRYPTTAB_BACKUP=$(mktemp)
if [ -f /etc/crypttab ]; then
    cp -p /etc/crypttab "$CRYPTTAB_BACKUP"
    CRYPTTAB_EXISTED=1
fi
FSTAB_BACKUP=$(mktemp)
cp -p /etc/fstab "$FSTAB_BACKUP"

# D and E hold filesystems; E is large enough for a two-device BTRFS.
for v in DEV_A DEV_B DEV_C DEV_D DEV_E; do
    size=$LOOP_SIZE
    [ "$v" = DEV_D ] || [ "$v" = DEV_E ] && size=256M
    d=$(new_loop "$size") || { echo "Failed to attach loop device" >&2; exit 1; }
    LOOPS+=("$d")
    IMG_FILES+=("$(losetup -nO BACK-FILE "$d")")
    printf -v "$v" '%s' "$d"
done
info "Loop devices: A=$DEV_A B=$DEV_B C=$DEV_C D=$DEV_D E=$DEV_E"

MAPPER_A=$(mapper_of "$DEV_A")
MAPPER_C=$(mapper_of "$DEV_C")
MAPPER_D=$(mapper_of "$DEV_D")
MAPPER_E=$(mapper_of "$DEV_E")

LOOP_DISCARD=1
if [ "$(cat "/sys/block/$(basename "$DEV_A")/queue/discard_max_bytes" 2>/dev/null)" = "0" ]; then
    info "Loop devices do not support discard; DISC-MAX checks will be skipped"
    LOOP_DISCARD=0
fi

KEYFILE=$(mktemp /var/tmp/omv-luks-key.XXXXXX)
TMP_FILES+=("$KEYFILE")
head -c 64 /dev/urandom > "$KEYFILE"

JUNK_FILE=$(mktemp /var/tmp/omv-luks-junk.XXXXXX)
TMP_FILES+=("$JUNK_FILE")
head -c 1M /dev/urandom > "$JUNK_FILE"

# ===========================================================================
# Tests
# ===========================================================================

# ---------------------------------------------------------------------------
section "Parameter validation"
# ---------------------------------------------------------------------------

assert_rpc_fails "getContainerDetails rejects missing devicefile" \
    "$SVC" getContainerDetails '{}'
assert_rpc_fails "getContainerDetails rejects non-existent device" \
    "$SVC" getContainerDetails '{"devicefile":"/dev/omv-luks-does-not-exist"}'
assert_rpc_fails "getContainerDetails rejects a non-LUKS device" \
    "$SVC" getContainerDetails "{\"devicefile\":\"$DEV_A\"}"
assert_rpc_fails "closeContainer rejects a non-LUKS device" \
    "$SVC" closeContainer "{\"devicefile\":\"$DEV_A\"}"
assert_rpc_fails "deleteContainer rejects a non-LUKS device" \
    "$SVC" deleteContainer "{\"devicefile\":\"$DEV_A\"}"
assert_rpc_fails "openContainer rejects missing uuid" \
    "$SVC" openContainer "{\"devicefile\":\"$DEV_A\",\"passphrase\":\"x\"}"
assert_rpc_fails "openContainer rejects malformed uuid" \
    "$SVC" openContainer "{\"uuid\":\"not-a-uuid\",\"devicefile\":\"$DEV_A\",\"passphrase\":\"x\"}"
assert_rpc_fails "removeStaleAutoUnlockEntry rejects malformed uuid" \
    "$SVC" removeStaleAutoUnlockEntry '{"uuid":"not-a-uuid"}'
assert_rpc_fails "enableContainerAutoUnlock rejects a non-LUKS device" \
    "$SVC" enableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\",\"passphrase\":\"x\"}"
assert_rpc_fails "disableContainerAutoUnlock rejects a non-LUKS device" \
    "$SVC" disableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\"}"

# ---------------------------------------------------------------------------
section "createContainer"
# ---------------------------------------------------------------------------

assert_rpc "getContainerCandidates returns a list" \
    "$SVC" getContainerCandidates '{}' '^\['
if echo "$RPC_OUT" | grep -q "\"$DEV_A\""; then
    info "Blank loop device $DEV_A is listed as a candidate"
else
    info "Blank loop device $DEV_A is not listed as a candidate (loop devices may be filtered)"
fi

assert_rpc_fails "createContainer rejects missing devicefile" \
    "$SVC" createContainer "{\"passphrase\":\"$PASS_A\"}"
assert_rpc_fails "createContainer rejects an unknown cipher" \
    "$SVC" createContainer \
    "{\"devicefile\":\"$DEV_A\",\"cipher\":\"des-ecb\",\"lukslabel\":\"x\",\"passphrase\":\"$PASS_A\"}"
check "rejected cipher left A untouched" "" not_luks "$DEV_A"

assert_rpc "createContainer on A (aes-xts-plain64, label)" \
    "$SVC" createContainer \
    "{\"devicefile\":\"$DEV_A\",\"cipher\":\"aes-xts-plain64\",\"lukslabel\":\"$LABEL\",\"passphrase\":\"$PASS_A\"}"
udevadm settle
check "A is a LUKS device" "cryptsetup isLuks failed" is_luks "$DEV_A"
check "A unlocks with its passphrase" "" key_works "$DEV_A" "$PASS_A"
UUID_A=$(cryptsetup luksUUID "$DEV_A" 2>/dev/null)
UUIDS+=("$UUID_A")
info "UUID A: $UUID_A"
check "A uses aes-xts-plain64" "$(cryptsetup luksDump "$DEV_A" | grep -i cipher)" \
    grep -q "aes-xts-plain64" <(cryptsetup luksDump "$DEV_A")

assert_rpc "createContainer on B (aes-cbc-essiv:sha256)" \
    "$SVC" createContainer \
    "{\"devicefile\":\"$DEV_B\",\"cipher\":\"aes-cbc-essiv:sha256\",\"lukslabel\":\"${LABEL}b\",\"passphrase\":\"$PASS_B\"}"
udevadm settle
check "B is a LUKS device" "cryptsetup isLuks failed" is_luks "$DEV_B"
UUID_B=$(cryptsetup luksUUID "$DEV_B" 2>/dev/null)
UUIDS+=("$UUID_B")
check "B uses aes-cbc-essiv:sha256" "$(cryptsetup luksDump "$DEV_B" | grep -i cipher)" \
    grep -q "aes-cbc-essiv:sha256" <(cryptsetup luksDump "$DEV_B")

# C is formatted directly as LUKS1 to cover version-1 header parsing.
quick_format "$DEV_C" "$PASS_C" luks1
UUID_C=$(cryptsetup luksUUID "$DEV_C" 2>/dev/null)
UUIDS+=("$UUID_C")

assert_rpc "getContainerCandidates after create" \
    "$SVC" getContainerCandidates '{}'
check "LUKS device A is no longer a candidate" "A still listed" \
    eval "! echo \"\$RPC_OUT\" | grep -q '\"$DEV_A\"'"

# ---------------------------------------------------------------------------
section "enumerateContainers / getContainersList / getContainerDetails"
# ---------------------------------------------------------------------------

assert_rpc "enumerateContainers lists A" "$SVC" enumerateContainers '{}' "\"$UUID_A\""
assert_rpc "enumerateContainers lists B" "$SVC" enumerateContainers '{}' "\"$UUID_B\""
assert_rpc "enumerateContainers lists C" "$SVC" enumerateContainers '{}' "\"$UUID_C\""

v=$(container_field "$DEV_A" uuid);        check "A uuid"             "got '$v'" [ "$v" = "$UUID_A" ]
v=$(container_field "$DEV_A" luksversion); check "A luksversion is 2" "got '$v'" [ "$v" = "2" ]
v=$(container_field "$DEV_A" lukslabel);   check "A lukslabel"        "got '$v'" [ "$v" = "$LABEL" ]
v=$(container_field "$DEV_A" usedslots);   check "A usedslots is 1"   "got '$v'" [ "$v" = "1" ]
v=$(container_field "$DEV_A" unlocked);    check "A is locked"        "got '$v'" [ "$v" = "false" ]
v=$(container_field "$DEV_A" autounlock);  check "A autounlock false" "got '$v'" [ "$v" = "false" ]
v=$(container_field "$DEV_A" size);        check "A size is non-zero" "got '$v'" [ "${v:-0}" != "0" ]
v=$(container_field "$DEV_A" decrypteddevicefile)
check "A has no decrypted device while locked" "got '$v'" [ -z "$v" ]

v=$(container_field "$DEV_C" luksversion); check "C luksversion is 1"  "got '$v'" [ "$v" = "1" ]
v=$(container_field "$DEV_C" lukslabel);   check "C lukslabel is n/a"  "got '$v'" [ "$v" = "n/a" ]
v=$(container_field "$DEV_C" usedslots);   check "C usedslots is 1"    "got '$v'" [ "$v" = "1" ]

assert_rpc "getContainersList returns total/data" \
    "$SVC" getContainersList "$LIST_PARAMS" '"total"'
v=$(list_field "$UUID_A" _used); check "A _used is null while locked" "got '$v'" [ "$v" = "null" ]
v=$(list_field "$UUID_A" devicefile); check "A listed by getContainersList" "got '$v'" [ "$v" = "$DEV_A" ]

assert_rpc "getContainersList honours limit" \
    "$SVC" getContainersList '{"start":0,"limit":1,"sortfield":"devicefile","sortdir":"asc"}'
v=$(echo "$RPC_OUT" | python3 -c "import sys,json; print(len(json.load(sys.stdin)['data']))" 2>/dev/null)
check "getContainersList limit=1 returns one row" "got '$v' rows" [ "$v" = "1" ]

assert_rpc_fails "getContainersList rejects missing paging params" \
    "$SVC" getContainersList '{}'

assert_rpc "getContainerDetails on A" \
    "$SVC" getContainerDetails "{\"devicefile\":\"$DEV_A\"}" "$UUID_A"
check "details include LUKS header information" "" \
    grep -q "LUKS header information" <<<"$RPC_OUT"

# ---------------------------------------------------------------------------
section "openContainer / closeContainer"
# ---------------------------------------------------------------------------

OPEN_A="{\"uuid\":\"$UUID_A\",\"devicefile\":\"$DEV_A\",\"passphrase\":\"$PASS_A\"}"

assert_rpc_fails "openContainer with wrong passphrase fails" \
    "$SVC" openContainer "{\"uuid\":\"$UUID_A\",\"devicefile\":\"$DEV_A\",\"passphrase\":\"$WRONG\"}"
v=$(container_field "$DEV_A" unlocked)
check "A still locked after wrong passphrase" "got '$v'" [ "$v" = "false" ]

assert_rpc "openContainer without discards" "$SVC" openContainer "$OPEN_A"
v=$(container_field "$DEV_A" unlocked); check "A is unlocked" "got '$v'" [ "$v" = "true" ]
v=$(container_field "$DEV_A" decrypteddevicefile)
check "A decrypted device is /dev/mapper/$MAPPER_A" "got '$v'" [ "$v" = "/dev/mapper/$MAPPER_A" ]
check "mapping has no allow_discards when discards omitted" \
    "$(dmsetup table "$MAPPER_A" 2>&1)" dm_denies_discards "$MAPPER_A"
v=$(list_field "$UUID_A" _used); check "A _used is false (no fstab entry)" "got '$v'" [ "$v" = "false" ]

assert_rpc "openContainer on an already unlocked container is a no-op" \
    "$SVC" openContainer "$OPEN_A"

assert_rpc "closeContainer" "$SVC" closeContainer "{\"devicefile\":\"$DEV_A\"}"
v=$(container_field "$DEV_A" unlocked); check "A is locked" "got '$v'" [ "$v" = "false" ]
check "mapping removed" "" test ! -e "/dev/mapper/$MAPPER_A"

assert_rpc "closeContainer on a locked container is a no-op" \
    "$SVC" closeContainer "{\"devicefile\":\"$DEV_A\"}"

assert_rpc "openContainer with discards=false" \
    "$SVC" openContainer "{\"uuid\":\"$UUID_A\",\"devicefile\":\"$DEV_A\",\"passphrase\":\"$PASS_A\",\"discards\":false}"
check "mapping has no allow_discards when discards=false" \
    "$(dmsetup table "$MAPPER_A" 2>&1)" dm_denies_discards "$MAPPER_A"
rpc "$SVC" closeContainer "{\"devicefile\":\"$DEV_A\"}" >/dev/null 2>&1

assert_rpc "openContainer with discards=true" \
    "$SVC" openContainer "{\"uuid\":\"$UUID_A\",\"devicefile\":\"$DEV_A\",\"passphrase\":\"$PASS_A\",\"discards\":true}"
check "mapping has allow_discards when discards=true" \
    "$(dmsetup table "$MAPPER_A" 2>&1)" dm_allows_discards "$MAPPER_A"
if [ "$LOOP_DISCARD" -eq 1 ]; then
    check "decrypted device reports discard support" \
        "DISC-MAX=$(lsblk -dno DISC-MAX "/dev/mapper/$MAPPER_A" 2>&1)" \
        reports_discard "/dev/mapper/$MAPPER_A"
fi
rpc "$SVC" closeContainer "{\"devicefile\":\"$DEV_A\"}" >/dev/null 2>&1

assert_rpc_fails "openContainer rejects non-boolean discards" \
    "$SVC" openContainer "{\"uuid\":\"$UUID_A\",\"devicefile\":\"$DEV_A\",\"passphrase\":\"$PASS_A\",\"discards\":\"yes\"}"
cryptsetup close "$MAPPER_A" >/dev/null 2>&1 || true

assert_rpc "openContainer on a LUKS1 container" \
    "$SVC" openContainer "{\"uuid\":\"$UUID_C\",\"devicefile\":\"$DEV_C\",\"passphrase\":\"$PASS_C\"}"
v=$(container_field "$DEV_C" unlocked); check "C is unlocked" "got '$v'" [ "$v" = "true" ]
assert_rpc "closeContainer on a LUKS1 container" \
    "$SVC" closeContainer "{\"devicefile\":\"$DEV_C\"}"

# ---------------------------------------------------------------------------
section "openContainer — mount on unlock"
# ---------------------------------------------------------------------------
# openContainer mounts a filesystem inside the container if it has an OMV
# mount point.  systemd may mount the same /etc/fstab entry as soon as the
# decrypted device appears; that race must not make openContainer fail.

quick_format "$DEV_D" "$PASS_D" luks2
UUID_D=$(cryptsetup luksUUID "$DEV_D" 2>/dev/null); UUIDS+=("$UUID_D")
OPEN_D="{\"uuid\":\"$UUID_D\",\"devicefile\":\"$DEV_D\",\"passphrase\":\"$PASS_D\"}"
quick_open "$DEV_D" "$PASS_D"
mkfs.ext4 -q -F "/dev/mapper/$MAPPER_D" >/dev/null
udevadm settle
FSUUID_D=$(blkid -s UUID -o value "/dev/mapper/$MAPPER_D")
cryptsetup close "$MAPPER_D"
udevadm settle

if m=$(add_mntent "$FSUUID_D" ext4 "$MNT_EXT4") && [ -n "$m" ]; then
    MNTENTS+=("$m")

    assert_rpc "openContainer mounts the filesystem inside" "$SVC" openContainer "$OPEN_D"
    check "ext4 filesystem mounted on $MNT_EXT4" "$(findmnt "$MNT_EXT4" 2>&1)" is_mounted "$MNT_EXT4"
    v=$(findmnt -n -o UUID "$MNT_EXT4" 2>/dev/null)
    check "the mounted filesystem is D's" "got '$v'" [ "$v" = "$FSUUID_D" ]
    v=$(list_field "$UUID_D" _used); check "D _used is true (has a mount point)" "got '$v'" [ "$v" = "true" ]

    assert_rpc "openContainer on an unlocked, mounted container is a no-op" \
        "$SVC" openContainer "$OPEN_D"
    v=$(mount_count "$MNT_EXT4"); check "filesystem still mounted once" "got $v mounts" [ "$v" = "1" ]

    umount "$MNT_EXT4"
    assert_rpc "openContainer mounts the filesystem of an already unlocked container" \
        "$SVC" openContainer "$OPEN_D"
    check "filesystem remounted" "" is_mounted "$MNT_EXT4"

    # Let something else mount the filesystem while openContainer runs.
    for i in 1 2 3; do
        umount "$MNT_EXT4" >/dev/null 2>&1
        rpc "$SVC" closeContainer "{\"devicefile\":\"$DEV_D\"}" >/dev/null 2>&1
        race_mount "$MAPPER_D" "$MNT_EXT4" & RACER=$!
        assert_rpc "openContainer succeeds when the filesystem is mounted concurrently (#$i)" \
            "$SVC" openContainer "$OPEN_D"
        wait "$RACER"; RACER=""
        check "filesystem mounted after race (#$i)" "" is_mounted "$MNT_EXT4"
        v=$(mount_count "$MNT_EXT4"); check "filesystem mounted once after race (#$i)" "got $v mounts" [ "$v" = "1" ]
    done

    umount "$MNT_EXT4" >/dev/null 2>&1
    assert_rpc "closeContainer after unmounting" "$SVC" closeContainer "{\"devicefile\":\"$DEV_D\"}"
    check "D mapping removed" "" test ! -e "/dev/mapper/$MAPPER_D"
else
    _fail "register an OMV mount point for D's ext4 filesystem" "FsTab set failed"
fi

# A multi-device BTRFS filesystem must only be mounted once all of its
# containers are unlocked.
if command -v mkfs.btrfs >/dev/null 2>&1; then
    quick_format "$DEV_D" "$PASS_D" luks2
    UUID_D=$(cryptsetup luksUUID "$DEV_D" 2>/dev/null); UUIDS+=("$UUID_D")
    quick_format "$DEV_E" "$PASS_E" luks2
    UUID_E=$(cryptsetup luksUUID "$DEV_E" 2>/dev/null); UUIDS+=("$UUID_E")
    OPEN_D="{\"uuid\":\"$UUID_D\",\"devicefile\":\"$DEV_D\",\"passphrase\":\"$PASS_D\"}"
    OPEN_E="{\"uuid\":\"$UUID_E\",\"devicefile\":\"$DEV_E\",\"passphrase\":\"$PASS_E\"}"
    quick_open "$DEV_D" "$PASS_D"
    quick_open "$DEV_E" "$PASS_E"
    mkfs.btrfs -q -f -d raid1 -m raid1 "/dev/mapper/$MAPPER_D" "/dev/mapper/$MAPPER_E" >/dev/null
    udevadm settle
    FSUUID_BTRFS=$(blkid -s UUID -o value "/dev/mapper/$MAPPER_D")
    cryptsetup close "$MAPPER_D"
    cryptsetup close "$MAPPER_E"
    udevadm settle

    if m=$(add_mntent "$FSUUID_BTRFS" btrfs "$MNT_BTRFS") && [ -n "$m" ]; then
        MNTENTS+=("$m")
        assert_rpc "openContainer on the first of two BTRFS devices" "$SVC" openContainer "$OPEN_D"
        check "incomplete BTRFS filesystem not mounted" "$(findmnt "$MNT_BTRFS" 2>&1)" \
            not_mounted "$MNT_BTRFS"
        assert_rpc "openContainer on the second BTRFS device" "$SVC" openContainer "$OPEN_E"
        check "complete BTRFS filesystem mounted" "" is_mounted "$MNT_BTRFS"
        v=$(findmnt -n -o UUID "$MNT_BTRFS" 2>/dev/null)
        check "the mounted filesystem is the BTRFS one" "got '$v'" [ "$v" = "$FSUUID_BTRFS" ]
        umount "$MNT_BTRFS" >/dev/null 2>&1
    else
        _fail "register an OMV mount point for the BTRFS filesystem" "FsTab set failed"
    fi
    rpc "$SVC" closeContainer "{\"devicefile\":\"$DEV_D\"}" >/dev/null 2>&1
    rpc "$SVC" closeContainer "{\"devicefile\":\"$DEV_E\"}" >/dev/null 2>&1
else
    info "mkfs.btrfs not found; skipping multi-device BTRFS mount tests"
fi

# A filesystem on a logical volume inside the container is mounted once the
# volume group is activated.  The hyphenated names make the /dev/mapper name
# differ from <vg>-<lv>.
if command -v pvcreate >/dev/null 2>&1; then
    quick_format "$DEV_D" "$PASS_D" luks2
    UUID_D=$(cryptsetup luksUUID "$DEV_D" 2>/dev/null); UUIDS+=("$UUID_D")
    OPEN_D="{\"uuid\":\"$UUID_D\",\"devicefile\":\"$DEV_D\",\"passphrase\":\"$PASS_D\"}"
    quick_open "$DEV_D" "$PASS_D"
    pvcreate -q -y "/dev/mapper/$MAPPER_D" >/dev/null
    vgcreate -q "$VG_NAME" "/dev/mapper/$MAPPER_D" >/dev/null
    lvcreate -q -y -n "$LV_NAME" -L 64M "$VG_NAME" >/dev/null
    udevadm settle
    mkfs.ext4 -q -F "/dev/$VG_NAME/$LV_NAME" >/dev/null
    udevadm settle
    FSUUID_LV=$(blkid -s UUID -o value "/dev/$VG_NAME/$LV_NAME")
    vgchange -q -a n "$VG_NAME" >/dev/null
    cryptsetup close "$MAPPER_D"
    udevadm settle

    if m=$(add_mntent "$FSUUID_LV" ext4 "$MNT_LVM") && [ -n "$m" ]; then
        MNTENTS+=("$m")
        assert_rpc "openContainer on a container holding an LVM volume group" \
            "$SVC" openContainer "$OPEN_D"
        check "logical volume activated" "" test -e "/dev/$VG_NAME/$LV_NAME"
        check "filesystem on the logical volume mounted" "$(findmnt "$MNT_LVM" 2>&1)" \
            is_mounted "$MNT_LVM"
        v=$(findmnt -n -o UUID "$MNT_LVM" 2>/dev/null)
        check "the mounted filesystem is the logical volume's" "got '$v'" [ "$v" = "$FSUUID_LV" ]
        umount "$MNT_LVM" >/dev/null 2>&1
    else
        _fail "register an OMV mount point for the LVM filesystem" "FsTab set failed"
    fi
    vgremove -q -f "$VG_NAME" >/dev/null 2>&1
    pvremove -q -f "/dev/mapper/$MAPPER_D" >/dev/null 2>&1
    cryptsetup close "$MAPPER_D" >/dev/null 2>&1

    # A physical volume that is not in any volume group is left alone.
    quick_format "$DEV_E" "$PASS_E" luks2
    UUID_E=$(cryptsetup luksUUID "$DEV_E" 2>/dev/null); UUIDS+=("$UUID_E")
    quick_open "$DEV_E" "$PASS_E"
    pvcreate -q -y "/dev/mapper/$MAPPER_E" >/dev/null
    cryptsetup close "$MAPPER_E"
    udevadm settle
    assert_rpc "openContainer on a container holding a PV without a volume group" \
        "$SVC" openContainer "{\"uuid\":\"$UUID_E\",\"devicefile\":\"$DEV_E\",\"passphrase\":\"$PASS_E\"}"
    v=$(container_field "$DEV_E" unlocked); check "E is unlocked" "got '$v'" [ "$v" = "true" ]
    pvremove -q -f "/dev/mapper/$MAPPER_E" >/dev/null 2>&1
    rpc "$SVC" closeContainer "{\"devicefile\":\"$DEV_E\"}" >/dev/null 2>&1
else
    info "pvcreate not found; skipping LVM mount tests"
fi

# ---------------------------------------------------------------------------
section "Key management"
# ---------------------------------------------------------------------------

KEY_A="\"uuid\":\"$UUID_A\",\"devicefile\":\"$DEV_A\""

assert_rpc "testContainerKey with correct passphrase returns slot 0" \
    "$SVC" testContainerKey "{$KEY_A,\"passphrase\":\"$PASS_A\"}" '^"\?0"\?$'
assert_rpc_fails "testContainerKey with wrong passphrase fails" \
    "$SVC" testContainerKey "{$KEY_A,\"passphrase\":\"$WRONG\"}"

assert_rpc_fails "addContainerKey with wrong current passphrase fails" \
    "$SVC" addContainerKey "{$KEY_A,\"oldpassphrase\":\"$WRONG\",\"newpassphrase\":\"$PASS_A2\"}"
check "new passphrase not added after failure" "" key_fails "$DEV_A" "$PASS_A2"
v=$(container_field "$DEV_A" usedslots); check "A usedslots still 1" "got '$v'" [ "$v" = "1" ]

assert_rpc "addContainerKey (passphrase → passphrase)" \
    "$SVC" addContainerKey "{$KEY_A,\"oldpassphrase\":\"$PASS_A\",\"newpassphrase\":\"$PASS_A2\"}"
check "new passphrase unlocks A" "" key_works "$DEV_A" "$PASS_A2"
check "original passphrase still unlocks A" "" key_works "$DEV_A" "$PASS_A"
v=$(container_field "$DEV_A" usedslots); check "A usedslots is 2" "got '$v'" [ "$v" = "2" ]
assert_rpc "testContainerKey with added passphrase returns slot 1" \
    "$SVC" testContainerKey "{$KEY_A,\"passphrase\":\"$PASS_A2\"}" '^"\?1"\?$'

assert_rpc "changeContainerKey (slot 1 passphrase → new passphrase)" \
    "$SVC" changeContainerKey "{$KEY_A,\"oldpassphrase\":\"$PASS_A2\",\"newpassphrase\":\"$PASS_A3\"}"
check "changed passphrase unlocks A" "" key_works "$DEV_A" "$PASS_A3"
check "old slot-1 passphrase no longer unlocks A" "" key_fails "$DEV_A" "$PASS_A2"
check "slot-0 passphrase unaffected by change" "" key_works "$DEV_A" "$PASS_A"
v=$(container_field "$DEV_A" usedslots); check "A usedslots still 2 after change" "got '$v'" [ "$v" = "2" ]

assert_rpc_fails "changeContainerKey with wrong current passphrase fails" \
    "$SVC" changeContainerKey "{$KEY_A,\"oldpassphrase\":\"$WRONG\",\"newpassphrase\":\"$PASS_A2\"}"
check "wrong change left key unchanged" "" key_works "$DEV_A" "$PASS_A3"

assert_rpc_fails "removeContainerKey with a passphrase not on the device fails" \
    "$SVC" removeContainerKey "{$KEY_A,\"passphrase\":\"$WRONG\"}"
v=$(container_field "$DEV_A" usedslots); check "A usedslots still 2" "got '$v'" [ "$v" = "2" ]

assert_rpc "removeContainerKey removes the changed passphrase" \
    "$SVC" removeContainerKey "{$KEY_A,\"passphrase\":\"$PASS_A3\"}"
check "removed passphrase no longer unlocks A" "" key_fails "$DEV_A" "$PASS_A3"
check "remaining passphrase still unlocks A" "" key_works "$DEV_A" "$PASS_A"
v=$(container_field "$DEV_A" usedslots); check "A usedslots back to 1" "got '$v'" [ "$v" = "1" ]

# Key files: add, test, open with, change from, remove.
assert_rpc "addContainerKey (passphrase → key file)" \
    "$SVC" addContainerKey "{$KEY_A,\"oldpassphrase\":\"$PASS_A\",\"newkeyfile\":\"$KEYFILE\"}"
check "key file unlocks A" "" keyfile_works "$DEV_A" "$KEYFILE"
assert_rpc "testContainerKey with key file" \
    "$SVC" testContainerKey "{$KEY_A,\"keyfile\":\"$KEYFILE\"}" '^"\?1"\?$'

assert_rpc "openContainer with key file" \
    "$SVC" openContainer "{$KEY_A,\"keyfile\":\"$KEYFILE\"}"
v=$(container_field "$DEV_A" unlocked); check "A unlocked via key file" "got '$v'" [ "$v" = "true" ]
rpc "$SVC" closeContainer "{\"devicefile\":\"$DEV_A\"}" >/dev/null 2>&1

assert_rpc "addContainerKey (key file → passphrase)" \
    "$SVC" addContainerKey "{$KEY_A,\"oldkeyfile\":\"$KEYFILE\",\"newpassphrase\":\"$PASS_A2\"}"
check "passphrase added via key file unlocks A" "" key_works "$DEV_A" "$PASS_A2"

assert_rpc "removeContainerKey with key file" \
    "$SVC" removeContainerKey "{$KEY_A,\"keyfile\":\"$KEYFILE\"}"
check "removed key file no longer unlocks A" "" eval "! keyfile_works '$DEV_A' '$KEYFILE'"

# Kill slots: the passphrase added via key file sits in a slot we can erase.
SLOT=$(echo -n "$PASS_A2" | cryptsetup open -v --test-passphrase "$DEV_A" --key-file=- 2>&1 \
    | awk '/Key slot/ {print $3; exit}')
info "PASS_A2 is in slot ${SLOT:-?}"
assert_rpc "killContainerKeySlot erases slot $SLOT" \
    "$SVC" killContainerKeySlot "{$KEY_A,\"keyslot\":${SLOT:-1}}"
check "erased slot's passphrase no longer unlocks A" "" key_fails "$DEV_A" "$PASS_A2"
check "slot-0 passphrase still unlocks A" "" key_works "$DEV_A" "$PASS_A"
v=$(container_field "$DEV_A" usedslots); check "A usedslots is 1 after kill" "got '$v'" [ "$v" = "1" ]

assert_rpc_fails "killContainerKeySlot on an empty slot fails" \
    "$SVC" killContainerKeySlot "{$KEY_A,\"keyslot\":5}"
assert_rpc_fails "killContainerKeySlot rejects keyslot 32" \
    "$SVC" killContainerKeySlot "{$KEY_A,\"keyslot\":32}"
assert_rpc_fails "killContainerKeySlot rejects keyslot -1" \
    "$SVC" killContainerKeySlot "{$KEY_A,\"keyslot\":-1}"
assert_rpc_fails "killContainerKeySlot rejects missing keyslot" \
    "$SVC" killContainerKeySlot "{$KEY_A}"

# LUKS2 key slots go up to 31.
echo -n "$PASS_A" | cryptsetup luksAddKey -q --key-slot 12 \
    --pbkdf pbkdf2 --pbkdf-force-iterations 1000 "$DEV_A" "$KEYFILE" --key-file=- >/dev/null 2>&1
v=$(container_field "$DEV_A" usedslots); check "A usedslots counts LUKS2 slot 12" "got '$v'" [ "$v" = "2" ]
assert_rpc "testContainerKey reports LUKS2 slot 12" \
    "$SVC" testContainerKey "{$KEY_A,\"keyfile\":\"$KEYFILE\"}" '^"\?12"\?$'
assert_rpc "killContainerKeySlot erases LUKS2 slot 12" \
    "$SVC" killContainerKeySlot "{$KEY_A,\"keyslot\":12}"
check "erased slot-12 key no longer unlocks A" "" eval "! keyfile_works '$DEV_A' '$KEYFILE'"
v=$(container_field "$DEV_A" usedslots); check "A usedslots back to 1" "got '$v'" [ "$v" = "1" ]

assert_rpc "addContainerKey on a LUKS1 container" \
    "$SVC" addContainerKey "{\"uuid\":\"$UUID_C\",\"devicefile\":\"$DEV_C\",\"oldpassphrase\":\"$PASS_C\",\"newpassphrase\":\"$PASS_A2\"}"
v=$(container_field "$DEV_C" usedslots); check "C (LUKS1) usedslots is 2" "got '$v'" [ "$v" = "2" ]
assert_rpc "removeContainerKey on a LUKS1 container" \
    "$SVC" removeContainerKey "{\"uuid\":\"$UUID_C\",\"devicefile\":\"$DEV_C\",\"passphrase\":\"$PASS_A2\"}"
v=$(container_field "$DEV_C" usedslots); check "C (LUKS1) usedslots back to 1" "got '$v'" [ "$v" = "1" ]

# ---------------------------------------------------------------------------
section "Header backup / restore"
# ---------------------------------------------------------------------------

assert_rpc "backupContainerHeader on A" \
    "$SVC" backupContainerHeader "{\"devicefile\":\"$DEV_A\"}" '"filepath"'
HDR_A=$(echo "$RPC_OUT" | json_field filepath)
HDR_NAME=$(echo "$RPC_OUT" | json_field filename)
[ -n "$HDR_A" ] && TMP_FILES+=("$HDR_A")
check "backup file exists"                 "path='$HDR_A'" test -s "$HDR_A"
check "backup file is a valid LUKS header" "" is_luks "$HDR_A"
check "backup file has mode 0600" "$(stat -c %a "$HDR_A" 2>&1)" \
    [ "$(stat -c %a "$HDR_A" 2>/dev/null)" = "600" ]
check "backup filename contains the UUID" "got '$HDR_NAME'" \
    eval "[[ '$HDR_NAME' == LUKS_header_*${UUID_A}.bak ]]"
check "backup unlink flag is set" "" \
    grep -q '"unlink": *true' <<<"$RPC_OUT"
# Keep a copy: the WebGUI normally deletes the backup after download.
HDR_COPY=$(mktemp /var/tmp/omv-luks-hdr.XXXXXX); TMP_FILES+=("$HDR_COPY")
cp "$HDR_A" "$HDR_COPY"

assert_rpc "backupContainerHeader on B" \
    "$SVC" backupContainerHeader "{\"devicefile\":\"$DEV_B\"}" '"filepath"'
HDR_B=$(echo "$RPC_OUT" | json_field filepath)
[ -n "$HDR_B" ] && TMP_FILES+=("$HDR_B")

# Add a key after the backup; restoring the backup should drop it.
rpc "$SVC" addContainerKey "{$KEY_A,\"oldpassphrase\":\"$PASS_A\",\"newpassphrase\":\"$PASS_A2\"}" >/dev/null 2>&1
check "key added after backup unlocks A" "" key_works "$DEV_A" "$PASS_A2"

RESTORE_A="\"uuid\":\"$UUID_A\",\"devicefile\":\"$DEV_A\",\"filename\":\"a.bak\""

assert_rpc_fails "restoreContainerHeader rejects a non-LUKS file" \
    "$SVC" restoreContainerHeader "{$RESTORE_A,\"force\":false,\"filepath\":\"$JUNK_FILE\"}"
assert_rpc_fails "restoreContainerHeader rejects another container's header (UUID mismatch)" \
    "$SVC" restoreContainerHeader "{$RESTORE_A,\"force\":false,\"filepath\":\"$HDR_B\"}"
assert_rpc_fails "restoreContainerHeader checks the device's UUID, not the one supplied" \
    "$SVC" restoreContainerHeader \
    "{\"uuid\":\"$UUID_B\",\"devicefile\":\"$DEV_A\",\"filename\":\"b.bak\",\"force\":false,\"filepath\":\"$HDR_B\"}"
v=$(cryptsetup luksUUID "$DEV_A" 2>/dev/null)
check "A UUID unchanged after rejected restore" "got '$v'" [ "$v" = "$UUID_A" ]
rpc "$SVC" openContainer "$OPEN_A" >/dev/null 2>&1
assert_rpc_fails "restoreContainerHeader refuses an unlocked container (even with force)" \
    "$SVC" restoreContainerHeader "{$RESTORE_A,\"force\":true,\"filepath\":\"$HDR_B\"}"
rpc "$SVC" closeContainer "{\"devicefile\":\"$DEV_A\"}" >/dev/null 2>&1
v=$(cryptsetup luksUUID "$DEV_A" 2>/dev/null)
check "A UUID unchanged after refused restore" "got '$v'" [ "$v" = "$UUID_A" ]
assert_rpc_fails "restoreContainerHeader rejects missing force" \
    "$SVC" restoreContainerHeader "{$RESTORE_A,\"filepath\":\"$HDR_COPY\"}"

assert_rpc "restoreContainerHeader with matching UUID" \
    "$SVC" restoreContainerHeader "{$RESTORE_A,\"force\":false,\"filepath\":\"$HDR_COPY\"}"
check "key added after backup is gone after restore" "" key_fails "$DEV_A" "$PASS_A2"
check "original passphrase unlocks A after restore" "" key_works "$DEV_A" "$PASS_A"
v=$(container_field "$DEV_A" usedslots); check "A usedslots is 1 after restore" "got '$v'" [ "$v" = "1" ]

# The uploaded file path must be passed to the shell quoted.  Unquoted, the
# spaces split it into several arguments and the header check fails.
HDR_ODD="/var/tmp/omv luks hdr;\$HOME & 'x' $$"
TMP_FILES+=("$HDR_ODD")
cp "$HDR_COPY" "$HDR_ODD"
assert_rpc "restoreContainerHeader with shell metacharacters in filepath" \
    "$SVC" restoreContainerHeader \
    "{$RESTORE_A,\"force\":false,\"filepath\":\"$HDR_ODD\"}"
check "A unlocks after restore from odd path" "" key_works "$DEV_A" "$PASS_A"

# ---------------------------------------------------------------------------
section "Auto-unlock — without discards"
# ---------------------------------------------------------------------------

assert_rpc_fails "enableContainerAutoUnlock with wrong passphrase fails" \
    "$SVC" enableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\",\"passphrase\":\"$WRONG\"}"
check "failed enable leaves no crypttab entry" "got '$(crypttab_options "$UUID_A")'" \
    [ -z "$(crypttab_options "$UUID_A")" ]
check "failed enable leaves no key file" "" test ! -e "$KEY_DIR/$UUID_A"
v=$(container_field "$DEV_A" usedslots); check "failed enable adds no key slot" "got '$v'" [ "$v" = "1" ]

assert_rpc_fails "disableContainerAutoUnlock when not enabled fails" \
    "$SVC" disableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\"}"

assert_rpc "enableContainerAutoUnlock (discards omitted)" \
    "$SVC" enableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\",\"passphrase\":\"$PASS_A\"}"
OPTS=$(crypttab_options "$UUID_A")
check "crypttab entry written ($OPTS)" "no entry for UUID=$UUID_A" [ -n "$OPTS" ]
check "crypttab options include luks"   "'$OPTS'" has_opt   "$OPTS" luks
check "crypttab options include nofail" "'$OPTS'" has_opt   "$OPTS" nofail
check "crypttab options omit discard"   "'$OPTS'" lacks_opt "$OPTS" discard
check "crypttab entry name is luks-<uuid>" "$(grep "UUID=$UUID_A" /etc/crypttab)" \
    grep -q "^luks-${UUID_A}[[:space:]]" /etc/crypttab
check "crypttab entry points at $KEY_DIR/<uuid>" "$(grep "UUID=$UUID_A" /etc/crypttab)" \
    grep -q "[[:space:]]$KEY_DIR/${UUID_A}[[:space:]]" /etc/crypttab
check "key file has mode 0400" "$(ls -l "$KEY_DIR/$UUID_A" 2>&1)" \
    [ "$(stat -c %a "$KEY_DIR/$UUID_A" 2>/dev/null)" = "400" ]
check "key directory has mode 0700" "$(stat -c %a "$KEY_DIR" 2>&1)" \
    [ "$(stat -c %a "$KEY_DIR" 2>/dev/null)" = "700" ]
check "key file is 512 bytes" "$(stat -c %s "$KEY_DIR/$UUID_A" 2>&1)" \
    [ "$(stat -c %s "$KEY_DIR/$UUID_A" 2>/dev/null)" = "512" ]
check "key file unlocks A" "" keyfile_works "$DEV_A" "$KEY_DIR/$UUID_A"
v=$(container_field "$DEV_A" usedslots); check "enable added a key slot" "got '$v'" [ "$v" = "2" ]
v=$(container_field "$DEV_A" autounlock); check "enumerate autounlock is true" "got '$v'" [ "$v" = "true" ]
v=$(container_field "$DEV_A" autounlockmethod); check "enumerate autounlockmethod is keyfile" "got '$v'" [ "$v" = "keyfile" ]
v=$(list_field "$UUID_A" stale); check "live container is not stale" "got '$v'" [ "$v" != "true" ]

assert_rpc_fails "enableContainerAutoUnlock twice fails" \
    "$SVC" enableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\",\"passphrase\":\"$PASS_A\",\"discards\":true}"
check "second enable did not change crypttab options" "'$(crypttab_options "$UUID_A")'" \
    lacks_opt "$(crypttab_options "$UUID_A")" discard
check "second enable left a single crypttab entry" "" \
    [ "$(grep -c "UUID=$UUID_A" /etc/crypttab)" = "1" ]

if boot_unlock "$UUID_A"; then
    _pass "systemd-cryptsetup unlocks A from crypttab"
    check "boot-unlocked mapping has no allow_discards" \
        "$(dmsetup table "luks-$UUID_A" 2>&1)" dm_denies_discards "luks-$UUID_A"
    v=$(container_field "$DEV_A" unlocked)
    check "enumerate shows boot-unlocked A as unlocked" "got '$v'" [ "$v" = "true" ]
    v=$(container_field "$DEV_A" decrypteddevicefile)
    check "decrypted device is /dev/mapper/luks-<uuid>" "got '$v'" [ "$v" = "/dev/mapper/luks-$UUID_A" ]
    assert_rpc "closeContainer locks a boot-unlocked container" \
        "$SVC" closeContainer "{\"devicefile\":\"$DEV_A\"}"
    check "boot mapping removed" "" test ! -e "/dev/mapper/luks-$UUID_A"
else
    _fail "systemd-cryptsetup unlocks A from crypttab" \
        "$(systemctl status "$(boot_unit_of "$UUID_A")" 2>&1 | tail -5)"
fi
boot_lock "$UUID_A"

assert_rpc "disableContainerAutoUnlock" \
    "$SVC" disableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\"}"
check "disable removes crypttab entry" "'$(crypttab_options "$UUID_A")'" [ -z "$(crypttab_options "$UUID_A")" ]
check "disable removes key file" "" test ! -e "$KEY_DIR/$UUID_A"
v=$(container_field "$DEV_A" usedslots); check "disable removes the key slot" "got '$v'" [ "$v" = "1" ]
v=$(container_field "$DEV_A" autounlock); check "enumerate autounlock is false" "got '$v'" [ "$v" = "false" ]
v=$(container_field "$DEV_A" autounlockmethod); check "enumerate autounlockmethod is empty" "got '$v'" [ -z "$v" ]
check "passphrase still unlocks A after disable" "" key_works "$DEV_A" "$PASS_A"

# ---------------------------------------------------------------------------
section "Auto-unlock — with discards"
# ---------------------------------------------------------------------------

assert_rpc_fails "enableContainerAutoUnlock rejects non-boolean discards" \
    "$SVC" enableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\",\"passphrase\":\"$PASS_A\",\"discards\":\"yes\"}"
check "rejected enable leaves no crypttab entry" "" [ -z "$(crypttab_options "$UUID_A")" ]

assert_rpc "enableContainerAutoUnlock with discards=false" \
    "$SVC" enableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\",\"passphrase\":\"$PASS_A\",\"discards\":false}"
check "discards=false omits discard" "'$(crypttab_options "$UUID_A")'" \
    lacks_opt "$(crypttab_options "$UUID_A")" discard
rpc "$SVC" disableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\"}" >/dev/null 2>&1

assert_rpc "enableContainerAutoUnlock with discards=true" \
    "$SVC" enableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\",\"passphrase\":\"$PASS_A\",\"discards\":true}"
OPTS=$(crypttab_options "$UUID_A")
check "crypttab options include luks"    "'$OPTS'" has_opt "$OPTS" luks
check "crypttab options include nofail"  "'$OPTS'" has_opt "$OPTS" nofail
check "crypttab options include discard" "'$OPTS'" has_opt "$OPTS" discard

if boot_unlock "$UUID_A"; then
    _pass "systemd-cryptsetup unlocks A from crypttab"
    check "boot-unlocked mapping has allow_discards" \
        "$(dmsetup table "luks-$UUID_A" 2>&1)" dm_allows_discards "luks-$UUID_A"
    if [ "$LOOP_DISCARD" -eq 1 ]; then
        check "boot-unlocked device reports discard support" \
            "DISC-MAX=$(lsblk -dno DISC-MAX "/dev/mapper/luks-$UUID_A" 2>&1)" \
            reports_discard "/dev/mapper/luks-$UUID_A"
    fi
else
    _fail "systemd-cryptsetup unlocks A from crypttab" \
        "$(systemctl status "$(boot_unit_of "$UUID_A")" 2>&1 | tail -5)"
fi
boot_lock "$UUID_A"

rpc "$SVC" disableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\"}" >/dev/null 2>&1

# Auto-unlock can also be enabled with an existing key file.
rpc "$SVC" addContainerKey "{$KEY_A,\"oldpassphrase\":\"$PASS_A\",\"newkeyfile\":\"$KEYFILE\"}" >/dev/null 2>&1
assert_rpc "enableContainerAutoUnlock with a key file" \
    "$SVC" enableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\",\"keyfile\":\"$KEYFILE\"}"
check "generated key file unlocks A" "" keyfile_works "$DEV_A" "$KEY_DIR/$UUID_A"
assert_rpc "disableContainerAutoUnlock" \
    "$SVC" disableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\"}"
check "supplied key file still unlocks A after disable" "" keyfile_works "$DEV_A" "$KEYFILE"
rpc "$SVC" removeContainerKey "{$KEY_A,\"keyfile\":\"$KEYFILE\"}" >/dev/null 2>&1

# Auto-unlock on a LUKS1 container.
assert_rpc "enableContainerAutoUnlock on a LUKS1 container" \
    "$SVC" enableContainerAutoUnlock "{\"devicefile\":\"$DEV_C\",\"passphrase\":\"$PASS_C\"}"
check "LUKS1 key file unlocks C" "" keyfile_works "$DEV_C" "$KEY_DIR/$UUID_C"
assert_rpc "disableContainerAutoUnlock on a LUKS1 container" \
    "$SVC" disableContainerAutoUnlock "{\"devicefile\":\"$DEV_C\"}"
v=$(container_field "$DEV_C" usedslots); check "C usedslots back to 1" "got '$v'" [ "$v" = "1" ]

# ---------------------------------------------------------------------------
section "Auto-unlock — Clevis"
# ---------------------------------------------------------------------------

assert_rpc_fails "enableContainerAutoUnlock rejects an unknown method" \
    "$SVC" enableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\",\"passphrase\":\"$PASS_A\",\"method\":\"bogus\"}"
assert_rpc_fails "enableContainerAutoUnlock rejects a non-http Tang URL" \
    "$SVC" enableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\",\"passphrase\":\"$PASS_A\",\"method\":\"tang\",\"tangurl\":\"ftp://tang\"}"
assert_rpc_fails "enableContainerAutoUnlock rejects a bad Tang thumbprint" \
    "$SVC" enableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\",\"passphrase\":\"$PASS_A\",\"method\":\"tang\",\"tangurl\":\"http://tang\",\"tangthp\":\"a b\"}"
assert_rpc_fails "tang method without a URL fails" \
    "$SVC" enableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\",\"passphrase\":\"$PASS_A\",\"method\":\"tang\"}"
assert_rpc_fails "tang method with wrong passphrase fails" \
    "$SVC" enableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\",\"passphrase\":\"$WRONG\",\"method\":\"tang\",\"tangurl\":\"http://tang.invalid\"}"
check "failed Clevis enable leaves no crypttab entry" "got '$(crypttab_options "$UUID_A")'" \
    [ -z "$(crypttab_options "$UUID_A")" ]
v=$(container_field "$DEV_A" usedslots); check "failed Clevis enable adds no key slot" "got '$v'" [ "$v" = "1" ]

if [ ! -e /dev/tpmrm0 ] && [ ! -e /dev/tpm0 ]; then
    assert_rpc_fails "tpm2 method without a TPM fails" \
        "$SVC" enableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\",\"passphrase\":\"$PASS_A\",\"method\":\"tpm2\"}"
    check "failed TPM2 enable leaves no crypttab entry" "" [ -z "$(crypttab_options "$UUID_A")" ]
fi

# Enable Clevis method $1 (with extra JSON params $2) on A, verify the binding
# and the crypttab entry, unlock it as at boot, then disable it again.
clevis_roundtrip() {
    local method=$1 extra=$2 netdev=$3; shift 3
    local pins=("$@") opts v p
    assert_rpc "enableContainerAutoUnlock method=$method" \
        "$SVC" enableContainerAutoUnlock \
        "{\"devicefile\":\"$DEV_A\",\"passphrase\":\"$PASS_A\",\"method\":\"$method\"$extra}" || return
    check "clevis is installed" "" test -x /usr/bin/clevis
    check "clevis-luks-askpass.path is enabled" "" systemctl -q is-enabled clevis-luks-askpass.path
    opts=$(crypttab_options "$UUID_A")
    check "crypttab key file is none" "got '$(crypttab_keyfile "$UUID_A")'" \
        [ "$(crypttab_keyfile "$UUID_A")" = "none" ]
    check "crypttab options include luks"   "'$opts'" has_opt "$opts" luks
    check "crypttab options include nofail" "'$opts'" has_opt "$opts" nofail
    if [ "$netdev" = 1 ]; then
        check "crypttab options include _netdev" "'$opts'" has_opt "$opts" _netdev
    else
        check "crypttab options omit _netdev" "'$opts'" lacks_opt "$opts" _netdev
    fi
    for p in "${pins[@]}"; do
        check "container is bound with clevis pin $p" "$(clevis luks list -d "$DEV_A" 2>&1)" \
            grep -qx "$p" <(clevis_pins "$DEV_A")
    done
    check "no key file stored" "" test ! -e "$KEY_DIR/$UUID_A"
    v=$(container_field "$DEV_A" usedslots);        check "enable added a key slot" "got '$v'" [ "$v" = "2" ]
    v=$(container_field "$DEV_A" autounlock);       check "enumerate autounlock is true" "got '$v'" [ "$v" = "true" ]
    v=$(container_field "$DEV_A" autounlockmethod); check "enumerate autounlockmethod is clevis" "got '$v'" [ "$v" = "clevis" ]
    if boot_unlock "$UUID_A"; then
        _pass "systemd-cryptsetup unlocks A via clevis"
        check "clevis-unlocked mapping exists" "" test -e "/dev/mapper/luks-$UUID_A"
    else
        _fail "systemd-cryptsetup unlocks A via clevis" \
            "$(systemctl status "$(boot_unit_of "$UUID_A")" 2>&1 | tail -5)"
    fi
    boot_lock "$UUID_A"
    assert_rpc "disableContainerAutoUnlock method=$method" \
        "$SVC" disableContainerAutoUnlock "{\"devicefile\":\"$DEV_A\"}"
    check "disable removes crypttab entry" "" [ -z "$(crypttab_options "$UUID_A")" ]
    check "disable removes clevis binding" "$(clevis luks list -d "$DEV_A" 2>&1)" \
        [ -z "$(clevis_pins "$DEV_A")" ]
    v=$(container_field "$DEV_A" usedslots); check "disable removes the key slot" "got '$v'" [ "$v" = "1" ]
    check "passphrase still unlocks A after disable" "" key_works "$DEV_A" "$PASS_A"
}

if [ -n "${TANG_URL:-}" ]; then
    clevis_roundtrip tang ",\"tangurl\":\"$TANG_URL\"" 1 tang
else
    info "TANG_URL not set; skipping Tang binding tests"
fi
if [ -e /dev/tpmrm0 ]; then
    clevis_roundtrip tpm2 "" 0 tpm2
    if [ -n "${TANG_URL:-}" ]; then
        clevis_roundtrip tangtpm2 ",\"tangurl\":\"$TANG_URL\"" 1 sss
    fi
else
    info "No TPM2 device; skipping TPM2 binding tests"
fi

# ---------------------------------------------------------------------------
section "Stale auto-unlock entries"
# ---------------------------------------------------------------------------

STALE_UUID=$(cat /proc/sys/kernel/random/uuid)
mkdir -p "$KEY_DIR" && chmod 0700 "$KEY_DIR"
head -c 512 /dev/urandom > "$KEY_DIR/$STALE_UUID"
printf 'luks-%s\tUUID=%s\t%s/%s\tluks,nofail\n' \
    "$STALE_UUID" "$STALE_UUID" "$KEY_DIR" "$STALE_UUID" >> /etc/crypttab
# Unrelated lines must survive crypttab rewrites.
printf '# omv-luks-test comment %s\n' "$$" >> /etc/crypttab

v=$(list_field "$STALE_UUID" stale);      check "stale entry is listed as stale"     "got '$v'" [ "$v" = "true" ]
v=$(list_field "$STALE_UUID" autounlock); check "stale entry shows autounlock=true" "got '$v'" [ "$v" = "true" ]
v=$(list_field "$STALE_UUID" devicefile); check "stale entry devicefile is the mapper name" "got '$v'" [ "$v" = "luks-$STALE_UUID" ]
v=$(list_field "$STALE_UUID" unlocked);   check "stale entry is not unlocked"        "got '$v'" [ "$v" = "false" ]

assert_rpc "removeStaleAutoUnlockEntry" \
    "$SVC" removeStaleAutoUnlockEntry "{\"uuid\":\"$STALE_UUID\"}"
check "stale crypttab entry removed" "" [ -z "$(crypttab_options "$STALE_UUID")" ]
check "stale key file removed" "" test ! -e "$KEY_DIR/$STALE_UUID"
v=$(list_field "$STALE_UUID" uuid); check "stale entry no longer listed" "got '$v'" [ -z "$v" ]
check "crypttab comments preserved" "" grep -q "^# omv-luks-test comment $$" /etc/crypttab

assert_rpc "removeStaleAutoUnlockEntry for an unknown UUID is a no-op" \
    "$SVC" removeStaleAutoUnlockEntry "{\"uuid\":\"$(cat /proc/sys/kernel/random/uuid)\"}"

# ---------------------------------------------------------------------------
section "Safety guards (UI-hidden actions called directly)"
# ---------------------------------------------------------------------------
# The WebGUI hides these actions, but the RPC methods can still be called
# directly.  These tests describe the safe behaviour; C is a throwaway
# LUKS1 container so a failure here cannot affect the other sections.

rpc "$SVC" enableContainerAutoUnlock "{\"devicefile\":\"$DEV_C\",\"passphrase\":\"$PASS_C\"}" >/dev/null 2>&1
assert_rpc_fails "removeStaleAutoUnlockEntry refuses a live container" \
    "$SVC" removeStaleAutoUnlockEntry "{\"uuid\":\"$UUID_C\"}"
check "live container's crypttab entry kept" "" [ -n "$(crypttab_options "$UUID_C")" ]
check "live container's key file kept" "" test -e "$KEY_DIR/$UUID_C"
rpc "$SVC" disableContainerAutoUnlock "{\"devicefile\":\"$DEV_C\"}" >/dev/null 2>&1

rpc "$SVC" openContainer "{\"uuid\":\"$UUID_C\",\"devicefile\":\"$DEV_C\",\"passphrase\":\"$PASS_C\"}" >/dev/null 2>&1
# Delete runs first: a failed create guard would wipe the header and make
# the delete result meaningless.
assert_rpc_fails "deleteContainer refuses an unlocked container" \
    "$SVC" deleteContainer "{\"devicefile\":\"$DEV_C\"}"
check "unlocked container intact after refused delete" "" key_works "$DEV_C" "$PASS_C"
assert_rpc_fails "createContainer refuses an unlocked container" \
    "$SVC" createContainer \
    "{\"devicefile\":\"$DEV_C\",\"cipher\":\"aes-xts-plain64\",\"lukslabel\":\"x\",\"passphrase\":\"$PASS_A\"}"
check "unlocked container header intact after refused create" "" key_works "$DEV_C" "$PASS_C"
rpc "$SVC" closeContainer "{\"devicefile\":\"$DEV_C\"}" >/dev/null 2>&1
cryptsetup close "$MAPPER_C" >/dev/null 2>&1 || true

quick_format "$DEV_C" "$PASS_C" luks2
UUID_C=$(cryptsetup luksUUID "$DEV_C" 2>/dev/null); UUIDS+=("$UUID_C")
assert_rpc_fails "killContainerKeySlot refuses to erase the last key slot" \
    "$SVC" killContainerKeySlot "{\"uuid\":\"$UUID_C\",\"devicefile\":\"$DEV_C\",\"keyslot\":0}"
check "container still unlockable after refused kill" "" key_works "$DEV_C" "$PASS_C"

quick_format "$DEV_C" "$PASS_C" luks2
UUID_C=$(cryptsetup luksUUID "$DEV_C" 2>/dev/null); UUIDS+=("$UUID_C")
assert_rpc_fails "removeContainerKey refuses to remove the last key" \
    "$SVC" removeContainerKey "{\"uuid\":\"$UUID_C\",\"devicefile\":\"$DEV_C\",\"passphrase\":\"$PASS_C\"}"
check "container still unlockable after refused remove" "" key_works "$DEV_C" "$PASS_C"

# Auto-unlock may hold the last key if the passphrase was removed later.
assert_rpc "enableContainerAutoUnlock on C" \
    "$SVC" enableContainerAutoUnlock "{\"devicefile\":\"$DEV_C\",\"passphrase\":\"$PASS_C\"}"
echo -n "$PASS_C" | cryptsetup luksRemoveKey -q "$DEV_C" --key-file=- >/dev/null 2>&1
assert_rpc_fails "disableContainerAutoUnlock refuses to remove the last key" \
    "$SVC" disableContainerAutoUnlock "{\"devicefile\":\"$DEV_C\"}"
check "crypttab entry kept after refused disable" "" [ -n "$(crypttab_options "$UUID_C")" ]
check "key file still unlocks C after refused disable" "" keyfile_works "$DEV_C" "$KEY_DIR/$UUID_C"
PASS_FILE=$(mktemp /var/tmp/omv-luks-pass.XXXXXX); TMP_FILES+=("$PASS_FILE")
echo -n "$PASS_C" > "$PASS_FILE"
cryptsetup luksAddKey -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 \
    "$DEV_C" "$PASS_FILE" --key-file "$KEY_DIR/$UUID_C" >/dev/null 2>&1
assert_rpc "disableContainerAutoUnlock once a passphrase is back" \
    "$SVC" disableContainerAutoUnlock "{\"devicefile\":\"$DEV_C\"}"
check "key file removed" "" test ! -e "$KEY_DIR/$UUID_C"
check "passphrase unlocks C" "" key_works "$DEV_C" "$PASS_C"

# The key file's slot may already be gone; disabling still cleans up.
rpc "$SVC" enableContainerAutoUnlock "{\"devicefile\":\"$DEV_C\",\"passphrase\":\"$PASS_C\"}" >/dev/null 2>&1
cryptsetup luksRemoveKey -q "$DEV_C" --key-file "$KEY_DIR/$UUID_C" >/dev/null 2>&1
assert_rpc "disableContainerAutoUnlock when its key slot was already removed" \
    "$SVC" disableContainerAutoUnlock "{\"devicefile\":\"$DEV_C\"}"
check "crypttab entry removed" "" [ -z "$(crypttab_options "$UUID_C")" ]
check "stale key file removed" "" test ! -e "$KEY_DIR/$UUID_C"
v=$(container_field "$DEV_C" usedslots); check "C usedslots is 1" "got '$v'" [ "$v" = "1" ]

# ---------------------------------------------------------------------------
section "deleteContainer"
# ---------------------------------------------------------------------------

assert_rpc "deleteContainer on locked B" \
    "$SVC" deleteContainer "{\"devicefile\":\"$DEV_B\"}"
udevadm settle
check "B is no longer a LUKS device" "" not_luks "$DEV_B"
check "B passphrase no longer unlocks" "" key_fails "$DEV_B" "$PASS_B"
# The LUKS2 header area is 16 MiB; all of it must be overwritten, not just
# the first 2 MiB.
check "delete overwrites the whole LUKS2 header area" "" \
    eval "! cmp -s <(dd if='$DEV_B' bs=1M skip=2 count=14 2>/dev/null) <(head -c 14M /dev/zero)"
v=$(container_field "$DEV_B" uuid); check "B no longer enumerated" "got '$v'" [ -z "$v" ]
assert_rpc_fails "getContainerDetails on deleted B fails" \
    "$SVC" getContainerDetails "{\"devicefile\":\"$DEV_B\"}"
assert_rpc_fails "deleteContainer on deleted B fails" \
    "$SVC" deleteContainer "{\"devicefile\":\"$DEV_B\"}"

assert_rpc "createContainer can reuse a deleted device (cipher/label omitted)" \
    "$SVC" createContainer \
    "{\"devicefile\":\"$DEV_B\",\"passphrase\":\"$PASS_B\"}"
udevadm settle
UUID_B2=$(cryptsetup luksUUID "$DEV_B" 2>/dev/null); UUIDS+=("$UUID_B2")
check "recreated B has a new UUID" "old=$UUID_B new=$UUID_B2" \
    eval "[ -n '$UUID_B2' ] && [ '$UUID_B2' != '$UUID_B' ]"
check "recreated B unlocks" "" key_works "$DEV_B" "$PASS_B"
check "omitted cipher defaults to aes-xts-plain64" "$(cryptsetup luksDump "$DEV_B" | grep -i cipher)" \
    grep -q "aes-xts-plain64" <(cryptsetup luksDump "$DEV_B")
v=$(container_field "$DEV_B" lukslabel); check "omitted label is empty" "got '$v'" [ -z "$v" ]
