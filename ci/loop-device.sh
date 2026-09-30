#!/usr/bin/env bash
# A pool on a real block device: a loop device over a sparse file,
# formatted, FUSE-mounted, written, unmounted, checked and remounted.
# Needs root (losetup, the mount). Usage: ci/loop-device.sh path/to/lchfs
set -euo pipefail
lchfs=$(realpath "$1")
work=$(mktemp -d)
loop=
cleanup() {
    umount "$work/mnt" 2>/dev/null || true
    [ -n "$loop" ] && losetup -d "$loop" 2>/dev/null || true
    rm -rf "$work"
}
trap cleanup EXIT
export RUST_LOG=warn

truncate -s 2G "$work/disk.img"
loop=$(losetup -f --show "$work/disk.img")
mkdir "$work/mnt"

# A device holding something is refused without --force.
printf 'not blank' | dd of="$loop" bs=1 seek=1080 conv=notrunc status=none
if "$lchfs" create-pool "$loop"; then echo "a non-blank device was formatted"; exit 1; fi
"$lchfs" create-pool --force "$loop"
if "$lchfs" create-pool --force "$loop"; then echo "a pool was formatted over"; exit 1; fi

wait_mounted() {
    for _ in $(seq 50); do mountpoint -q "$work/mnt" && return 0; sleep 0.2; done
    echo "the mount did not come up"; exit 1
}
wait_unmounted() {
    for _ in $(seq 100); do pgrep -f "lchfs mount $loop" >/dev/null || return 0; sleep 0.2; done
    echo "the mount did not exit"; exit 1
}

"$lchfs" mount "$loop" "$work/mnt" &
wait_mounted
head -c 50000000 /dev/urandom > "$work/data"
cp "$work/data" "$work/mnt/data"
echo hello > "$work/mnt/hello"
sync
cmp "$work/data" "$work/mnt/data"
# The device is held: a second mount is refused, the control socket works.
if "$lchfs" mount "$loop" "$work/mnt"; then echo "a second mount was allowed"; exit 1; fi
"$lchfs" pool status "$loop" | grep -q '"degraded": false'
umount "$work/mnt"
wait_unmounted

"$lchfs" fsck "$loop" | grep -q "No errors found"

"$lchfs" mount "$loop" "$work/mnt" &
wait_mounted
cmp "$work/data" "$work/mnt/data"
[ "$(cat "$work/mnt/hello")" = hello ]
umount "$work/mnt"
wait_unmounted
echo "loop device: ok"
