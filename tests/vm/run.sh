#!/usr/bin/env bash
# End-to-end test in a throwaway VM: loads the BPF programs (real verifier,
# real kernel), plays a 64 Hz UDP "game" with three staged lag sources and
# checks that lagblame blames each one correctly. No root needed on the host,
# only /dev/kvm and qemu.
#   tests/vm/run.sh [KERNEL] [LAGBLAME_BINARY]
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
default_kernel() {
    local r; r=$(uname -r)
    if [[ -e /boot/vmlinuz-$r ]]; then echo "/boot/vmlinuz-$r"; return; fi
    case $r in   # Arch names kernels by package
        *-zen) echo /boot/vmlinuz-linux-zen ;; *-lts) echo /boot/vmlinuz-linux-lts ;;
        *-hardened) echo /boot/vmlinuz-linux-hardened ;; *) echo /boot/vmlinuz-linux ;;
    esac
}
kernel=${1:-$(default_kernel)}
bin=${2:-$here/../../target/release/lagblame}
[[ -r $kernel ]] || { echo "kernel $kernel not readable" >&2; exit 2; }
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
root=$work/root
mkdir -p "$root"/{usr/bin,usr/lib,proc,sys,dev,tmp,etc}
ln -s usr/bin "$root/bin"; ln -s usr/lib "$root/lib"; ln -s usr/lib "$root/lib64"; ln -s ../usr/bin "$root/usr/sbin"

gcc -O2 -static -o "$root/usr/bin/udptest" "$here/udptest.c"
install -m755 "$bin" "$root/usr/bin/lagblame"
# libraries keep their paths (Arch: /usr/lib, Debian/Ubuntu: /lib/x86_64-linux-gnu)
libs() {
    ldd "$1" 2>/dev/null | grep -o '/[^ ]*' | while read -r lib; do
        [[ -e $root$lib ]] && continue
        mkdir -p "$root$(dirname "$lib")"
        cp -L "$lib" "$root$lib"
    done
}
copy() {
    cp -L "$1" "$root/usr/bin/$(basename "$1")"
    libs "$1"
}
for b in bash mount tee ls timeout sleep cat mkdir setpriv setcap getcap ip env chown grep head tail wc cp date; do
    copy "$(command -v $b)"
done
libs "$bin"
# the ELF interpreter path, whatever ldd called it
[[ -e $root/lib64/ld-linux-x86-64.so.2 ]] || cp -L /lib64/ld-linux-x86-64.so.2 "$root/lib64/"
echo 'root:x:0:0::/:/bin/bash' >"$root/etc/passwd"
echo 'u:x:1000:1000::/tmp/home:/bin/bash' >>"$root/etc/passwd"
cp "$here/scenario.sh" "$root/init"
chmod +x "$root/init"
(cd "$root" && find . | cpio -o -H newc --quiet) >"$work/initrd"

timeout ${VM_TIMEOUT:-300} qemu-system-x86_64 -enable-kvm -cpu host -smp 2 -m 1024 \
    -kernel "$kernel" -initrd "$work/initrd" \
    -append "console=ttyS0 ${VM_KERNEL_ARGS:-quiet loglevel=1} panic=-1 rdinit=/init" \
    -nographic -no-reboot -serial mon:stdio </dev/null | tee "$work/console.log" | sed 's/\r$//'
grep -q '^RESULT: PASS' "$work/console.log"
