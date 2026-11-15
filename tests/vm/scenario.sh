#!/bin/bash
# Runs as /init inside the test VM (see run.sh).
export PATH=/usr/bin
mount -t proc proc /proc; mount -t sysfs sys /sys; mount -t devtmpfs dev /dev; mount -t tmpfs tmp /tmp
exec </dev/null
ip link set lo up
echo "0 2147483647" >/proc/sys/net/ipv4/ping_group_range
echo 1 >/proc/sys/kernel/bpf_stats_enabled
mkdir -p /tmp/home && chown 1000:1000 /tmp/home
cp /usr/bin/udptest /tmp/game; cp /usr/bin/udptest /tmp/gamesrv
# the same thing a user does once after installing
setcap cap_bpf,cap_perfmon+ep /usr/bin/lagblame
U="setpriv --reuid 1000 --regid 1000 --clear-groups env HOME=/tmp/home"
cat >/tmp/home/cfg.toml <<CFG
apps = ["game"]
[probe]
wan_target = "127.0.0.1"
interval_ms = 250
[record]
linger_s = 2
CFG
fail=0
check() { if eval "$2"; then echo "ok   $1"; else echo "FAIL $1"; fail=1; fi; }
L() { $U lagblame --config /tmp/home/cfg.toml "$@"; }

echo "=== kernel $(cat /proc/sys/kernel/osrelease)"
echo "=== doctor (unprivileged user + file caps)"
L doctor | tee /tmp/doctor.log
check "BPF loads as a normal user with file caps" "grep -q 'ok  ] load' /tmp/doctor.log"
check "all hooks attach" "grep -q 'ok  ] attach' /tmp/doctor.log"

echo "=== scenario: 20 s of 64 Hz UDP; server quiet at 5 s, game hitch at 10 s, CPU hog at 15 s"
( while sleep 5; do
    ps=""; for p in /proc/[0-9]*; do read -r c <"$p/comm" 2>/dev/null && read -r _ _ st _ <"$p/stat" 2>/dev/null; case $c in game|gamesrv|udptest|lagblame) ps="$ps $c(${p#/proc/}:$st)";; esac; done
    read -r up _ </proc/uptime; echo "[watchdog] up $up:$ps"
done ) &
wd=$!
$U lagblame --config /tmp/home/cfg.toml record >/tmp/rec.out 2>/tmp/rec.err &
rec=$!
sleep 2
/tmp/gamesrv server 9000 5 200 &
srv=$!
udptest hog 1 15.5 250 &
/tmp/game client 9000 64 20 1 10 150
sleep 3
kill -INT $rec; wait $rec
kill $srv
kill $wd
echo "--- recorder stderr"; cat /tmp/rec.err
echo "--- recorder spikes"; cat /tmp/rec.out
echo "--- sessions"; L sessions
echo "--- spikes"; L spikes | tee /tmp/spikes.log
for t in $(L spikes --json | grep '"t"' | grep -o '[0-9.]*'); do
    echo "--- explain $t"; L explain --at "$t" --window 1.5
done | tee /tmp/explain.log
check "recv gap from the quiet server found" "grep -q 'recv gap' /tmp/spikes.log"
check "send gap from the hitch found" "grep -q 'send gap' /tmp/spikes.log"
check "server blamed" "grep -q 'Most likely: server' /tmp/explain.log"
check "app hitch blamed" "grep -q 'Most likely: the app itself' /tmp/explain.log"
check "CPU blamed, naming the hog" "grep -q 'Most likely: CPU scheduler.*udptest' /tmp/explain.log"
sess=$(ls /tmp/home/.local/state/lagblame/sessions/*.jsonl 2>/dev/null | head -1)
check "session recorded" "[ -n '$sess' ]"
check "packets measured NIC->socket" "grep -q stack_avg '$sess'"
check "socket->app measured" "grep -q pick_avg '$sess'"
check "probe ran" "grep -q '\"wan\"' '$sess'"
check "softirq measured" "grep -q rx_sirq '$sess'"

echo "=== overhead (64 Hz game, 8 s)"
/tmp/gamesrv server 9001 &
srv=$!
/tmp/game client 9001 64 12 1 &
timeout 30 $U lagblame --config /tmp/home/cfg.toml overhead --seconds 8 | tee /tmp/over.log
kill $srv
check "overhead measured" "grep -q 'kernel side' /tmp/over.log"

[ $fail = 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL"
# Let the serial console drain first: sysrq prints "Power Off" at default loglevel, and it used to land
# inside the RESULT line ("RESULT: [ 33.96] sysrq: Power Off"), failing a passing run.
sleep 1
echo o >/proc/sysrq-trigger
sleep 5
