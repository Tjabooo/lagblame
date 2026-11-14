#!/usr/bin/env bash
# Build (or take LAGBLAME_BINARY) and install lagblame for this user.
#   ./install.sh            binary only
#   ./install.sh --service  also the systemd user unit (records in the background)
set -euo pipefail
cd "$(dirname "$0")"
prefix=${PREFIX:-$HOME/.local}
bin=${LAGBLAME_BINARY:-}
if [[ -z $bin ]]; then
    nice -n 10 cargo build --release --locked
    bin=target/release/lagblame
fi
install -Dm755 "$bin" "$prefix/bin/lagblame"
echo "installed $prefix/bin/lagblame"
if [[ ${1:-} == --service ]]; then
    unit=${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/lagblame.service
    install -Dm644 contrib/lagblame.service "$unit"
    cfg=${XDG_CONFIG_HOME:-$HOME/.config}/lagblame/config.toml
    [[ -e $cfg ]] || install -Dm644 contrib/config.example.toml "$cfg"
    systemctl --user daemon-reload
    echo "installed $unit (enable with: systemctl --user enable --now lagblame)"
fi
if ! "$prefix/bin/lagblame" caps >/dev/null 2>&1; then
    echo
    echo "One more step (again after every reinstall): let it load its BPF programs:"
    echo "  sudo setcap cap_bpf,cap_perfmon+ep $prefix/bin/lagblame"
fi
