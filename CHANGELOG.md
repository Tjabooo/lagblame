# Changelog

## v0.1.0 — 2026-11-14

First release.

- eBPF hooks: runqueue delay per thread, UDP send/receive rhythm per socket, NIC → socket → app
  timing, in-kernel tunnel decap time, TCP RTT/retransmits, NET_RX/NET_TX softirq latency,
  skb drops by reason. CO-RE, no kernel headers needed at runtime.
- Verdict engine ranks CPU scheduler, the app itself, kernel network stack, VPN tunnel, LAN/Wi-Fi,
  internet and server, with the evidence behind each.
- `live` TUI with rewind, `record` for a systemd user service, `replay`, `explain --at`, `spikes`,
  `mark` (bind to a key: "it lagged just now"), `sessions`, `doctor`, `overhead`.
- Built-in LAN/internet probe (ICMP ping sockets) or another prober's JSON.
- VM end-to-end test (`tests/vm/run.sh`) that runs the real verifier and staged lag scenarios.
