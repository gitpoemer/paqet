# paqet — production deployment notes

This document covers OS-level tuning required for paqet to scale past
a few hundred concurrent users on a single server. Code-level
optimizations are constrained by what the kernel will let paqet do;
these settings remove those ceilings.

All numbers below are starting points for a server expected to handle
**3,000–10,000 concurrent users**. Scale up for larger fleets; the
hardware ceiling (CPU, RAM, NIC PPS) sets the practical upper bound.
For 30,000+ users on one box, expect to hit OS or PCIe limits before
paqet's own design becomes the bottleneck — at that scale, horizontal
scale-out (multiple paqet backends behind an L4 load balancer with
IP-hash) is the recommended path.

---

## Quick start — copy-paste everything

Adjust the paths in the systemd unit if your binary or config live
somewhere other than `/usr/local/bin/paqet` and `/etc/paqet/config.yaml`.
Then run the block as root.

```bash
# 1) Persist sysctl tuning.
sudo tee /etc/sysctl.d/99-paqet.conf > /dev/null <<'EOF'
# paqet — file descriptors
fs.file-max = 2097152
fs.nr_open = 1048576

# paqet — socket buffers (32 MB max, 8 MB default)
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.core.rmem_default = 8388608
net.core.wmem_default = 8388608
net.core.netdev_max_backlog = 50000

# paqet — listen / SYN backlog
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# paqet — outbound TCP behavior (server → target hosts)
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 10
net.ipv4.tcp_keepalive_probes = 6
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 10000 65535
EOF
sudo sysctl --system

# 2) Install the systemd unit. Adjust ExecStart / config path if needed.
sudo tee /etc/systemd/system/paqet.service > /dev/null <<'EOF'
[Unit]
Description=paqet server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/paqet run -c /etc/paqet/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
LimitNPROC=infinity

# Capabilities for raw packet I/O without running as full root.
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true

# Optional: GC pressure under high RAM use.
# paqet sets GOMEMLIMIT itself at startup (90% of cgroup/host RAM).
# Override only if you want a specific ceiling:
#Environment=GOMEMLIMIT=8GiB
# Optional CPU pinning — leave CPU 0-1 for the kernel:
#CPUAffinity=2-7

[Install]
WantedBy=multi-user.target
EOF

# 3) Reload, enable, start.
sudo systemctl daemon-reload
sudo systemctl enable --now paqet.service

# 4) Verify the process inherited the limits.
sleep 1
PID=$(pidof paqet) && {
  echo "FDs:       $(ls /proc/$PID/fd | wc -l)"
  echo "RSS:       $(awk '/VmRSS/ {print $2 " " $3}' /proc/$PID/status)"
  echo "NOFILE:    $(grep 'open files' /proc/$PID/limits)"
  echo "Sockets:   $(ss -tn state established | wc -l)"
}
```

Done. paqet is running with raised FD limits and tuned sysctls,
persisted across reboots. The rest of this document explains what
each knob does and when to tune it further.

---

## File descriptors

Each tunneled outbound TCP or UDP connection holds one file
descriptor. Default Linux per-process limit is 1024 (or whatever the
distro's systemd ships); paqet will fail with `accept: too many open
files` long before saturation.

The quick-start block sets:
- `LimitNOFILE=1048576` in the systemd unit (per-process)
- `fs.file-max=2097152` and `fs.nr_open=1048576` via sysctl (system-wide)

## Socket buffers

Default `net.core.rmem_max` and `wmem_max` are typically 200KB–1MB on
modern kernels. Smux's per-stream and session-wide buffers benefit
from larger socket buffers, particularly under bursty UDP and high-
latency paths.

- `rmem_max` / `wmem_max` = **32 MB** (cap any socket can request)
- `rmem_default` / `wmem_default` = **8 MB** (default per socket)
- `netdev_max_backlog` = **50000** (kernel ingress queue)

## Connection backlog

The kernel's listen-queue limit caps how many half-open SOCKS5
connections can be pending. Default 4096 is fine for thousands of
users but bump it if you see `ss -ltn Send-Q` saturating.

Quick-start sets `somaxconn` and `tcp_max_syn_backlog` to 65535.

## TCP behavior tuning

paqet already sets `SO_KEEPALIVE` with a 30s period on outbound dials
(alpha.33), but kernel-wide tunables apply to every connection
including new ones the keepalive code hasn't customized:

- `tcp_keepalive_time=120` — idle seconds before probes
- `tcp_keepalive_intvl=10` — interval between probes
- `tcp_keepalive_probes=6` — declare dead after 6 failed probes
  → total detect time ≈ 120 + 6 × 10 = **180 s** for connections that
  paqet's per-socket keepalive doesn't override
- `tcp_fin_timeout=15` — shrinks FIN_WAIT2 retention
- `tcp_tw_reuse=1` — recycles TIME_WAIT for outbound (safe; not NAT)
- `ip_local_port_range=10000 65535` — gives ~55k outbound source ports

## pcap (BPF) ring buffer

paqet reads packets via libpcap; the kernel ring buffer behind it
defaults to small. Higher = fewer packet drops under burst load. Set
on the interface:

```bash
sudo ethtool -G eth0 rx 4096 tx 4096    # if NIC supports it
```

Make persistent via your distro's network config (NetworkManager,
networkd, ifupdown, or a `udev` rule).

If you see `pcap_stats` reporting `drops > 0` under load, the ring
buffer is the bottleneck.

## CPU & GC

paqet is largely single-pcap-thread bound on the receive side; the
hot CPU at saturation is the pcap parse + KCP dispatch path. Pin
that goroutine to a dedicated CPU and isolate it from interrupt
handlers (uncomment `CPUAffinity` in the unit):

```ini
CPUAffinity=2-7
```

Adjust the core list to your topology — leave CPU 0–1 for syscalls/
IRQs. After editing the unit run `systemctl daemon-reload && systemctl
restart paqet`.

paqet sets `GOMEMLIMIT` automatically to 90% of cgroup-or-host RAM at
startup. Override via the env var if a manual target is needed:

```ini
Environment=GOMEMLIMIT=8GiB
```

## Verify the tuning

```bash
ulimit -n                                              # your shell's limit
sysctl net.core.somaxconn fs.file-max                  # confirm sysctl values
ss -ltn                                                # listening sockets
cat /proc/$(pidof paqet)/limits | grep "open files"    # process limits
ss -tn state established | wc -l                       # live sockets count
```

## Relay mode (alpha.34 item 10 — experimental)

paqet's TCP relay defaults to `perstream` mode: one BG goroutine per
active stream doing the strm→conn direction. Memory cost ~4 KB per
active stream. Simple, predictable, battle-tested.

Alpha.34 added an experimental `coordinator` mode using the vendored
smux's new `TryRead` + `ReadEvents` APIs. One coordinator goroutine
per smux session multiplexes readability events across all that
session's streams; lazy workers spawn only when a stream actually
has data to forward and exit when its buffer drains.

In `config.yaml`:
```yaml
transport:
  relaymode: coordinator   # default: perstream
```

When to consider switching:
- Heavy concurrent stream count per session (one client opening
  hundreds of streams in parallel).
- Goroutine-stack memory shows up as the dominant heap cost in
  `pprof` heap profiles.

Caveats:
- Each event dispatch goes through `reflect.Select` over the session's
  stream channels — O(N) per call, N = MaxStreamsPerSession (4096).
  Adds ~40 μs CPU per dispatched event on commodity x86.
- Wire format and stealth properties are byte-identical to
  `perstream` mode. The change is purely about how the BG direction's
  goroutines are managed.
- Less production-tested than `perstream`. Stick with the default on
  critical deployments until you have evidence the coordinator helps
  your specific workload.

## Horizontal scaling (>10k users)

At ~10k concurrent users on commodity hardware (8 cores, 32 GB RAM)
you start to hit:
- libpcap single-thread read cap (~500–800k pps)
- Goroutine memory pressure (one goroutine per relay direction)
- KCP-go internal session map mutex contention

Recommended pattern:
1. L4 LB (HAProxy stream / Nginx stream / IPVS) in front of N paqet
   servers, source-IP-hashing so the same user always lands on the
   same backend.
2. Each backend tuned per this doc, handling 2–5k users.
3. Backends are stateless from a control-plane perspective — no
   shared state between them. Restart any one without affecting the
   others.

Caveat for paqet's pcap-based design: the LB cannot terminate KCP
(it's our application layer over raw TCP). It needs to operate at IP
layer — DNAT-style or anycast routing. HAProxy in `mode tcp` with
`source` balance algorithm works for the carrier-TCP flows.
