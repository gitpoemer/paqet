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

## File descriptors

Each tunneled outbound TCP or UDP connection holds one file
descriptor. Default Linux per-process limit is 1024 (or whatever the
distro's systemd ships); paqet will fail with `accept: too many open
files` long before saturation.

### Per-process limit

For a systemd unit:
```
[Service]
LimitNOFILE=1048576
```

For a shell test:
```
ulimit -n 1048576
```

### System-wide ceiling

```
sudo sysctl -w fs.file-max=2097152
sudo sysctl -w fs.nr_open=1048576
```

Persist in `/etc/sysctl.d/99-paqet.conf`.

## Socket buffers

Default `net.core.rmem_max` and `wmem_max` are typically 200KB–1MB on
modern kernels. Smux's per-stream and session-wide buffers benefit
from larger socket buffers, particularly under bursty UDP and high-
latency paths.

```
sudo sysctl -w net.core.rmem_max=33554432       # 32 MB
sudo sysctl -w net.core.wmem_max=33554432
sudo sysctl -w net.core.rmem_default=8388608    # 8 MB
sudo sysctl -w net.core.wmem_default=8388608
sudo sysctl -w net.core.netdev_max_backlog=50000
```

## Connection backlog

The kernel's listen-queue limit caps how many half-open SOCKS5
connections can be pending. Default 4096 is fine for thousands of
users but bump it if you see `ss -ltn Send-Q` saturating.

```
sudo sysctl -w net.core.somaxconn=65535
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=65535
```

## TCP behavior tuning

Outbound TCP from paqet to target hosts. We already set SO_KEEPALIVE
with 30s period (alpha.33), but the kernel-wide tunables affect every
connection.

```
sudo sysctl -w net.ipv4.tcp_keepalive_time=120         # idle before probes (s)
sudo sysctl -w net.ipv4.tcp_keepalive_intvl=10         # interval between probes (s)
sudo sysctl -w net.ipv4.tcp_keepalive_probes=6         # probes before declaring dead
sudo sysctl -w net.ipv4.tcp_fin_timeout=15             # FIN_WAIT2 timeout
sudo sysctl -w net.ipv4.tcp_tw_reuse=1                 # safe in NAT-free server scenarios
sudo sysctl -w net.ipv4.ip_local_port_range="10000 65535"
```

## pcap (BPF) buffer

paqet reads packets via libpcap; the kernel ring buffer behind it
defaults to small. Higher = fewer packet drops under burst load. Set
on the interface:

```
sudo ethtool -G eth0 rx 4096 tx 4096    # if NIC supports it
```

If you see `pcap_stats` reporting `drops` > 0 under load, the ring
buffer is the bottleneck.

## CPU & GC

paqet is largely single-pcap-thread bound on the receive side; the
hot CPU at saturation is the pcap parse + KCP dispatch path. Pin
that goroutine to a dedicated CPU and isolate it from interrupt
handlers:

```
sudo systemctl set-property paqet-server.service CPUAffinity=2-7
```

(adjust core list to your topology — leave CPU 0–1 for syscalls/IRQs.)

paqet sets `GOMEMLIMIT` automatically to 90% of cgroup-or-host RAM at
startup (alpha.33). Override via the env var if a manual target is
needed:

```
[Service]
Environment=GOMEMLIMIT=8GiB
```

## Verify the tuning

After applying:

```
ulimit -n                                                # should report your new soft limit
sysctl net.core.somaxconn fs.file-max                    # confirm reads back
ss -ltn                                                  # see your listening sockets
cat /proc/$(pidof paqet)/limits | grep open              # confirm the process sees the limit
```

## systemd-unit template (Linux server)

```ini
[Unit]
Description=paqet server
After=network-online.target

[Service]
ExecStart=/usr/local/bin/paqet -c /etc/paqet/config.yaml run
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
LimitNPROC=infinity
Environment=GOGC=200
# Optional pinning — adjust to your CPU layout:
# CPUAffinity=2-7
# Optional explicit memory ceiling:
# Environment=GOMEMLIMIT=8GiB

# Capabilities for raw socket / pcap (alternative to running as root):
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

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
