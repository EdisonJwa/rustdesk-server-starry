#!/usr/bin/env bash
# Host tuning for a Starry node. Idempotent; safe to re-run.
#
# Deliberately does NOT touch: firewalld/ufw policy, TLS certificates, nginx, or
# any container that does not belong to Starry. On this host those are shared with
# other services.
set -euo pipefail

echo "== kernel UDP buffers =="
# HBBS receives punch packets on a UDP socket whose receive buffer defaults to
# ~208 KiB. At even modest registration rates the kernel drops them before HBBS
# reads, which looks like random connection failures rather than a load problem.
# rmem_max must be raised first or SO_RCVBUFFORCE is capped.
install -m 0644 /dev/stdin /etc/sysctl.d/70-starry.conf <<'CONF'
# Starry node tuning.
# UDP receive headroom for the rendezvous socket (25 MiB * 2 for overhead).
net.core.rmem_max = 52428800
net.core.rmem_default = 2621440
net.core.wmem_max = 10485760
# Backlog for bursts of registrations; the defaults are small for a public node.
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 8192
# A relay carries long-lived idle sessions; keep them alive through NAT.
net.ipv4.tcp_keepalive_time = 300
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
# Relay forwards many small frames: cheap reuse beats waiting for TIME_WAIT.
net.ipv4.tcp_fin_timeout = 15
net.ipv4.ip_local_port_range = 10240 65000
CONF
sysctl --system >/dev/null
echo "  rmem_max=$(sysctl -n net.core.rmem_max)"

echo "== file descriptors =="
# Every peer and every relay session holds a descriptor; 1024 is the wrong number
# for a public rendezvous node.
install -d -m 0755 /etc/systemd/system.conf.d
install -m 0644 /dev/stdin /etc/systemd/system.conf.d/70-starry-limits.conf <<'CONF'
[Manager]
DefaultLimitNOFILE=524288
CONF
echo "  written (applies to units started after the next systemd reload)"

echo "== time discipline =="
# Delays, JWT expiry and telemetry freshness all assume a correct clock.
if timedatectl | grep -q "System clock synchronized: yes"; then
  echo "  clock already synchronized"
else
  echo "  WARNING: clock not synchronized; check $(command -v chronyc >/dev/null && echo chrony || echo systemd-timesyncd)"
fi

echo "== conntrack (docker rules share the host) =="
if [ -f /proc/sys/net/netfilter/nf_conntrack_max ]; then
  echo "  nf_conntrack_max=$(cat /proc/sys/net/netfilter/nf_conntrack_max)"
fi

echo "== done =="
