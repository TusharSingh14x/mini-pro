#!/bin/bash
# Automated Kernel Mitigation Rules Synthesized by Closed-Loop NIDS
# Generated upon Socket Pool Exhaustion Interception (Port 80)

# 1. Drop invalid states
iptables -A INPUT -m state --state INVALID -j DROP

# 2. Connection rate limiting for Slowloris mitigation
iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 5 -j DROP

# 3. TCP SYN flood rate limit guard
iptables -A INPUT -p tcp --syn -m limit --limit 100/s --limit-burst 150 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# 4. Mitigate slow HTTP header starvation (TCP window scale)
sysctl -w net.ipv4.tcp_fin_timeout=15
sysctl -w net.ipv4.tcp_synack_retries=2
