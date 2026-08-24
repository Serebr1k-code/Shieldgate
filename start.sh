#!/usr/bin/env bash
# Start ShieldGate locally against the ForcAD lab.
# Usage: ./start.sh   (requires sudo — NFQUEUE/nftables)
set -e
cd "$(dirname "$0")"
sudo -E ./shieldgate -config shieldgate.yaml
