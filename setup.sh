#!/bin/sh
# Prepare the host folders shared between zones (no container sits on both networks).
#   data/decoys/<slot>   Cowrie var/ (logs)      written by Cowrie (uid 999), read by the collector
#   data/render/<slot>   fs.pickle, etc/userdb   written by builder / mirage-control (uid 1001), read by Cowrie
#   data/deception       decoy file contents     written by builder / mirage-control, read by Cowrie and the wiki
#   data/control         tiers, open services... written by mirage-control, read by the wiki
#   data/trap-logs       wiki and gateway logs   written by the wiki and the gateway, read by the collector
set -eu
for host in fake-jump-01 fake-db-01 fake-ftp-01; do
  mkdir -p "data/decoys/$host/log/cowrie" "data/decoys/$host/lib/cowrie/tty" "data/decoys/$host/lib/cowrie/downloads"
  mkdir -p "data/render/$host/etc" "data/deception/$host"
done
mkdir -p data/deception/wiki data/control data/trap-logs data/groundtruth exports
sudo chown -R 999:999 data/decoys
sudo chown -R 1001:1001 data/render data/deception data/control data/trap-logs data/groundtruth exports
sudo chmod -R a+rX data
echo "folders ready"
