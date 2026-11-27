#!/usr/bin/env bash
set -euo pipefail

# These runner dependencies all come from Ubuntu. Restrict both apt commands
# to the distribution sources so an unrelated vendor outage cannot block CI.
sources=/etc/apt/sources.list.d/ubuntu.sources
if [[ ! -f "$sources" ]]; then
  sources=/etc/apt/sources.list
fi
options=(-o "Dir::Etc::sourcelist=$sources" -o "Dir::Etc::sourceparts=-")
sudo apt-get "${options[@]}" update
sudo apt-get "${options[@]}" install -y "$@"
