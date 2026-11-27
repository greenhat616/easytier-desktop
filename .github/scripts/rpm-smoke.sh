#!/usr/bin/env bash
# Smoke test of the release rpm in a Fedora container (release-package.yml).
#   rpm-smoke.sh <release.rpm> <next.rpm>
# The container has no systemd, so the hooks only print their notice: this
# checks the package itself. Its scriptlets parse; it installs root-owned
# with its modes and links; it upgrades to the next version; and erasing it
# leaves the file system as it was before the install, empty folders
# included.
set -euo pipefail
release=$1
next=$2

for tag in PREIN POSTIN PREUN; do
  rpm -qp --qf "%{$tag}" "$release" > "/tmp/$tag.sh"
  [[ -s "/tmp/$tag.sh" ]] || { echo "the rpm has no $tag scriptlet"; exit 1; }
  sh -n "/tmp/$tag.sh"
  echo "$tag scriptlet parses ($(rpm -qp --qf "%{${tag}PROG}" "$release"))"
done

# The dependencies first (names only; rpm checks the versions), so that the
# snapshot below sees only what the package itself adds.
mapfile -t requires < <(rpm -qp --requires "$release" | grep -v '^rpmlib(' | awk '{print $1}' | sort -u)
echo "requires: ${requires[*]}"
dnf install -y -q --setopt=install_weak_deps=False "${requires[@]}"
echo "recommends: $(rpm -qp --recommends "$release" | tr '\n' ' ')"

snapshot() {
  find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp \
    -o -path /var/cache -o -path /var/log -o -path /var/lib/dnf -o -path /usr/lib/sysimage \
    -o -path /pkg -o -path /scripts \) -prune -o -print | sort
}
snapshot > /tmp/before

output=$(rpm -i "$release" 2>&1)
echo "$output"
grep -q 'systemd is not running' <<<"$output"
rpm -q easytier-desktop
lib=/usr/lib/easytier-desktop
for file in "$lib/etd-ui" "$lib/etd-host" "$lib/etd-ctl" "$lib"/cores/*/easytier-core; do
  [[ "$(stat -c '%U:%G %a' "$file")" == "root:root 755" ]] || { stat "$file"; exit 1; }
done
for dir in "$lib" "$lib/cores" "$lib"/cores/*/; do
  [[ "$(stat -c '%U:%G %a' "$dir")" == "root:root 755" ]] || { stat "$dir"; exit 1; }
done
[[ "$(readlink /usr/bin/easytier-desktop)" == "$lib/etd-ui" ]]
[[ "$(readlink /usr/bin/etd-ctl)" == "$lib/etd-ctl" ]]
[[ "$(stat -c '%U:%G %a' /usr/share/applications/easytier-desktop.desktop)" == "root:root 644" ]]
"$lib/etd-ctl" --version
echo "installed $(rpm -q easytier-desktop): payload, links and desktop entry root-owned with their modes"

rpm -U "$next"
echo "upgraded to $(rpm -q easytier-desktop)"

rpm -e easytier-desktop
if rpm -q easytier-desktop; then echo "the package is still installed"; exit 1; fi
snapshot > /tmp/after
if ! diff -u /tmp/before /tmp/after; then
  echo "erasing the package left the paths above (+) or removed them (-)"
  exit 1
fi
echo "erased: the file system matches the snapshot before the install"
