#!/usr/bin/env bash
# Smoke test of the release Arch package in an Arch Linux container
# (release-package.yml).
#   arch-smoke.sh <release.pkg.tar.zst> <next.pkg.tar.zst>
# The container has no systemd, so the hooks only print their notice: this
# checks the package itself. Its .INSTALL parses; it installs root-owned with
# its modes and links; it upgrades to the next version; and removing it
# leaves the file system as it was before the install, empty folders
# included.
set -euo pipefail
release=$1
next=$2

tar --zstd -xOf "$release" .INSTALL > /tmp/install.sh
bash -n /tmp/install.sh
for hook in post_install post_upgrade pre_remove; do
  grep -q "^function $hook()" /tmp/install.sh || { echo ".INSTALL has no $hook"; exit 1; }
done
echo ".INSTALL parses and defines post_install, post_upgrade and pre_remove"

# The dependencies first, so that the snapshot below sees only what the
# package itself adds; diffutils for the leftover check.
mapfile -t depends < <(tar --zstd -xOf "$release" .PKGINFO | sed -n 's/^depend = //p' | sed -E 's/[<>=].*//')
echo "depends: ${depends[*]}"
echo "optdepends: $(tar --zstd -xOf "$release" .PKGINFO | sed -n 's/^optdepend = //p' | tr '\n' ' ')"
pacman -Syu --noconfirm --needed --noprogressbar "${depends[@]}" diffutils > /dev/null

snapshot() {
  find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp \
    -o -path /var/cache -o -path /var/log -o -path /var/lib/pacman -o -path /pkg -o -path /scripts \) \
    -prune -o -print | sort
}
snapshot > /tmp/before

output=$(pacman -U --noconfirm --noprogressbar "$release" 2>&1)
echo "$output"
grep -q 'systemd is not running' <<<"$output"
pacman -Q easytier-desktop
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
echo "installed $(pacman -Q easytier-desktop): payload, links and desktop entry root-owned with their modes"

output=$(pacman -U --noconfirm --noprogressbar "$next" 2>&1)
echo "$output"
grep -q 'systemd is not running' <<<"$output"
echo "upgraded to $(pacman -Q easytier-desktop)"

output=$(pacman -R --noconfirm --noprogressbar easytier-desktop 2>&1)
echo "$output"
grep -q 'systemd is not running' <<<"$output"
if pacman -Q easytier-desktop 2> /dev/null; then echo "the package is still installed"; exit 1; fi
snapshot > /tmp/after
if ! diff -u /tmp/before /tmp/after; then
  echo "removing the package left the paths above (+) or removed them (-)"
  exit 1
fi
echo "removed: the file system matches the snapshot before the install"
