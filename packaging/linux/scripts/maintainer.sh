#!/bin/sh
# EasyTier Desktop package hook (packaging/linux/scripts/maintainer.sh).
# `cargo xtask dist` renders one copy per package format and hook, filling
# in FORMAT (deb, rpm or arch) and HOOK. The package owns only its payload
# in /usr/lib/easytier-desktop; the service, its protected folder
# /usr/local/lib/easytier-desk and its state belong to etd-host, which these
# hooks run:
#   - no service yet: `etd-host install`, tagged with OWNER;
#   - an upgrade: `etd-host upgrade` of a service this package installed
#     (with no service at all, install instead);
#   - a full removal: `etd-host uninstall` of a service this package installed.
# A service another installer made is never upgraded or removed here: deb and
# rpm refuse to install over it, Arch leaves it alone. Without systemd every
# hook only prints a notice.
set -eu
FORMAT=@FORMAT@
HOOK=@HOOK@
HOST=/usr/lib/easytier-desktop/etd-host
INSTALLED=/usr/local/lib/easytier-desk/etd-host
UNIT=/etc/systemd/system/easytier-desk-host.service
SYSTEMD=/run/systemd/system
OWNER=easytier-desktop-package

note() {
    echo "easytier-desktop: $*"
}

install_service() {
    "$HOST" install --owner "$OWNER"
}

upgrade_service() {
    if [ -e "$UNIT" ]; then
        "$HOST" upgrade --only-owner "$OWNER"
    else
        note "no service is installed; installing it instead of upgrading"
        install_service
    fi
}

remove_service() {
    if [ -x "$HOST" ]; then
        "$HOST" uninstall --only-owner "$OWNER"
    fi
}

# deb and rpm, before anything is unpacked: failing here aborts the install.
refuse_existing() {
    if [ -e "$UNIT" ]; then
        echo "easytier-desktop: the EasyTier Desktop service is already installed ($UNIT)." >&2
        echo "easytier-desktop: remove it first with: $INSTALLED uninstall" >&2
        exit 1
    fi
}

# pacman cannot abort from a hook: leave a foreign service alone.
arch_install() {
    if [ -e "$UNIT" ]; then
        note "a service installed by something else exists ($UNIT); this package leaves it alone and will not upgrade or remove it."
        note "to let the package manage it: $INSTALLED uninstall, then reinstall easytier-desktop (pacman -S easytier-desktop)."
        return 0
    fi
    install_service
}

main() {
    if [ ! -d "$SYSTEMD" ]; then
        if [ "$HOOK" != preinstall ]; then
            note "systemd is not running; the service is not managed here. On a systemd host run: $HOST install"
        fi
        return 0
    fi
    # deb: preinst install|upgrade, postinst configure [old version],
    #      prerm remove|upgrade|deconfigure|failed-upgrade;
    # rpm: $1 counts the installed instances after the step (1 install,
    #      2 or more upgrade, 0 removal);
    # arch: separate hooks, called with versions.
    case "$FORMAT:$HOOK:${1:-}" in
        deb:preinstall:install | rpm:preinstall:1) refuse_existing ;;
        deb:postinstall:configure)
            if [ -n "${2:-}" ]; then upgrade_service; else install_service; fi
            ;;
        rpm:postinstall:1) install_service ;;
        rpm:postinstall:*) upgrade_service ;;
        arch:postinstall:*) arch_install ;;
        arch:postupgrade:*) upgrade_service ;;
        deb:preremove:remove | rpm:preremove:0 | arch:preremove:*) remove_service ;;
        *) ;;
    esac
}

main "$@"
