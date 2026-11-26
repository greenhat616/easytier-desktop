"""Native, read-only inventory. No product observer, sweeper, or ledger calls."""

from collections import defaultdict
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
from xml.etree import ElementTree


CLASSES = ("interface", "route", "resolver", "firewall", "registry", "service", "runtime", "process")


def command(*args, check=True, **kwargs):
    result = subprocess.run(
        [str(arg) for arg in args], check=False, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=60,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), **kwargs,
    )
    if check and result.returncode:
        raise RuntimeError(f"{Path(args[0]).name} failed ({result.returncode}): {result.stderr.strip()}")
    return result


def output(*args):
    return command(*args).stdout


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


@dataclass
class Inventory:
    # Values are stable credentials/configuration. Never print file contents,
    # command lines, firewall policy dumps, or environment variables in CI.
    rows: dict = field(default_factory=dict)

    def put(self, kind, key, value):
        entry = (kind, str(key))
        if entry in self.rows:
            raise AssertionError(f"duplicate inventory key {entry}")
        self.rows[entry] = value

    def delta(self, other):
        return {key for key in self.rows.keys() | other.rows.keys()
                if self.rows.get(key) != other.rows.get(key)}

    def counts(self):
        return {kind: sum(row[0] == kind for row in self.rows) for kind in CLASSES}


def file_identity(path):
    st = path.lstat()
    return st.st_dev, st.st_ino, st.st_mode, digest(path)


def directories(inv, root):
    # The instance directory persists between epochs. H1 records the epoch
    # directory itself; read its file identity even when its contents change.
    for instance in root.iterdir():
        if instance.is_dir() and not instance.is_symlink():
            for epoch in instance.iterdir():
                st = epoch.lstat()
                inv.put("runtime", epoch, (st.st_dev, st.st_ino, st.st_mode))


def processes(inv, text, paths):
    for row in text.splitlines():
        pid, _, image = row.strip().partition(" ")
        image = image.strip()
        if any(image == str(path) or image.startswith(str(path) + os.sep) for path in paths):
            inv.put("process", pid, image)


def linux(inv, paths):
    links = json.loads(output("ip", "-j", "-d", "link", "show"))
    addresses = {r["ifname"]: sorted((a["local"], a["prefixlen"]) for a in r["addr_info"])
                 for r in json.loads(output("ip", "-j", "address", "show"))}
    for link in links:
        name = link["ifname"]
        inv.put("interface", name, {
            "index": link["ifindex"], "type": link.get("link_type"),
            "mtu": link["mtu"], "mac": link.get("address"), "addresses": addresses[name],
            "kind": link.get("linkinfo", {}).get("info_kind"),
        })
    routes = defaultdict(list)
    for family in ("-4", "-6"):
        for row in json.loads(output("ip", "-j", family, "route", "show", "table", "all")):
            row.pop("expires", None)  # decreasing lifetime is not a configuration change
            routes[row.get("dev", "")].append(json.dumps(row, sort_keys=True))
    for device, entries in routes.items():
        inv.put("route", device, sorted(entries))
    resolved = defaultdict(list)
    for query in ("dns", "domain"):
        for row in output("resolvectl", query).splitlines():
            label, sep, value = row.partition(":")
            if not sep:
                raise ValueError(f"unexpected resolvectl {query} row")
            name = re.fullmatch(r"Link \d+ \((.+)\)", label)
            if value.strip():
                resolved[name[1] if name else label].append((query, value.strip()))
    for name, values in resolved.items():
        inv.put("resolver", name, values)
    tables = defaultdict(list)
    for item in json.loads(output("nft", "-s", "-j", "-a", "list", "ruleset"))["nftables"]:
        kind, row = next(iter(item.items()))
        if kind != "metainfo":
            table = row["name"] if kind == "table" else row["table"]
            tables[(row["family"], table)].append(json.dumps(item, sort_keys=True))
    for (family, table), entries in tables.items():
        inv.put("firewall", f"{family}/{table}", entries)
    for row in output("systemctl", "list-unit-files", "--type=service", "--no-legend",
                      "--no-pager", "--plain").splitlines():
        unit, state, *_ = row.split()
        inv.put("service", unit, state)
    processes(inv, output("ps", "-eo", "pid=,exe=", "-ww"), paths)
    tun = Path("/dev/net/tun")
    if tun.exists():
        st = tun.stat()
        inv.put("interface", str(tun), (st.st_mode, st.st_rdev, st.st_ino))


def darwin(inv, paths):
    addresses = defaultdict(list)
    name = None
    for line in output("/sbin/ifconfig", "-a").splitlines():
        if line and not line[0].isspace():
            name = line.split(":", 1)[0]
        elif line.strip().startswith(("inet ", "inet6 ")):
            fields = line.split()
            addresses[name].append(fields[1])
    for index, name in socket.if_nameindex():
        inv.put("interface", name, {"index": index, "addresses": sorted(addresses[name])})
    routes = defaultdict(list)
    for family in ("inet", "inet6"):
        headers = None
        for line in output("netstat", "-rn", "-f", family).splitlines():
            cols = line.split()
            if cols[:1] == ["Destination"]:
                headers = cols
            elif cols and headers:
                row = dict(zip(headers, cols))
                # Link-layer neighbour cache changes as unrelated runner traffic
                # passes. Compare configured and kernel interface routes.
                if "L" not in row["Flags"]:
                    routes[row["Netif"]].append((row["Destination"], row["Gateway"], row["Flags"]))
    for name, entries in routes.items():
        inv.put("route", name, sorted(entries))
    resolver = Path("/etc/resolver")
    if resolver.exists():
        for file in resolver.iterdir():
            if file.is_file():
                inv.put("resolver", str(file), file_identity(file))
    for anchor in ("com.apple/easytier-desk", "com.apple/easytier-desk-g2-foreign"):
        for line in output("/sbin/pfctl", "-a", anchor, "-sr").splitlines():
            label = re.search(r' label "([^"]+)"', line)
            inv.put("firewall", label[1] if label else line, (anchor, line))
    for file in Path("/Library/LaunchDaemons").glob("*.plist"):
        inv.put("service", file.name, file_identity(file))
    processes(inv, output("ps", "-axww", "-o", "pid=,comm="), paths)


def windows(inv, paths):
    env = os.environ.copy()
    env["ETD_G2_IMAGES"] = json.dumps([str(path) for path in paths])
    data = json.loads(command("powershell.exe", "-NoProfile", "-NonInteractive", "-File",
                              Path(__file__).with_name("windows.ps1"), env=env).stdout)
    for kind, entries in data.items():
        for key, value in entries.items():
            inv.put(kind, key, value)
    with tempfile.TemporaryDirectory() as directory:
        state = Path(directory) / "wfp.xml"
        command("netsh.exe", "wfp", "show", "state", f"file={state}")
        tree = ElementTree.parse(state)
        for item in tree.findall(".//item[filterKey]"):
            label = item.findtext("displayData/name", "")
            if label.startswith("etd-fence:"):
                inv.put("firewall", "wfp/" + item.findtext("filterKey"),
                        [label, ElementTree.tostring(item, encoding="unicode")])


def capture(run_dir, images):
    inv = Inventory()
    directories(inv, run_dir)
    {"linux": linux, "darwin": darwin, "win32": windows}[sys.platform](inv, images)
    return inv
