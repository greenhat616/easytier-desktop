"""Native, read-only inventory. No product observer, sweeper, or ledger calls."""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import tempfile
import time
from xml.etree import ElementTree


CLASSES = ("interface", "route", "resolver", "firewall", "registry", "service", "runtime", "process")
WFP_WF = "wfp-group/fwpm_provider_mpssvc_wf/fwpm_sublayer_mpssvc_wf"
WFP_QUARANTINE = "wfp-group/fwpm_provider_mpssvc_wf/fwpm_sublayer_mpssvc_quarantine"
WINDOWS_POLICY_GROUPS = {WFP_WF, WFP_QUARANTINE,
    "wfp-group/fwpm_provider_mpssvc_wf/fwpm_sublayer_teredo",
    "wfp-group/fwpm_provider_mpssvc_wsh/fwpm_sublayer_mpssvc_wsh",
    "wfp-group/fwpm_provider_mpssvc_app_isolation/fwpm_sublayer_mpssvc_app_isolation"}


def command(*args, check=True, timeout=60, **kwargs):
    result = subprocess.run(
        [str(arg) for arg in args], check=False, capture_output=True, text=True,
        encoding="utf-8", errors="replace", timeout=timeout,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0), **kwargs,
    )
    if check and result.returncode:
        message = result.stderr.strip()
        if not message and Path(args[0]).name.lower() in ("sc.exe", "netsh.exe"):
            message = result.stdout.strip()[:400]
        raise RuntimeError(f"{Path(args[0]).name} failed ({result.returncode}): {message}")
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
    descendants: dict = field(default_factory=dict)
    parents: dict = field(default_factory=dict)
    management_workers: set = field(default_factory=set)
    registry_values: dict = field(default_factory=dict)
    profile_connections: list = field(default_factory=list)
    signature_profiles: dict = field(default_factory=dict)
    captured_at: float = field(default_factory=time.time)
    policy_filters: dict = field(default_factory=dict)
    quarantine_fields: dict = field(default_factory=dict)
    application_filters: dict = field(default_factory=dict)

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


def processes(inv, paths):
    import psutil
    roots = [path.resolve() for path in paths]
    psutil.process_iter.cache_clear()
    table = {p.pid: p.info for p in psutil.process_iter(["pid", "ppid", "exe", "create_time"])}
    if sys.platform == "win32" and os.environ.get("RUNNER_TEMP"):
        powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        script = Path(os.environ["RUNNER_TEMP"]) / "g2-release/crates/etd-sysfx-os/src/windows/system.ps1"
        if script.is_file():
            # Match the bytes included in the staged host binary, including
            # its line endings. Retain only verified process identities.
            encoded = base64.b64encode(script.read_bytes().decode().encode("utf-16-le")).decode()
            args = ["-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]
            for pid, row in table.items():
                parent = table.get(row["ppid"])
                if not row["exe"] or Path(row["exe"]) != powershell or not parent or not parent["exe"]:
                    continue
                parent_image = Path(parent["exe"])
                if parent_image.name.lower() != "etd-host.exe" or parent_image not in roots:
                    continue
                try:
                    proc = psutil.Process(pid)
                    argv = proc.cmdline()
                    if (argv and Path(argv[0]) == powershell and argv[1:] == args
                            and proc.create_time() == row["create_time"] and proc.is_running()):
                        inv.management_workers.add((pid, row["create_time"]))
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    pass  # An unverified process never receives an exemption.
    children = defaultdict(list)
    for pid, row in table.items():
        if row["ppid"] != pid:
            children[row["ppid"]].append(pid)
    for parent, row in table.items():
        if not row["exe"]:
            continue
        path = Path(row["exe"]).resolve()
        if not any(path == root or root in path.parents for root in roots):
            continue
        seen = set()
        pending = [parent]
        while pending:
            pid = pending.pop()
            if pid in seen:
                continue
            seen.add(pid)
            child = table[pid]
            born = child["create_time"]
            assert born is not None, f"no creation time for product process {pid}"
            if ("process", str(pid)) not in inv.rows:
                inv.put("process", pid, [child["exe"] or "", born])
                inv.parents[pid] = child["ppid"]
            pending.extend(p for p in children[pid] if table[p]["create_time"] is None
                           or table[p]["create_time"] >= born)
        inv.descendants[parent] = {(pid, table[pid]["create_time"]) for pid in seen - {parent}}


def assert_exited(identities, timeout=0):
    import psutil
    end = time.monotonic() + timeout
    pending = set(identities)
    while pending:
        for pid, born in pending.copy():
            try:
                if psutil.Process(pid).create_time() == born:
                    continue
            except psutil.NoSuchProcess:
                pass
            pending.remove((pid, born))
        if pending:
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise AssertionError(f"old process identities remain: {sorted(pending)}")
            time.sleep(min(remaining, 0.2))


def linux(inv):
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
    # Cover the bytes of every service fragment and drop-in in systemd's
    # native load path, including templates, aliases, masks and service.d.
    # File contents and environment directives never leave this process.
    for directory in set(output("systemd-analyze", "unit-paths").splitlines()):
        root = Path(directory)
        files = set(root.glob("*.service"))
        for pattern in ("*.service.d/*.conf", "service.d/*.conf"):
            files.update(root.glob(pattern))
        for file in files:
            link = os.readlink(file) if file.is_symlink() else None
            inv.put("service", str(file), (link, digest(file) if file.is_file() else None))
    tun = Path("/dev/net/tun")
    try:
        st = tun.lstat()
    except FileNotFoundError:
        return
    inv.put("interface", str(tun), (st.st_mode, st.st_rdev, st.st_ino))


def darwin(inv):
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
    pf = "/sbin/pfctl"
    status = re.search(r"^Status:\s+(Enabled|Disabled)\b", output(pf, "-si"), re.M)
    assert status, "missing PF status"
    inv.put("firewall", "pf/status", status[1])
    refs = [line for line in output(pf, "-s", "References").splitlines() if line.strip()]
    owners = {}
    if [line.strip() for line in refs] != ["No pf starter references held"]:
        if refs and refs[0].strip() == "TOKENS:":
            refs.pop(0)
        assert refs and refs[0].split() == ["PID", "Process", "Name", "TOKEN", "TIMESTAMP"]
        header = refs.pop(0)
        start, end = header.index("TOKEN"), header.index("TIMESTAMP")
        for line in refs:
            token = line[start:end].strip()
            assert token.isdecimal(), "invalid PF reference record"
            fingerprint = hashlib.sha256(token.encode()).hexdigest()
            assert fingerprint not in owners, "duplicate PF reference"
            owners[fingerprint] = tuple(line[:start].split())
    # Compare the enable references and their owners. The TIMESTAMP column
    # is presentation data and the native tokens must never appear in logs.
    inv.put("firewall", "pf/references", owners)
    anchors = output(pf, "-v", "-s", "Anchors").split()
    for anchor in ["", *anchors]:
        args = [pf, "-a", anchor] if anchor else [pf]
        tables = {name: sorted(output(*args, "-t", name, "-T", "show").splitlines())
                  for name in output(*args, "-s", "Tables").split()}
        inv.put("firewall", "pf/anchor/" + anchor, {
            "rules": output(*args, "-sr").splitlines(),
            "nat": output(*args, "-sn").splitlines(), "tables": tables,
        })
    for file in Path("/Library/LaunchDaemons").glob("*.plist"):
        inv.put("service", file.name, file_identity(file))


def wfp_policy_record(item, quarantine_fields=None):
    # Retain the entire record and its structure, except the exact MpsSvc
    # regeneration fields from run 45857049239, ruling msg#1353.
    def content(node):
        children = tuple(content(c) for c in node
                         if not (node is item and c.tag in {"filterKey", "filterId", "providerContextKey"})
                         and not (node.tag == "providerData" and c.tag in {"data", "asString"}))
        value = node.text or ""
        return node.tag, value if value.strip() else "", tuple(sorted(node.attrib.items())), children
    normalized = content(item)
    fingerprint = hashlib.sha256(repr(normalized).encode()).digest()
    if quarantine_fields is not None:
        # Only field paths and hashes are kept for the two-sided diagnostic.
        # Never publish policy values, provider data, or an application path.
        fields = {}
        def visit(node, path):
            tag, value, attrs, children = node
            fields[path] = hashlib.sha256(repr((value, attrs)).encode()).digest()
            for index, child in enumerate(children):
                visit(child, f"{path}/{child[0]}[{index}]")
        visit(normalized, normalized[0])
        quarantine_fields[fingerprint] = fields
    return fingerprint


def wf_application_rule(item):
    if item.findtext("action/type") != "FWP_ACTION_PERMIT":
        return None
    layer = item.findtext("layerKey", "").removeprefix("FWPM_LAYER_ALE_")
    expected = {"FWPM_CONDITION_ALE_APP_ID"}
    if layer in ("RESOURCE_ASSIGNMENT_V4", "RESOURCE_ASSIGNMENT_V6"):
        expected.add("FWPM_CONDITION_IP_PROTOCOL")
    elif layer not in ("AUTH_LISTEN_V4", "AUTH_LISTEN_V6", "AUTH_RECV_ACCEPT_V4", "AUTH_RECV_ACCEPT_V6"):
        return None
    conditions = item.findall("filterCondition/item")
    if len(conditions) != len(expected) or {c.findtext("fieldKey") for c in conditions} != expected:
        return None
    app = next(c for c in conditions if c.findtext("fieldKey") == "FWPM_CONDITION_ALE_APP_ID")
    if app.findtext("matchType") != "FWP_MATCH_EQUAL":
        return None
    if app.findtext("conditionValue/type") != "FWP_BYTE_BLOB_TYPE":
        return None
    data = app.findtext("conditionValue/byteBlob/data")
    if not data:
        return None
    return layer, hashlib.sha256(bytes.fromhex(data)).digest()


def native_application_id(path):
    import ctypes
    class Blob(ctypes.Structure):
        _fields_ = [("size", ctypes.c_uint32), ("data", ctypes.POINTER(ctypes.c_ubyte))]
    native = ctypes.WinDLL("fwpuclnt")
    ptr = ctypes.POINTER(Blob)()
    get = native.FwpmGetAppIdFromFileName0
    get.argtypes = [ctypes.c_wchar_p, ctypes.POINTER(ctypes.POINTER(Blob))]
    get.restype = ctypes.c_uint32
    rc = get(str(path), ctypes.byref(ptr))
    if rc:
        raise ctypes.WinError(rc)
    try:
        return hashlib.sha256(ctypes.string_at(ptr.contents.data, ptr.contents.size)).digest()
    finally:
        free = native.FwpmFreeMemory0
        free.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
        free.restype = None
        free(ctypes.cast(ctypes.byref(ptr), free.argtypes[0]))


def native_interface_guid(index):
    import ctypes
    from uuid import UUID
    native = ctypes.WinDLL("iphlpapi")
    luid = ctypes.c_uint64()
    data = (ctypes.c_ubyte * 16)()
    to_luid = native.ConvertInterfaceIndexToLuid
    to_luid.argtypes = [ctypes.c_uint32, ctypes.POINTER(ctypes.c_uint64)]
    to_guid = native.ConvertInterfaceLuidToGuid
    to_guid.argtypes = [ctypes.POINTER(ctypes.c_uint64), ctypes.POINTER(type(data))]
    rc = to_luid(index, ctypes.byref(luid))
    if not rc:
        rc = to_guid(ctypes.byref(luid), ctypes.byref(data))
    if rc:
        raise ctypes.WinError(rc)
    return UUID(bytes_le=bytes(data))


def windows_registry(inv):
    import ctypes
    from ctypes import wintypes
    import winreg
    from uuid import UUID
    query = ctypes.WinDLL("advapi32").RegQueryValueExW
    query.argtypes = [wintypes.HKEY, wintypes.LPCWSTR, ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD),
                      ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD)]
    query.restype = wintypes.LONG
    services = r"SYSTEM\CurrentControlSet\Services"
    network_list = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList"
    signatures = network_list + r"\Signatures"
    key_trees = (r"SOFTWARE\EasyTier", r"SOFTWARE\EasyTierDesk", signatures)
    trees = [*key_trees, network_list + r"\Profiles",
             *(services + "\\" + stack + r"\Parameters\Interfaces" for stack in ("Tcpip", "Tcpip6", "NetBT"))]

    def visit(key, path, root):
        if root in key_trees:
            inv.put("registry", "key/HKLM\\" + path, ["key"])
        children, values, _ = winreg.QueryInfoKey(key)
        for index in range(values):
            name, _, _ = winreg.EnumValue(key, index)
            # Get the original bytes even for unknown types, unexpanded paths,
            # or unusual string terminators. Compare type and bytes together.
            size = wintypes.DWORD()
            kind = wintypes.DWORD()
            rc = query(int(key), name, None, ctypes.byref(kind), None, ctypes.byref(size))
            if rc:
                raise ctypes.WinError(rc)
            for _ in range(5):
                data = ctypes.create_string_buffer(max(1, size.value))
                rc = query(int(key), name, None, ctypes.byref(kind), data, ctypes.byref(size))
                if rc != 234:  # ERROR_MORE_DATA if the value grew between the reads
                    break
            if rc:
                raise ctypes.WinError(rc)
            key_name = "HKLM\\" + path + "\\" + name
            raw = data.raw[:size.value]
            fingerprint = hashlib.sha256(kind.value.to_bytes(4, "little") + raw).hexdigest()
            inv.put("registry", key_name, (kind.value, fingerprint))
            # Only these semantic values are needed for plan and default
            # checks. The strict diff above always compares the native bytes.
            if kind.value == winreg.REG_DWORD and len(raw) == 4:
                inv.registry_values[key_name] = ["DWord", int.from_bytes(raw, "little")]
            elif kind.value == winreg.REG_SZ:
                if raw in (b"", b"\x00\x00"):
                    inv.registry_values[key_name] = ["String", ""]
                elif name == "ProfileName":
                    inv.registry_values[key_name] = ["String", raw.decode("utf-16-le").removesuffix("\0")]
                elif root == signatures and name.casefold() == "profileguid":
                    try:
                        inv.signature_profiles[key_name] = UUID(raw.decode("utf-16-le").removesuffix("\0"))
                    except ValueError:
                        pass  # Malformed references still have a typed fingerprint.
            elif name == "NameServerList" and kind.value == winreg.REG_MULTI_SZ and raw in (b"", b"\0\0", b"\0\0\0\0"):
                inv.registry_values[key_name] = ["MultiString", []]
            elif name in ("DateCreated", "DateLastConnected") and kind.value == winreg.REG_BINARY and len(raw) == 16:
                year, month, weekday, day, hour, minute, second, ms = struct.unpack("<8H", raw)
                try:
                    stamp = datetime(year, month, day, hour, minute, second, ms * 1000)
                    if weekday == stamp.isoweekday() % 7:
                        inv.registry_values[key_name] = ["SYSTEMTIME", stamp.timestamp()]
                except (ValueError, OSError, OverflowError):
                    pass  # An invalid native time remains in the strict byte-level diff.
        for index in range(children):
            name = winreg.EnumKey(key, index)
            with winreg.OpenKey(key, name) as child:
                visit(child, path + "\\" + name, root)

    for path in trees:
        try:
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        except FileNotFoundError:
            continue
        with key:
            visit(key, path, path)


def windows(inv):
    windows_registry(inv)
    data = json.loads(command("powershell.exe", "-NoProfile", "-NonInteractive", "-File",
                              Path(__file__).with_name("windows.ps1"), timeout=180).stdout)
    inv.profile_connections = data.pop("networkProfiles")
    # Win32_SystemDriver can omit a disabled SCM registration with no
    # loadable image. SCM is authoritative for these two product-wide names.
    for name in ("wintun", "windivert"):
        result = command("sc.exe", "qc", name, check=False)
        if result.returncode == 1060:  # ERROR_SERVICE_DOES_NOT_EXIST
            data["service"].pop(name, None)
        elif result.returncode:
            raise RuntimeError(f"SCM query configuration for {name}: {result.returncode}")
        else:
            data["service"][name] = result.stdout.strip()
    for kind, entries in data.items():
        for key, value in entries.items():
            inv.put(kind, key, value)
    with tempfile.TemporaryDirectory() as directory:
        filters = Path(directory) / "filters.xml"
        command("netsh.exe", "wfp", "show", "filters", "verbose=on", f"file={filters}")
        groups = defaultdict(dict)
        for _, item in ElementTree.iterparse(filters):
            if item.tag != "item" or item.find("filterKey") is None:
                continue
            key = item.findtext("filterKey").strip().lower()
            group = tuple(item.findtext(field, "").strip().strip("{}").lower()
                          for field in ("providerKey", "subLayerKey"))
            assert key and key not in groups[group], "missing or duplicate WFP filter key"
            group_name = "wfp-group/" + "/".join(group)
            item.tail = None  # whitespace between XML records is not filter configuration
            raw = ElementTree.tostring(item, encoding="utf-8")
            groups[group][key] = hashlib.sha256(raw).digest()
            if group_name in WINDOWS_POLICY_GROUPS:
                fingerprint = wfp_policy_record(item, inv.quarantine_fields if group_name == WFP_QUARANTINE else None)
                inv.policy_filters.setdefault(group_name, Counter())[fingerprint] += 1
                if group_name == WFP_WF:
                    inv.application_filters[fingerprint] = wf_application_rule(item)
            label = item.findtext("displayData/name", "").strip()
            if ("51e7d001-7bc3-43b9-a795-7b80c196382f" in group
                    or "51e7d002-7bc3-43b9-a795-7b80c196382f" in group):
                inv.put("firewall", "wfp/" + key,
                        [label, ElementTree.tostring(item, encoding="unicode")])
            item.clear()
        assert groups, "WFP export contains no native filters"
        for group, records in groups.items():
            inv.put("firewall", "wfp-group/" + "/".join(group), records)


def capture(run_dir, images, other_run_dirs=()):
    inv = Inventory()
    for root in (run_dir, *other_run_dirs):
        if root.exists():
            directories(inv, root)
    {"linux": linux, "darwin": darwin, "win32": windows}[sys.platform](inv)
    processes(inv, images)
    return inv
