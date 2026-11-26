"""Native, read-only inventory. No product observer, sweeper, or ledger calls."""

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import hashlib
import json
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
from xml.etree import ElementTree


CLASSES = ("interface", "route", "resolver", "firewall", "registry", "service", "runtime", "process")
WFP_WF = "wfp-group/fwpm_provider_mpssvc_wf/fwpm_sublayer_mpssvc_wf"
WINDOWS_POLICY_GROUPS = {WFP_WF,
    "wfp-group/fwpm_provider_mpssvc_wf/fwpm_sublayer_mpssvc_quarantine",
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
    policy_filters: dict = field(default_factory=dict)
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


def assert_exited(identities):
    import psutil
    for pid, born in identities:
        try:
            if psutil.Process(pid).create_time() == born:
                raise AssertionError(f"old process identity remains: pid={pid}, created={born}")
        except psutil.NoSuchProcess:
            pass


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
        config = output("systemctl", "cat", unit) if unit.startswith("easytier-desk") else None
        inv.put("service", unit, (state, hashlib.sha256(config.encode()).hexdigest() if config else None))
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


def wfp_policy_record(item):
    # Retain the entire record and its structure, except the exact MpsSvc
    # regeneration fields from run 45857049239, ruling msg#1353.
    def content(node):
        children = tuple(content(c) for c in node
                         if not (node is item and c.tag in {"filterKey", "filterId", "providerContextKey"})
                         and not (node.tag == "providerData" and c.tag in {"data", "asString"}))
        value = node.text or ""
        return node.tag, value if value.strip() else "", tuple(sorted(node.attrib.items())), children
    return hashlib.sha256(repr(content(item)).encode()).digest()


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


def windows(inv):
    data = json.loads(command("powershell.exe", "-NoProfile", "-NonInteractive", "-File",
                              Path(__file__).with_name("windows.ps1"), timeout=180).stdout)
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
                fingerprint = wfp_policy_record(item)
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
