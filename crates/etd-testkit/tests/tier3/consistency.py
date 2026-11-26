"""Compare persisted launch intents with native observations, in both directions."""

from pathlib import Path
from collections import Counter
import json
import os
import stat
import time
from uuid import UUID
from inventory import WINDOWS_POLICY_GROUPS, WFP_QUARANTINE, WFP_WF


class UnpredictedChanges(AssertionError):
    """All expected objects were verified, but there were additional changes."""


class FirewallReadbackPending(AssertionError):
    """The native program rule and its asynchronous ledger readback differ."""


def scope(instance, epoch):
    return {"instance": {"instance": instance, "epoch": epoch}}


def installed_image(value):
    return Path(value[0] if isinstance(value, list) else value)


def management_processes(base, live, host_image):
    verified = set()
    for pid, started in live.management_workers:
        parent = live.parents.get(pid)
        host_key = ("process", str(parent))
        host = live.rows.get(host_key)
        if not host or installed_image(host) != host_image or host != base.rows.get(host_key):
            continue
        assert started >= host[1]
        verified.add((pid, started))
        console = Path(os.environ["SystemRoot"]) / "System32/conhost.exe"
        children = {(child, born) for child, born in live.descendants[parent]
                    if live.parents[child] == pid and born >= started
                    and installed_image(live.rows["process", str(child)]) == console}
        assert len(children) <= 1, "extra console hosts for management worker"
        verified.update(children)
        print(f"verified management script: host={parent} worker={pid} console={sorted(children)}", flush=True)
    return verified


def managed_service_changes(base, live):
    # Windows SCM changed only IKEEXT Start from demand to automatic.
    # Run 45834730897, Security 4657 record 583086, ruling in msg#1186.
    key = ("service", "ikeext")
    before = base.rows.get(key)
    if (os.name == "nt" and isinstance(before, dict) and before.get("Start") == 3
            and live.rows.get(key) == {**before, "Start": 2}):
        return {key}
    return set()


def tun_created(base, live):
    key = ("interface", "/dev/net/tun")
    native = live.rows.get(key)
    return {key} if (key not in base.rows and native and stat.S_ISCHR(native[0])
                     and os.major(native[1]) == 10 and os.minor(native[1]) == 200) else set()


def adapter_defaults(base, live, adapter_indices):
    # Windows retains these exact defaults under a newly created adapter's
    # GUID after it goes away (paired run 45854603162, ruling msg#1321).
    # The DHCPv6 IAID high byte identifies the recorded live adapter index.
    # Run 45861957387, ruling msg#1388. No assumption on its low 24 bits.
    expected = {}
    iaids = {}
    for guid, index in adapter_indices.items():
        netbt = rf"HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_{{{guid}}}\NameServerList"
        expected[netbt.casefold()] = ["MultiString", []]
        for stack in ("Tcpip", "Tcpip6"):
            prefix = rf"HKLM\SYSTEM\CurrentControlSet\Services\{stack}\Parameters\Interfaces\{{{guid}}}"
            fields = {"EnableDHCP": ["DWord", 0]}
            if stack == "Tcpip":
                fields.update(NameServer=["String", ""], Domain=["String", ""])
            else:
                fields["Dhcpv6State"] = ["DWord", 0]
                iaids[(prefix + "\\Dhcpv6Iaid").casefold()] = index
            expected.update({(prefix + "\\" + name).casefold(): value for name, value in fields.items()})
    allowed = set()
    for key in live.rows:
        if key[0] != "registry" or key in base.rows:
            continue
        path = key[1].casefold()
        setting = live.registry_values.get(key[1])
        if path in expected and setting == expected[path]:
            allowed.add(key)
        elif path in iaids and setting:
            kind, value = setting
            if kind == "DWord" and type(value) is int and 0 <= value <= 0xffffffff and value >> 24 == iaids[path]:
                allowed.add(key)
    return allowed


def runner_noise(base, live):
    # Hosted-image noise, independent of product launch: the idle control in
    # run 45841944759 recorded services.exe changing BITS Start (4657 #582930).
    key = ("service", "bits")
    before, after = base.rows.get(key), live.rows.get(key)
    if os.name == "nt" and isinstance(before, dict) and isinstance(after, dict):
        transition = {before.get("Start"), after.get("Start")}
        if transition == {2, 3} and after == {**before, "Start": after["Start"]}:
            return {key}
    return set()


def active_signature(base, live, profile_guid):
    unmanaged = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged"
    matches = [path for path, target in live.signature_profiles.items()
               if target == profile_guid and path.rsplit("\\", 2)[0] == unmanaged]
    if len(matches) != 1:
        return set()
    signature = matches[0].rsplit("\\", 1)[0]
    key = ("registry", "key/" + signature)
    values = {("registry", signature + "\\" + field) for field in
              ("ProfileGuid", "Description", "FirstNetwork", "DnsSuffix", "DefaultGatewayMac", "Source")}
    if key in base.rows or not values <= live.rows.keys():
        return set()
    print(f"native NLA signature {signature} points to active profile {profile_guid}", flush=True)
    return values | {key}


def profile_metadata(base, live, profile_name_key, name, credential):
    profile = profile_name_key.rsplit("\\", 1)[0]
    profile_guid = UUID(profile.rsplit("\\", 1)[1])
    assert profile_guid == UUID(credential), "native profile GUID differs from the ledger"
    assert profile_name_key.startswith(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles" + "\\")
    assert not any(kind == "registry" and path.startswith(profile + "\\") for kind, path in base.rows)
    nic = live.rows["interface", name]
    connections = [c for c in live.profile_connections if c["index"] == nic["index"]]
    assert connections == [{"alias": name, "index": nic["index"], "matches": True}], "native NLA profile/adapter mismatch"
    print(f"active NLA profile {profile_guid}: adapter={name} GUID={nic['guid']} ifIndex={nic['index']}", flush=True)
    # Windows NLA creates these only while this specific adapter's profile
    # exists. At stop and afterwards all five native values must disappear.
    included = active_signature(base, live, profile_guid)
    description = ("registry", profile + "\\Description")
    if live.rows.get(description) == live.rows["registry", profile_name_key]:
        included.add(description)
    for field, value in (("NameType", 53), ("Managed", 0)):
        path = profile + "\\" + field
        if live.registry_values.get(path) == ["DWord", value]:
            included.add(("registry", path))
    start = base.captured_at
    for field in ("DateCreated", "DateLastConnected"):
        path = profile + "\\" + field
        stamp = live.registry_values.get(path)
        if stamp and stamp[0] == "SYSTEMTIME" and start <= stamp[1] <= time.time():
            included.add(("registry", path))
            start = stamp[1]
    return included


def system_policy_changes(base, live, phase, retained_app=None, *, fixture_tunnel=False):
    # Product allow-list, not hosted-runner noise. MpsSvc recompiles these
    # five groups on adapter changes (45857049239, rulings 1353 and 1355).
    allowed = set()
    for group in sorted(WINDOWS_POLICY_GROUPS):
        key = ("firewall", group)
        if key not in base.rows and key not in live.rows:
            continue
        prior = base.policy_filters.get(group, Counter())
        current = live.policy_filters.get(group, Counter())
        missing, extra = prior - current, current - prior
        print(f"{phase} {group}: {prior.total()} -> {current.total()}, "
              f"missing={missing.total()} extra={extra.total()}", flush=True)
        if group == WFP_QUARANTINE and fixture_tunnel and (missing or extra):
            # The independent, tunnel-free job judges this group across stop,
            # purge and uninstall. Record replacements while the foreign
            # IPv6 tunnel is present (ruling msg#1502, control 45863459869).
            added = [live.quarantine_fields[x] for x in extra.elements()]
            for key_hash in missing.elements():
                prior_fields = base.quarantine_fields[key_hash]
                if not added:
                    break
                def changes(fields):
                    return {k for k in prior_fields.keys() | fields.keys() if prior_fields.get(k) != fields.get(k)}
                index = min(range(len(added)), key=lambda i: len(changes(added[i])))
                print(f"{phase} fixture Quarantine nearest replacement fields: {sorted(changes(added.pop(index)))}",
                      flush=True)
            allowed.add(key)
        elif phase == "active" or (not missing and not extra):
            allowed.add(key)
        elif group == WFP_WF and phase == "stopped" and retained_app is not None and not missing:
            expected = {(layer + version, retained_app)
                        for layer in ("AUTH_LISTEN", "AUTH_RECV_ACCEPT", "RESOURCE_ASSIGNMENT")
                        for version in ("_V4", "_V6")}
            actual = {live.application_filters.get(digest) for digest in extra}
            if extra.total() == 6 and actual == expected:
                allowed.add(key)
    return allowed


def check_generation(base, live, records, instance, view, adapter_indices, worker_keys):
    try:
        return compare_generation(base, live, records, instance, view, adapter_indices, worker_keys)
    except FirewallReadbackPending:
        raise
    except (AssertionError, KeyError, OSError):
        for kind, key in sorted(base.delta(live)):
            print(f"native delta: {kind} {key}", flush=True)
            if kind == "process":
                source = live if (kind, key) in live.rows else base
                path, born = source.rows[kind, key]
                parent = source.parents.get(int(key))
                parent_row = source.rows.get((kind, str(parent)))
                print(f"process {key} image={Path(path).name} created={born} parent={parent} "
                      f"parent_image={Path(parent_row[0]).name if parent_row else 'outside tree'}", flush=True)
            if kind == "service":
                old = base.rows.get((kind, key))
                new = live.rows.get((kind, key))
                if isinstance(old, dict) and isinstance(new, dict):
                    for field in sorted(old.keys() | new.keys()):
                        if old.get(field) != new.get(field):
                            detail = (f"{old.get(field)} -> {new.get(field)}"
                                      if field in {"Type", "Start", "ErrorControl"} else "changed")
                            print(f"service {key} {field}: {detail}", flush=True)
        for row in records:
            if row["state"] != "reclaimed":
                print(f"open intent: {row['kind']} {row['state']}", flush=True)
        raise


def compare_generation(base, live, records, instance, view, adapter_indices, worker_keys):
    changed = base.delta(live)
    expected = set(worker_keys)
    active = [r for r in records if r["state"] != "reclaimed"
              and (r["scope"] == scope(instance, view["epoch"]) or "instance" not in r["scope"])]
    kinds = {r["kind"] for r in active}
    assert {"process", "run_dir", "route"} <= kinds, kinds
    assert kinds & {"linux.tun", "macos.utun", "win.tun"}, kinds
    assert kinds & {"linux.fence_rule", "macos.fence_rule", "win.fence_filter"}, kinds
    name = view["interface_name"]
    # macOS learns its actual name after spawn. Retrieve it from the kernel
    # inventory if the status has not published it, requiring a unique addition.
    if not name or ("interface", name) not in live.rows:
        names = [key for kind, key in changed if kind == "interface" and key.startswith("utun")
                 and ("interface", key) in live.rows]
        assert len(names) == 1, "missing or ambiguous system-assigned utun"
        name = names[0]
    for record in active:
        key = record["key"]
        kind = record["kind"]
        obs = record.get("observation") or {}
        if kind == "upnp_mapping":
            # A remote gateway lease has no local system object.
            assert key["type"] == "port_mapping"
            continue
        if kind == "service_registration":
            continue  # installed before the launch baseline
        if key["type"] == "interface":
            matches = {("interface", name)}
            assert not key.get("name") or key["name"] == name
            if kind == "win.tun":
                assert record["scope"] == scope(instance, view["epoch"])
                assert ("interface", name) not in base.rows
                guid = UUID(live.rows["interface", name]["guid"])
                assert all(UUID(v["guid"]) != guid for (cls, _), v in base.rows.items()
                           if cls == "interface" and v.get("guid"))
                if key.get("guid"):
                    assert UUID(key["guid"]) == guid
                adapter_indices[guid] = live.rows["interface", name]["index"]
        elif key["type"] == "routes_via":
            matches = {("route", name)}
        elif key["type"] == "path" and kind == "run_dir":
            path = Path(key["path"])
            matches = {k for k in live.rows if k[0] == "runtime" and path.samefile(k[1])}
            assert len(matches) == 1, f"expected one native runtime directory for {path}"
        elif kind == "process":
            pid = int((obs.get("credential") or {})["pid"])
            matches = {("process", str(pid))}
            for match in matches:
                observed = installed_image(live.rows[match])
                assert observed.samefile(key["exe"]), f"PID {match[1]} uses {observed}; plan {key['exe']}"
            if os.name == "nt":
                # The Windows hidden console can have one native conhost child.
                # Generation end checks use its PID *and* creation time.
                console = Path(os.environ["SystemRoot"]) / "System32/conhost.exe"
                born = live.rows["process", str(pid)][1]
                children = {("process", str(child)) for child, started in live.descendants[pid]
                            if live.parents[child] == pid and started >= born
                            and installed_image(live.rows["process", str(child)]) == console}
                assert len(children) <= 1, "unexpected additional console host"
                matches.update(children)
        elif key["type"] == "resolved_link":
            matches = {("resolver", key["interface"])}
        elif key["type"] == "fence":
            if kind == "linux.fence_rule":
                matches = {("firewall", "inet/" + key["container"])}
            elif kind == "macos.fence_rule":
                anchor = ("firewall", "pf/anchor/com.apple/easytier-desk")
                policy = live.rows[anchor]
                before = base.rows.get(anchor, {"rules": [], "nat": [], "tables": {}})
                remaining = policy["rules"].copy()
                for suffix in ("-v4", "-v6"):
                    label = key["rule"] + suffix
                    own = [line for line in remaining if f' label "{label}"' in line]
                    assert len(own) == 1, f"expected one native PF rule for {label}"
                    remaining.remove(own[0])
                assert {**policy, "rules": remaining} == before, "unexpected change within PF anchor"
                matches = {anchor}
            else:
                label = f"etd-fence:{key['rule']}:{key['port']}"
                matches = {k for k, v in live.rows.items()
                           if k[0] == "firewall" and k[1].startswith("wfp/") and v[0] == label}
                assert len(matches) == 4, f"expected four native WFP filters for {label}"
                group = ("firewall", "wfp-group/51e7d001-7bc3-43b9-a795-7b80c196382f/"
                         "51e7d002-7bc3-43b9-a795-7b80c196382f")
                prior = set(base.rows.get(group, []))
                ids = {k[1].removeprefix("wfp/") for k in matches}
                assert not prior & ids and set(live.rows[group]) == prior | ids
                matches.add(group)
        elif key["type"] == "service":
            matches = {("service", key["name"].lower())}
            if kind == "driver":
                assert record["scope"] == "product"
                # WinDivert is a conditional intent. It loads on demand for
                # faketcp / broadcast, neither is enabled in this fixture.
                if key["name"].lower() == "windivert" and not matches & live.rows.keys():
                    continue
        elif kind in ("win.firewall_rule", "win.program_firewall_rule"):
            matches = {k for k, v in live.rows.items() if k[0] == "firewall"
                       and k[1].startswith("policy/") and v[:2] == [key["name"], key["group"]]}
            assert len(matches) == 1, f"ambiguous or missing rule {key['name']}"
            match = next(iter(matches))
            value = obs["credential"]["value"]
            rule_id = match[1].removeprefix("policy/")
            if kind == "win.program_firewall_rule":
                assert "core_binary" in record["scope"]
                rule_name, group, direction, _, _, image, *_ = live.rows[match]
                credential = json.loads(value)
                if credential != {
                    "id": rule_id, "name": rule_name.lower(), "group": group.lower(),
                    "direction": direction.lower(), "program": image.removeprefix("\\\\?\\").lower(),
                }:
                    raise FirewallReadbackPending(
                        f"{rule_name}: native ID {rule_id}, ledger ID {credential.get('id')}; "
                        "full program rule credential differs"
                    )
            else:
                assert value == rule_id, f"stale interface rule credential for {key['name']}"
        elif kind == "win.registry_value":
            path = key["key"] + "\\" + key["value"]
            matches = {k for k in live.rows if k[0] == "registry" and k[1].casefold() == path.casefold()}
            assert len(matches) == 1, f"missing registry value {path}"
            setting = record["undo"]["ours"]
            assert setting["type"] == "u32"
            assert live.registry_values.get(next(iter(matches))[1]) == ["DWord", setting["value"]], path
        elif kind == "win.network_profile":
            matches = {("registry", path) for path, value in live.registry_values.items()
                       if path.endswith("\\ProfileName") and value == ["String", key["profile_name"]]}
            assert len(matches) == 1, f"NetworkList profile for {name}"
            assert key["profile_name"] == name and ("interface", name) not in base.rows
            profile_name_key = next(iter(matches))[1]
            matches.update(profile_metadata(base, live, profile_name_key, name, obs["credential"]["value"]))
        else:
            raise AssertionError(f"unmapped local launch effect {kind}")
        assert matches <= live.rows.keys(), f"predicted but absent: {matches - live.rows.keys()}"
        expected.update(matches)
    # These changes intentionally have no separate ownership record.
    # Match the precise object and transition, never a registry subtree.
    exempt = managed_service_changes(base, live) | tun_created(base, live)
    exempt |= adapter_defaults(base, live, adapter_indices) | system_policy_changes(base, live, "active")
    for kind, path in expected:
        if kind == "registry" and path.endswith("\\ProfileName"):
            category = ("registry", path.removesuffix("ProfileName") + "Category")
            if live.registry_values.get(category[1]) == ["DWord", 1]:
                exempt.add(category)
    assert expected <= changed, f"predicted effects already present at baseline: {sorted(expected - changed)}"
    unexpected = changed - expected - exempt - runner_noise(base, live)
    if unexpected:
        raise UnpredictedChanges(f"unpredicted native changes: {sorted(unexpected)}")
    for kind in sorted({k[0] for k in live.rows}):
        print(f"{kind}: baseline={base.counts()[kind]} live={live.counts()[kind]} "
              f"changed={sum(k[0] == kind for k in changed)}")
    return expected


def check_closed(service, instance, epoch):
    pending = [(r["kind"], r["state"]) for r in service.effects()
               if r["scope"] == scope(instance, epoch) and r["state"] != "reclaimed"]
    assert not pending, f"generation {epoch} still has open records: {pending}"
