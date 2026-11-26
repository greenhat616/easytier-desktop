"""Compare persisted launch intents with native observations, in both directions."""

from pathlib import Path
import json
import os
import stat


class UnpredictedChanges(AssertionError):
    """All expected objects were verified, but there were additional changes."""


def scope(instance, epoch):
    return {"instance": {"instance": instance, "epoch": epoch}}


def installed_image(value):
    return Path(value[0] if isinstance(value, list) else value)


def managed_service_changes(base, live):
    # Windows SCM changed only IKEEXT Start from demand to automatic.
    # Run 45834730897, Security 4657 record 583086, ruling in msg#1186.
    key = ("service", "ikeext")
    before = base.rows.get(key)
    if (os.name == "nt" and isinstance(before, dict) and before.get("Start") == 3
            and live.rows.get(key) == {**before, "Start": 2}):
        return {key}
    return set()


def check_generation(base, live, records, instance, view):
    try:
        return compare_generation(base, live, records, instance, view)
    except (AssertionError, KeyError, OSError):
        for kind, key in sorted(base.delta(live)):
            print(f"native delta: {kind} {key}", flush=True)
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


def compare_generation(base, live, records, instance, view):
    changed = base.delta(live)
    expected = set()
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
        elif key["type"] == "routes_via":
            matches = {("route", name)}
        elif key["type"] == "path" and kind == "run_dir":
            path = Path(key["path"])
            matches = {k for k in live.rows if k[0] == "runtime" and path.samefile(k[1])}
            assert len(matches) == 1, f"expected one native runtime directory for {path}"
        elif kind == "process":
            matches = {("process", str((obs.get("credential") or {})["pid"]))}
            for match in matches:
                observed = installed_image(live.rows[match])
                assert observed.samefile(key["exe"]), f"PID {match[1]} uses {observed}; plan {key['exe']}"
        elif key["type"] == "resolved_link":
            matches = {("resolver", key["interface"])}
        elif key["type"] == "fence":
            if kind == "linux.fence_rule":
                matches = {("firewall", "inet/" + key["container"])}
            elif kind == "macos.fence_rule":
                matches = {("firewall", key["rule"] + suffix) for suffix in ("-v4", "-v6")}
            else:
                label = f"etd-fence:{key['rule']}:{key['port']}"
                matches = {k for k, v in live.rows.items()
                           if k[0] == "firewall" and k[1].startswith("wfp/") and v[0] == label}
                assert len(matches) == 4, f"expected four native WFP filters for {label}"
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
                assert json.loads(value) == {
                    "id": rule_id, "name": rule_name.lower(), "group": group.lower(),
                    "direction": direction.lower(), "program": image.removeprefix("\\\\?\\").lower(),
                }, f"stale program rule credential for {rule_name}"
            else:
                assert value == rule_id, f"stale interface rule credential for {key['name']}"
        elif kind == "win.registry_value":
            path = key["key"] + "\\" + key["value"]
            matches = {k for k in live.rows if k[0] == "registry" and k[1].casefold() == path.casefold()}
            assert len(matches) == 1, f"missing registry value {path}"
            setting = record["undo"]["ours"]
            assert setting["type"] == "u32"
            assert live.rows[next(iter(matches))] == ["DWord", setting["value"]], path
        elif kind == "win.network_profile":
            matches = {k for k, v in live.rows.items() if k[0] == "registry"
                       and k[1].endswith("\\ProfileName") and v[-1] == key["profile_name"]}
            assert len(matches) == 1, f"NetworkList profile for {name}"
        else:
            raise AssertionError(f"unmapped local launch effect {kind}")
        assert matches <= live.rows.keys(), f"predicted but absent: {matches - live.rows.keys()}"
        expected.update(matches)
    # These changes intentionally have no separate ownership record.
    # Match the precise object and transition, never a registry subtree.
    exempt = managed_service_changes(base, live)
    tun = ("interface", "/dev/net/tun")
    if tun not in base.rows and tun in live.rows and stat.S_ISCHR(live.rows[tun][0]):
        exempt.add(tun)
    for kind, path in expected:
        if kind == "registry" and path.endswith("\\ProfileName"):
            category = ("registry", path.removesuffix("ProfileName") + "Category")
            if live.rows.get(category) == ["DWord", 1]:
                exempt.add(category)
    assert expected <= changed, f"predicted effects already present at baseline: {sorted(expected - changed)}"
    unexpected = changed - expected - exempt
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
