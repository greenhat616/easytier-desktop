"""Compare persisted launch intents with native observations, in both directions."""

from pathlib import Path
import stat


def scope(instance, epoch):
    return {"instance": {"instance": instance, "epoch": epoch}}


def installed_image(value):
    return Path(value[0] if isinstance(value, list) else value)


def check_generation(base, live, records, instance, view):
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
            matches = {("runtime", key["path"])}
        elif kind == "process":
            matches = {("process", str((obs.get("credential") or {})["pid"]))}
            for match in matches:
                assert installed_image(live.rows[match]).resolve() == Path(key["exe"]).resolve()
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
            assert len(matches) == 1 and obs.get("credential"), f"rule identity for {key['name']}"
        elif kind == "win.registry_value":
            matches = {("registry", key["key"] + "\\" + key["value"])}
        elif kind == "win.network_profile":
            matches = {k for k, v in live.rows.items() if k[0] == "registry"
                       and k[1].endswith("\\ProfileName") and v[-1] == key["profile_name"]}
            assert len(matches) == 1, f"NetworkList profile for {name}"
        else:
            raise AssertionError(f"unmapped local launch effect {kind}")
        assert matches <= live.rows.keys(), f"predicted but absent: {matches - live.rows.keys()}"
        expected.update(matches)
    # Two upstream changes intentionally have no separate ownership record.
    # Match the precise object and transition, never a registry subtree.
    exempt = set()
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
    assert not unexpected, f"unpredicted native changes: {sorted(unexpected)}"
    for kind in sorted({k[0] for k in live.rows}):
        print(f"{kind}: baseline={base.counts()[kind]} live={live.counts()[kind]} "
              f"changed={sum(k[0] == kind for k in changed)}")
    return expected


def check_closed(service, instance, epoch):
    pending = [(r["kind"], r["state"]) for r in service.effects()
               if r["scope"] == scope(instance, epoch) and r["state"] != "reclaimed"]
    assert not pending, f"generation {epoch} still has open records: {pending}"
