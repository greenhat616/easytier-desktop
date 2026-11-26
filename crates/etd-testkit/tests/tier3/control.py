"""Matched idle/start observations on fresh hosted runners."""
from service import Service
from product import spec
import os
import time
import uuid
from collections import Counter
from pathlib import Path
from service import eventually

service = Service()
group = os.environ["G2_GROUP"]

def compare(stage, base, current):
    delta = base.delta(current)
    print(f"{group} {stage} {len(delta)} differences; totals {current.counts()}", flush=True)
    for kind, key in sorted(delta):
        k = (kind, key)
        old, new = base.rows.get(k), current.rows.get(k)
        detail = "added" if old is None else "removed" if new is None else "modified"
        if key.startswith("wfp-group/"):
            old, new = set(old or []), set(new or [])
            detail = f"filters {len(old)} to {len(new)}, added {len(new-old)}, removed {len(old-new)}"
            prior, latest = base.wfp.get(key, {}), current.wfp.get(key, {})
            for index, label in enumerate(("content", "withoutEffectiveWeight")):
                old_content = Counter(value[0][index] for value in prior.values())
                new_content = Counter(value[0][index] for value in latest.values())
                lost, gained = old_content-new_content, new_content-old_content
                detail += f" {label} removed={lost.total()} added={gained.total()}"
                if index == 1:
                    for values, counts, verb in [(prior,lost,"lost"),(latest,gained,"gained")]:
                        summaries = {str(summary) for hashes,summary in values.values() if hashes[index] in counts}
                        print(f"{group} {stage} {key} {verb} templates {sorted(summaries)[:12]}",flush=True)
        elif kind == "registry" and key.rsplit(chr(92), 1)[-1] in ("NameServer","Domain","EnableDHCP"):
            def safe(value):
                if value is None:
                    return "absent"
                typ, val = value
                return (typ, val if isinstance(val,int) or val == "" else "<nonempty>")
            detail += f" {safe(old)} to {safe(new)}"
        elif kind == "process":
            native = new or old
            ancestors = [pid for pid,ids in current.descendants.items() if (int(key),native[1]) in ids]
            detail += f" image={Path(native[0]).name} creation={native[1]} tracked_ancestors={ancestors}"
        elif kind == "interface" and isinstance(new,dict):
            detail += f" guid={new.get('guid')}"
        elif kind == "service" and isinstance(old, dict) and isinstance(new, dict):
            detail += " fields " + str([field for field in old.keys() | new.keys() if old.get(field) != new.get(field)])
        print(f"{group} {stage} {kind} {key} {detail}", flush=True)

pre = service.inventory()
try:
    with service.installed():
        base = service.inventory()
        compare("install", pre, base)
        start = time.monotonic()
        if group == "start":
            instance = str(uuid.uuid4())
            service.apply(spec(), instance, str(uuid.uuid4()), str(service.ctl("status")["revision"]))
            service.ready(instance)
        for seconds in (90, 240, 480):
            time.sleep(max(0, start+seconds-time.monotonic()))
            compare(f"t{seconds}", base, service.inventory())
        if group == "start":
            service.ctl("stop", instance)
            eventually("network stopped",lambda: service.view(instance),lambda v: v.get("state")=="stopped",timeout=240)
            compare("stopped",base,service.inventory())
            service.stop()
            from service import command
            result=command(service.installer,"reclaim","--all","--purge",check=False,timeout=240)
            print(f"standalone purge exit {result.returncode}",flush=True)
            compare("purged",base,service.inventory())
finally:
    compare("uninstall", pre, service.inventory())
