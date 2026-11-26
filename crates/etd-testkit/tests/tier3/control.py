"""Matched idle/start observations on fresh hosted runners."""
from service import Service
from product import spec
import os
import time
import uuid

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
finally:
    compare("uninstall", pre, service.inventory())
