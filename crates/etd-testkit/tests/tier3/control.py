"""Matched idle/start observations on fresh hosted runners."""
from service import Service
from product import spec
import os
import time
import uuid
from itertools import combinations
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
            left, right = base.fields.get(key,{}), current.fields.get(key,{})
            labels = set().union(*(r.keys() for r in [*left.values(), *right.values()]))
            def tuples(source, fields):
                names = sorted(fields)
                return Counter(tuple(rule.get(f) for f in names) for rule in source.values())
            changing = set()
            for field in sorted(labels):
                left_field, right_field = tuples(left,{field}), tuples(right,{field})
                removed, added = (left_field-right_field).total(),(right_field-left_field).total()
                if removed or added:
                    changing.add(field)
                    print(f"{group} {stage} {key} leaf {field}: -{removed}/+{added}",flush=True)
            def residual(drop):
                a,b=tuples(left,labels-set(drop)),tuples(right,labels-set(drop))
                return (a-b).total(),(b-a).total()
            print(f"{group} {stage} {key} omit all changed leaves {sorted(changing)} -> {residual(changing)}",flush=True)
            volatile = {f for f in labels if f.split("/")[0] in ("rawContext","providerContextKey","reserved","providerData","effectiveWeight","weight","displayData")}
            best = None
            for n in range(min(4,len(volatile))+1):
                for drop in combinations(sorted(volatile),n):
                    lost,gained=residual(drop)
                    score=(min(lost,gained),len(drop),lost+gained)
                    if best is None or score<best[0]:
                        best=(score,drop,(lost,gained))
                    if min(lost,gained)==0:
                        break
                if best[0][0]==0:
                    break
            drop=best[1]
            print(f"{group} {stage} {key} best metadata omission {drop} unmatched {best[2]}",flush=True)
            if min(best[2])==0 and best[2]!=(0,0):
                a,b=tuples(left,labels-set(drop)),tuples(right,labels-set(drop))
                names=sorted(labels-set(drop))
                for source,full,unmatched,verb in [(left,prior,a-b,"removed"),(right,latest,b-a,"added")]:
                    templates=Counter()
                    for fid,rule in source.items():
                        fp=tuple(rule.get(f) for f in names)
                        if unmatched[fp]:
                            templates[str(full[fid][1])] += 1
                            unmatched[fp]-=1
                    print(f"{group} {stage} {key} {verb} policy templates {sorted(templates.items())}",flush=True)
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
        for seconds in (90, 180):
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
