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
        if kind == "registry" and key.rsplit(chr(92),1)[-1] in ("Dhcpv6Iaid","Dhcpv6State"):
            typ,val = new or old
            guid = key.split(chr(92))[-2].lower()
            nic = next((value for (cls,_),value in current.rows.items()
                        if cls=="interface" and str(value.get("guid","")).lower()==guid),None)
            if isinstance(val,int): value=str(val)
            elif isinstance(val,list):
                value=f"bytes={len(val)} nonzero={sum(x!=0 for x in val)}"
            else: value=f"length={len(str(val))}"
            detail += f" type={typ} value={value}"
            if nic:
                mac=(nic.get("mac") or "").replace("-","").replace(":","")
                detail += f" adapter index={nic['index']} GUID matches"
                if isinstance(val,int) and len(mac)==12:
                    detail += f" iaid hex={val&0xffffffff:08x} low24=MAC-low24:{(val&0xffffff)==int(mac[-6:],16)} index-high8:{(val>>24)==nic['index']}"
        elif kind == "process":
            n=new or old
            detail+=f" image={Path(n[0]).name} created={n[1]}"
        elif kind == "firewall" and key.startswith("wfp-group/"):
            continue
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
        for seconds in (90, 160):
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
            for line in (result.stdout+"\n"+result.stderr).splitlines():
                if line.strip().startswith(("Reclaim:", "left in place:","etd-host:")):
                    print(f"standalone purge result {line.strip()[:450]}",flush=True)
            compare("purged",base,service.inventory())
finally:
    compare("uninstall", pre, service.inventory())
