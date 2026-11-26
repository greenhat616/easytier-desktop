"""Sample two service start settings without opening WFP or starting a service."""
from contextlib import ExitStack
from pathlib import Path
import os
import tempfile
import threading
import time
import uuid
import winreg

from registry_writer import registry_audit
from service import Service
from product import foreign_runtime, spec
import foreign

def settings():
    values = []
    for name in ("IKEEXT", "BITS"):
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\" + name) as key:
            values.append(winreg.QueryValueEx(key, "Start")[0])
    return tuple(values)

service = Service()
case = os.environ["G2_COMPARISON"]
phase = "before install"
stop = threading.Event()
start = time.monotonic()

def watch():
    previous = None
    while not stop.is_set():
        value = settings()
        if value != previous:
            print(f"{case} t={time.monotonic()-start:.1f}s phase={phase} IKEEXT/BITS={value}", flush=True)
        previous = value
        stop.wait(0.5)

with registry_audit() as (read_events, writer_records):
    print(f"{case} initial IKEEXT/BITS: {settings()}", flush=True)
    watcher = threading.Thread(target=watch)
    watcher.start()
    try:
        with service.installed(), ExitStack() as stack:
            phase = "create sibling fixtures"
            instance = str(uuid.uuid4())
            sibling = stack.enter_context(foreign_runtime(service, instance))
            stack.enter_context(foreign.windows())
            image, _ = stack.enter_context(foreign.idle_process())
            phase = "baseline native inventory"
            service.inventory([image], [sibling])
            baseline = settings()
            end = time.monotonic() + 480
            print(f"{case} before launch interval: {baseline}", flush=True)
            read_events()
            if case == "started":
                phase = "apply network until ready"
                service.apply(spec(), instance, str(uuid.uuid4()), str(service.ctl("status")["revision"]))
                ready = service.ready(instance)
                read_events()
                print(f"{case} {ready['state']} epoch={ready['epoch']}", flush=True)
            phase = "matched observation interval"
            while time.monotonic() < end:
                time.sleep(min(5, max(0, end-time.monotonic())))
                read_events()
            phase = "second native inventory"
            service.inventory([image], [sibling])
            after = settings()
            read_events()
            print(f"{case} final IKEEXT/BITS: {baseline} -> {after}; BITS event count={len(writer_records)}", flush=True)
            phase = "fixture cleanup and uninstall"
            if after[1] != baseline[1]:
                assert writer_records, "BITS changed without a 4657 record"
                raise AssertionError(f"{case}: unpredicted BITS change {baseline[1]} -> {after[1]}")
    finally:
        stop.set()
        watcher.join()
        read_events()
