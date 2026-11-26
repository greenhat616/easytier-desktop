"""Disposable CI audit of writes to IKEEXT Start."""
from contextlib import contextmanager, ExitStack
import csv
import datetime
from pathlib import Path
import re
import tempfile
from xml.etree import ElementTree
import winreg
import psutil
import pywintypes
import win32api
import win32con
import win32evtlog as events
import win32security as security
from service import command

KEY = r"MACHINE\SYSTEM\CurrentControlSet\Services\IKEEXT"
INFO = security.SACL_SECURITY_INFORMATION
REG = security.SE_REGISTRY_KEY
UTC = datetime.timezone.utc

def descriptor():
    return security.GetNamedSecurityInfo(KEY, REG, INFO)

def acl_text():
    return security.ConvertSecurityDescriptorToStringSecurityDescriptor(descriptor(), 1, INFO)

def set_sacl(value):
    security.SetNamedSecurityInfo(KEY, REG, INFO, None, None, None, value)

def registry_writes(start, seen):
    query = ("*[System[(EventID=4657) and TimeCreated[@SystemTime >= '" + start + "']] "
             "and EventData[Data[@Name='ObjectValueName']='Start']]")
    handle = events.EvtQuery("Security", events.EvtQueryChannelPath | events.EvtQueryReverseDirection, query)
    while True:
        try:
            batch = events.EvtNext(handle, 16)
        except pywintypes.error as exc:
            if exc.winerror == 259:  # ERROR_NO_MORE_ITEMS
                break
            raise
        if not batch:
            break
        for event in batch:
            xml = ElementTree.fromstring(events.EvtRender(event, events.EvtRenderEventXml))
            data = {n.attrib["Name"]: n.text for n in xml.findall("./{*}EventData/{*}Data")}
            if not re.fullmatch(r"\\REGISTRY\\MACHINE\\SYSTEM\\(?:ControlSet\d+|CurrentControlSet)\\Services\\IKEEXT",
                                data.get("ObjectName", ""), re.I):
                continue
            identifier = xml.findtext("./{*}System/{*}EventRecordID")
            if identifier in seen:
                continue
            seen.add(identifier)
            stamp = xml.find("./{*}System/{*}TimeCreated").attrib["SystemTime"]
            when = datetime.datetime.fromisoformat(stamp).timestamp()
            pid = int(data["ProcessId"], 0)
            image = data["ProcessName"]
            services = []
            try:
                process = psutil.Process(pid)
                if (process.create_time() <= when and Path(process.exe()).name.casefold() == Path(image).name.casefold()):
                    rows = command("tasklist.exe", "/svc", "/fi", f"PID eq {pid}", "/fo", "csv", "/nh")
                    services = [row[2] for row in csv.reader(rows.stdout.splitlines()) if len(row) == 3 and row[1] == str(pid)]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            print(f"Security 4657 record={identifier} UTC={stamp} key={data['ObjectName']} value=Start "
                  f"writer={image} pid={pid} old={data.get('OldValue')} new={data.get('NewValue')} "
                  f"services={services}", flush=True)

@contextmanager
def registry_audit():
    token = security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY | win32con.TOKEN_ADJUST_PRIVILEGES)
    privilege = security.LookupPrivilegeValue(None, "SeSecurityPrivilege")
    prior = security.AdjustTokenPrivileges(token, False, [(privilege, win32con.SE_PRIVILEGE_ENABLED)])
    seen = set()
    with ExitStack() as cleanup:
        cleanup.callback(security.AdjustTokenPrivileges, token, False, prior)
        old_acl = descriptor().GetSecurityDescriptorSacl()
        old_sddl = acl_text()
        prior_policy = command("auditpol.exe", "/get", "/subcategory:Registry", "/r").stdout
        directory = cleanup.enter_context(tempfile.TemporaryDirectory())
        backup = "/file:" + str(Path(directory) / "policy.csv")
        command("auditpol.exe", "/backup", backup)
        def restore_policy():
            command("auditpol.exe", "/restore", backup)
            assert command("auditpol.exe", "/get", "/subcategory:Registry", "/r").stdout == prior_policy
            print("restored Registry audit policy", flush=True)
        cleanup.callback(restore_policy)
        command("auditpol.exe", "/set", "/subcategory:Registry", "/success:enable")
        acl = descriptor().GetSecurityDescriptorSacl()
        if acl is None:
            acl = security.ACL()
        acl.AddAuditAccessAceEx(security.ACL_REVISION_DS, 0, winreg.KEY_SET_VALUE,
                                security.ConvertStringSidToSid("S-1-1-0"), 1, 0)
        def restore_acl():
            set_sacl(old_acl)
            assert acl_text() == old_sddl
            print("restored original IKEEXT SACL", flush=True)
        cleanup.callback(restore_acl)
        set_sacl(acl)
        start = datetime.datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        def read():
            registry_writes(start, seen)
        try:
            yield read, seen
        finally:
            read()
