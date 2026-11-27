"""Loaded-driver paths without SeDebugPrivilege (PK3, msg#1764).

Windows Installer custom actions run without SeDebugPrivilege (msiserver's
RequiredPrivileges omit it), so etd-host reads loaded-driver paths from
NtQuerySystemInformation(SystemModuleInformation) there. This probe removes
SeDebugPrivilege from its own token, shows that it can no longer be enabled
and that EnumDeviceDrivers hides the bases, then reads the module list with
the same layout and rules as driver_refs.rs. It prints one JSON object.
"""

import ctypes
from ctypes import wintypes
import json
import sys
import winreg

advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
ntdll = ctypes.WinDLL("ntdll")
psapi = ctypes.WinDLL("psapi", use_last_error=True)

TOKEN_ADJUST_PRIVILEGES, TOKEN_QUERY = 0x20, 0x8
SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_REMOVED = 0x2, 0x4
ERROR_NOT_ALL_ASSIGNED = 1300
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
POINTER = ctypes.sizeof(ctypes.c_void_p)
HEADER, NAME, NAME_LEN = POINTER, 3 * POINTER + 16, 256
ENTRY = NAME + NAME_LEN


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Luid", LUID), ("Attributes", wintypes.DWORD)]


# Full signatures: ctypes' default int would truncate 64-bit handles such as
# GetCurrentProcess()'s pseudo-handle.
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.GetCurrentProcess.argtypes = []
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
advapi32.OpenProcessToken.restype = wintypes.BOOL
advapi32.LookupPrivilegeValueW.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(LUID)]
advapi32.LookupPrivilegeValueW.restype = wintypes.BOOL
advapi32.AdjustTokenPrivileges.argtypes = [wintypes.HANDLE, wintypes.BOOL, ctypes.POINTER(TOKEN_PRIVILEGES),
                                           wintypes.DWORD, ctypes.c_void_p, ctypes.c_void_p]
advapi32.AdjustTokenPrivileges.restype = wintypes.BOOL
psapi.EnumDeviceDrivers.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
psapi.EnumDeviceDrivers.restype = wintypes.BOOL
ntdll.NtQuerySystemInformation.argtypes = [ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong,
                                           ctypes.POINTER(ctypes.c_ulong)]
ntdll.NtQuerySystemInformation.restype = ctypes.c_long


def set_debug(attributes):
    """Apply `attributes` to SeDebugPrivilege on this process token; the
    Win32 error AdjustTokenPrivileges leaves (0 or ERROR_NOT_ALL_ASSIGNED)."""
    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                     ctypes.byref(token)):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, "SeDebugPrivilege", ctypes.byref(luid)):
            raise ctypes.WinError(ctypes.get_last_error())
        state = TOKEN_PRIVILEGES(1, luid, attributes)
        ctypes.set_last_error(0)
        if not advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(state), 0, None, None):
            raise ctypes.WinError(ctypes.get_last_error())
        return ctypes.get_last_error()
    finally:
        kernel32.CloseHandle(token)


def driver_bases():
    bases = (ctypes.c_void_p * 4096)()
    needed = wintypes.DWORD()
    if not psapi.EnumDeviceDrivers(bases, ctypes.sizeof(bases), ctypes.byref(needed)):
        raise ctypes.WinError(ctypes.get_last_error())
    return [bases[i] for i in range(needed.value // POINTER)]


def module_list():
    length = 64 * 1024
    while True:
        buffer = ctypes.create_string_buffer(length)
        written = wintypes.ULONG()
        status = ntdll.NtQuerySystemInformation(11, buffer, length, ctypes.byref(written)) & 0xFFFFFFFF
        if status == STATUS_INFO_LENGTH_MISMATCH:
            length = written.value + 64 * 1024
            continue
        if status:
            raise OSError(f"NtQuerySystemInformation(SystemModuleInformation): NTSTATUS {status:#010x}")
        raw = buffer.raw[:written.value]
        break
    count = int.from_bytes(raw[:4], "little")
    entries, problems = [], []
    for index in range(count):
        entry = raw[HEADER + index * ENTRY:HEADER + (index + 1) * ENTRY]
        if len(entry) < ENTRY:
            problems.append(f"entry {index}: short buffer")
            break
        name = entry[NAME:]
        offset = int.from_bytes(entry[NAME - 2:NAME], "little")
        end = name.find(b"\0")
        if end <= 0:
            problems.append(f"entry {index}: {'unterminated' if end < 0 else 'empty'} path")
            continue
        if end >= NAME_LEN - 1:
            problems.append(f"entry {index}: path may be truncated")
        if offset >= end or (offset and name[offset - 1:offset] != b"\\"):
            problems.append(f"entry {index}: file name offset {offset} inconsistent")
        path = name[:end].decode("mbcs", errors="replace")
        rest = path[4:] if path.startswith("\\??\\") else path
        if "?" in rest or "�" in path:
            problems.append(f"entry {index}: not representable: {path}")
        entries.append(path)
    return count, entries, problems


def build():
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
    with key:
        return f"{winreg.QueryValueEx(key, 'CurrentBuild')[0]}.{winreg.QueryValueEx(key, 'UBR')[0]}", \
            winreg.QueryValueEx(key, "DisplayVersion")[0]


def main():
    removed = set_debug(SE_PRIVILEGE_REMOVED)
    enable = set_debug(SE_PRIVILEGE_ENABLED)
    bases = driver_bases()
    count, entries, problems = module_list()
    number, display = build()
    print(json.dumps({
        "build": number, "display_version": display,
        "debug_privilege_removed": removed == 0,
        "debug_privilege_enable_refused": enable == ERROR_NOT_ALL_ASSIGNED,
        "enum_count": len(bases), "enum_null_bases": sum(1 for base in bases if not base),
        "module_count": count, "modules": entries, "problems": problems,
    }))


if __name__ == "__main__":
    assert sys.platform == "win32"
    main()
