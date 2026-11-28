"""Fail if a shipped Windows binary imports a C runtime a clean machine lacks.

    python check-pe-imports.py <folder> [<folder> ...]

Every .exe and .dll under the folders is read (PE32 or PE32+) and its import
table listed. The VC++ runtime (vcruntime*, msvcp*, concrt*, vccorlib*), the
debug runtimes, and the UCRT API sets (api-ms-win-crt-*, which a statically
linked C runtime never imports) are refused: the packages ship none of them,
so a machine without the Redistributable could not start the binary. The
Windows system msvcrt.dll is not the VC++ runtime and is allowed. Each folder
must hold an etd-host.exe, so an empty extraction cannot pass. Drivers
(.sys) are not user-mode imports and are skipped.
"""

from pathlib import Path
import re
import struct
import sys

REFUSED = re.compile(r"^(vcruntime\d+(_\d+)?d?|msvcp\d+(_\w+)?d?|concrt\d+d?|vccorlib\d+d?|ucrtbased"
                     r"|api-ms-win-crt-[\w-]+)\.dll$")


def imports(path):
    """The DLL names in the image's import table (what the loader resolves
    at start)."""
    data = path.read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError(f"{path} is not a PE image")
    count, = struct.unpack_from("<H", data, pe + 6)
    optional_size, = struct.unpack_from("<H", data, pe + 20)
    optional = pe + 24
    magic, = struct.unpack_from("<H", data, optional)
    directories = optional + {0x20B: 112, 0x10B: 96}[magic]
    import_rva, _ = struct.unpack_from("<II", data, directories + 8)
    if import_rva == 0:
        return []
    sections = [struct.unpack_from("<IIII", data, optional + optional_size + 40 * i + 8)
                for i in range(count)]

    def offset(rva):
        for size, address, raw_size, raw in sections:
            if address <= rva < address + max(size, raw_size):
                return rva - address + raw
        raise ValueError(f"{path}: RVA {rva:#x} outside every section")

    names, at = [], offset(import_rva)
    while any(descriptor := struct.unpack_from("<IIIII", data, at)):
        start = offset(descriptor[3])
        names.append(data[start:data.index(b"\0", start)].decode("ascii").lower())
        at += 20
    return names


def main(folders):
    failed = False
    for folder in map(Path, folders):
        images = sorted(path for path in folder.rglob("*")
                        if path.is_file() and path.suffix.lower() in (".exe", ".dll"))
        if not any(path.name.lower() == "etd-host.exe" for path in images):
            print(f"{folder}: no etd-host.exe")
            failed = True
        for path in images:
            names = imports(path)
            refused = sorted({name for name in names if REFUSED.match(name)})
            print(f"{path.relative_to(folder)}: {', '.join(dict.fromkeys(names))}")
            if refused:
                print(f"  refused: {', '.join(refused)} (a C runtime the package does not ship)")
                failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
