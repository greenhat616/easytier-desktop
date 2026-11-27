"""ES2N gate (doc#17): the call stack of the first matching registry access
per process in a Process Monitor log, each frame named by its module and
the offset into it (no symbols). Used to attribute HKCU reads of etd-host to Windows or to
our code (topic#51 msg#2045).

usage: es2n-stacks.py <log.pml> <process name> <path substring> [more substrings]
"""
import sys

from procmon_parser import ProcmonLogsReader


def module_of(address, modules):
    for m in modules:
        base = m.base_address
        if base <= address < base + m.size:
            name = m.path.rsplit('\\', 1)[-1]
            return f'{name}+0x{address - base:x}'
    return 'kernel' if address >= 0xFFFF800000000000 else f'?+0x{address:x}'


def main():
    pml, process, needles = sys.argv[1], sys.argv[2].lower(), [n.lower() for n in sys.argv[3:]]
    seen = set()
    with open(pml, 'rb') as f:
        for event in ProcmonLogsReader(f):
            proc = event.process
            if proc.process_name.lower() != process:
                continue
            path = (event.path or '').lower()
            if not any(n in path for n in needles):
                continue
            key = (proc.pid, path)
            if key in seen:
                continue
            seen.add(key)
            frames = [module_of(a, proc.modules) for a in (event.stacktrace or [])]
            ours = [f for f in frames if f.lower().startswith('etd-host.exe+')]
            print(f'pid {proc.pid} {proc.image_path} ({proc.user}, {proc.integrity}): {event.operation} {event.path}')
            print(f'  etd-host frames: {len(ours)} of {len(frames)}')
            for i, frame in enumerate(frames):
                print(f'  {i:3} {frame}')


if __name__ == '__main__':
    main()
