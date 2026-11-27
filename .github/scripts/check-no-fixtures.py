"""Fail if any file under the given folders carries the CI test-fixtures marker.

    python check-no-fixtures.py <folder> [<folder> ...]

Every binary built with etd-sysfx-os's `ci-test-fixtures` feature (the CI
upgrade fault hooks) embeds the marker; release packages must carry none.
`cargo xtask dist` already refuses such an etd-host. This checks the built
packages' extracted contents independently, every file, and requires that
each folder holds an etd-host at all (so an empty extraction cannot pass).
"""

from pathlib import Path
import sys

MARKER = b"ETD-CI-TEST-" + b"FIXTURES-BUILD"


def main(folders):
    failed = False
    for folder in map(Path, folders):
        files = [path for path in folder.rglob("*") if path.is_file() and not path.is_symlink()]
        hosts = [path for path in files if path.name in ("etd-host", "etd-host.exe")]
        if not hosts:
            print(f"{folder}: no etd-host in the extracted package")
            failed = True
        for path in files:
            if MARKER in path.read_bytes():
                print(f"{path}: carries the CI test-fixtures marker")
                failed = True
        print(f"{folder}: {len(files)} files checked, {len(hosts)} etd-host")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
