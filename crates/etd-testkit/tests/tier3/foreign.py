"""Unrelated native objects whose lifetime spans the service crash tests."""

from contextlib import contextmanager, ExitStack
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import tempfile
import uuid

from inventory import command, output


@contextmanager
def idle_process():
    with tempfile.TemporaryDirectory(prefix="g2-foreign-") as directory:
        if os.name == "nt":
            source = Path(os.environ["SystemRoot"]) / "System32" / "ping.exe"
            args = ["-t", "127.0.0.1"]
        else:
            source = Path("/bin/sleep")
            args = ["1200"]
        image = Path(directory).resolve() / ("etd-g2-foreign" + source.suffix)
        shutil.copy2(source, image)
        proc = subprocess.Popen([str(image), *args], stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            yield image, ("process", str(proc.pid))
            assert proc.poll() is None, "foreign process exited during recovery"
        finally:
            if proc.poll() is None:
                proc.terminate()
            proc.wait(timeout=10)


@contextmanager
def macos():
    with ExitStack() as stack:
        bridge = output("/sbin/ifconfig", "bridge", "create").strip()
        assert bridge.startswith("bridge") and bridge[6:].isdigit()
        stack.callback(command, "/sbin/ifconfig", bridge, "destroy")
        command("/sbin/ifconfig", bridge, "inet", "198.51.100.241/28", "up")
        resolver = Path("/etc/resolver")
        if not resolver.exists():
            resolver.mkdir()
            stack.callback(resolver.rmdir)
        rule = resolver / "etd-g2-foreign.invalid"
        with rule.open("xb") as stream:
            stream.write(b"nameserver 192.0.2.53\n")
        stack.callback(rule.unlink)
        # Sibling anchor, independently owned, with an inert counting rule.
        anchor = "com.apple/easytier-desk-g2-foreign"
        assert not output("/sbin/pfctl", "-a", anchor, "-sr").strip()
        command("/sbin/pfctl", "-a", anchor, "-f", "-",
                input='pass out on lo0 inet to 192.0.2.241 label "etd-g2-foreign"\n')
        stack.callback(command, "/sbin/pfctl", "-a", anchor, "-F", "rules")
        label = "easytier-desk-g2-foreign"
        file = Path("/Library/LaunchDaemons") / (label + ".plist")
        with file.open("xb") as stream:
            plistlib.dump({"Label": label, "ProgramArguments": ["/usr/bin/true"]}, stream)
        stack.callback(file.unlink)
        command("launchctl", "bootstrap", "system", file)
        stack.callback(command, "launchctl", "bootout", "system/" + label)
        yield {("interface", bridge), ("route", bridge), ("resolver", str(rule)),
               ("firewall", "etd-g2-foreign"), ("service", file.name)}
        command("launchctl", "print", "system/" + label)


@contextmanager
def windows():
    import winreg
    with ExitStack() as stack:
        tag = str(uuid.uuid4())
        name = "easytier-desk-g2-" + tag[:8]
        # A disabled, never-started service with a known system image.
        command("sc.exe", "create", name, "start=", "disabled", "binPath=",
                str(Path(os.environ["SystemRoot"]) / "System32" / "where.exe"))
        stack.callback(command, "sc.exe", "delete", name)
        reg = r"SOFTWARE\EasyTier\G2-" + tag
        key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, reg, access=winreg.KEY_WRITE)
        with key:
            winreg.SetValueEx(key, "Foreign", 0, winreg.REG_BINARY, tag.encode("ascii"))
        stack.callback(winreg.DeleteKey, winreg.HKEY_LOCAL_MACHINE, reg)
        def ps(script):
            return output("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                          "$ErrorActionPreference='Stop'; " + script).strip()
        ps(f"New-NetFirewallRule -Name '{name}' -DisplayName 'EasyTier {name}' "
           "-Group EasyTier -Direction Inbound -Action Block -Enabled False | Out-Null")
        stack.callback(ps, f"Remove-NetFirewallRule -Name '{name}'")
        rule = ps("Add-DnsClientNrptRule -Namespace '.g2-foreign.invalid' "
                  "-NameServers '192.0.2.53' -PassThru | Select-Object -ExpandProperty Name")
        assert uuid.UUID(rule.strip("{}"))
        stack.callback(ps, f"Remove-DnsClientNrptRule -Name '{rule}' -Force")
        yield {("service", name), ("registry", "HKLM\\" + reg + "\\Foreign"),
               ("resolver", rule), ("firewall", "policy/" + name)}
