"""Unrelated native objects whose lifetime spans the service crash tests."""

from contextlib import contextmanager, ExitStack
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tempfile
import uuid

from inventory import command, output


@contextmanager
def idle_process():
    with tempfile.TemporaryDirectory(prefix="g2-foreign-") as directory:
        child_env = os.environ.copy()
        if sys.platform == "linux":
            # Some runner images ship a multi-call /bin/sleep whose copied
            # image exits immediately under a different program name.
            source = Path(sys.executable).resolve()
            child_env["PYTHONHOME"] = sys.base_prefix
            args = ["-S", "-c", "import time; time.sleep(1200)"]
        elif os.name == "nt":
            source = Path(os.environ["SystemRoot"]) / "System32" / "ping.exe"
            args = ["-t", "127.0.0.1"]
        else:
            source = Path("/bin/sleep")
            args = ["1200"]
        image = Path(directory).resolve() / ("etd-g2-foreign" + source.suffix)
        shutil.copy2(source, image)
        proc = subprocess.Popen([str(image), *args], stdin=subprocess.DEVNULL, env=child_env,
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
               ("firewall", "pf/anchor/" + anchor), ("service", file.name)}
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
        root = r"SOFTWARE\EasyTier"
        try:
            winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root).Close()
        except FileNotFoundError:
            winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, root).Close()

            def remove_fixture_root():
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, root) as key:
                    assert winreg.QueryInfoKey(key)[:2] == (0, 0), "fixture registry root gained unexpected contents"
                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, root)

            stack.callback(remove_fixture_root)
        reg = root + "\\G2-" + tag
        key = winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, reg, access=winreg.KEY_WRITE)
        stack.callback(winreg.DeleteKey, winreg.HKEY_LOCAL_MACHINE, reg)
        with key:
            winreg.SetValueEx(key, "Foreign", 0, winreg.REG_BINARY, tag.encode("ascii"))
        empty = reg + "\\Empty"
        winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, empty).Close()
        stack.callback(winreg.DeleteKey, winreg.HKEY_LOCAL_MACHINE, empty)
        def ps(script):
            return output("powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
                          "$ErrorActionPreference='Stop'; " + script).strip()
        nic = "etd-" + tag[:8]
        import ipaddress
        local = ipaddress.IPv4Address(ps(
            "Start-Service iphlpsvc; "
            "$route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' "
            "| Sort-Object RouteMetric,InterfaceIndex | Select-Object -First 1; "
            "Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $route.InterfaceIndex "
            "| Where-Object { $_.AddressState -eq 'Preferred' -and !$_.SkipAsSource } "
            "| Select-Object -First 1 -ExpandProperty IPAddress"
        ))
        if local.is_loopback or local.is_unspecified:
            raise ValueError("no configured IPv4 endpoint for the foreign interface")
        command("netsh.exe", "interface", "ipv6", "add", "v6v4tunnel",
                "interface=" + nic, f"localaddress={local}", "remoteaddress=192.0.2.253")
        stack.callback(command, "netsh.exe", "interface", "ipv6", "delete", "interface", nic)
        # Use the loopback link, never the runner's management interface.
        index = int(ps("(Get-NetIPAddress -IPAddress 127.0.0.1).InterfaceIndex"))
        alias = ps(f"(Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex {index}).InterfaceAlias")
        prefix = "198.51.100.241/32"
        route = f"-InterfaceIndex {index} -DestinationPrefix '{prefix}' -NextHop 0.0.0.0 -PolicyStore ActiveStore"
        ps(f"New-NetRoute {route} | Out-Null")
        stack.callback(ps, f"Remove-NetRoute {route} -Confirm:$false")
        ps(f"New-NetFirewallRule -Name '{name}' -DisplayName 'EasyTier {name}' "
           "-Group EasyTier -Direction Inbound -Action Block -Enabled False | Out-Null")
        stack.callback(ps, f"Remove-NetFirewallRule -Name '{name}'")
        rule = ps("Add-DnsClientNrptRule -Namespace '.g2-foreign.invalid' "
                  "-NameServers '192.0.2.53' -PassThru | Select-Object -ExpandProperty Name")
        assert uuid.UUID(rule.strip("{}"))
        stack.callback(ps, f"Remove-DnsClientNrptRule -Name '{rule}' -Force")
        yield {("service", name), ("interface", nic), ("route", alias), ("registry", "HKLM\\" + reg + "\\Foreign"),
               ("registry", "key/HKLM\\" + empty), ("resolver", rule), ("firewall", "policy/" + name)}
