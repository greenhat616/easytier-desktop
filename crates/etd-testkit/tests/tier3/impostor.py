"""Test-owned impostor processes for the takeover regressions (doc#7).

Each one runs as its own process, takes one native object the installed
product must never use or touch, and publishes what reached it as JSON in
--status. It releases the object once --stop exists or the test process
(--parent-pid) is gone. Only takeover.py starts it, on a disposable hosted
runner. Standard library plus psutil.
"""

import argparse
import errno
import json
import os
from pathlib import Path
import select
import socket
import sqlite3
import subprocess
import sys
import time

FENCE_KINDS = {"linux.fence_rule", "macos.fence_rule", "win.fence_filter"}
IN_USE = {errno.EADDRINUSE, errno.EACCES, 10013, 10048}


class Reporter:
    def __init__(self, path):
        self.path = Path(path)
        self.body = {"pid": os.getpid()}

    def publish(self, **fields):
        self.body.update(fields)
        partial = self.path.with_name(self.path.name + ".partial")
        partial.write_text(json.dumps(self.body), encoding="utf-8")
        os.replace(partial, self.path)


def alive(pid, born):
    import psutil
    try:
        return psutil.Process(pid).create_time() == born
    except psutil.NoSuchProcess:
        return False


class Stop:
    """True once the stop file exists or the parent test process exited."""

    def __init__(self, path, parent, born):
        self.path, self.parent, self.born = Path(path), parent, born
        self.checked = 0.0

    def __call__(self):
        if self.path.exists():
            return True
        now = time.monotonic()
        if now - self.checked >= 0.5:
            self.checked = now
            if not alive(self.parent, self.born):
                return True
        return False


def bind(port, reuse):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        if reuse:
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", port))
        server.listen(16)
        return server
    except OSError:
        server.close()
        raise


def peer_pid(address, port):
    import psutil
    try:
        for c in psutil.net_connections(kind="tcp"):
            if c.laddr and c.raddr and tuple(c.laddr) == tuple(address) and c.raddr.port == port:
                return c.pid
    except (psutil.Error, OSError):
        pass
    return None


def serve(server, port, report, stop):
    # Accept and read only; never answer. Every connection and every byte
    # that reaches the impostor is recorded.
    server.setblocking(False)
    peers, open_peers = [], {}
    report.publish(state="bound", port=port, bound_at=time.time(), connections=0, bytes=0, peers=peers)

    def pump(timeout):
        ready, _, _ = select.select([server, *open_peers], [], [], timeout)
        for sock in ready:
            if sock is server:
                try:
                    conn, address = server.accept()
                except BlockingIOError:
                    continue
                conn.setblocking(False)
                open_peers[conn] = len(peers)
                peers.append({"address": list(address), "pid": peer_pid(address, port),
                              "at": time.time(), "bytes": 0})
            else:
                try:
                    data = sock.recv(65536)
                except BlockingIOError:
                    continue
                except OSError:
                    data = b""
                if data:
                    peers[open_peers[sock]]["bytes"] += len(data)
                else:
                    del open_peers[sock]
                    sock.close()
            report.publish(connections=len(peers), bytes=sum(p["bytes"] for p in peers), peers=peers)
        return bool(ready)

    while not stop():
        pump(0.2)
    # Count whatever arrived since the last round, queued or unread.
    while pump(0):
        pass
    for sock in open_peers:
        sock.close()
    server.close()
    report.publish(state="released", released_at=time.time())


def squat(args, report, stop):
    """Bind the port the moment its holder lets go."""
    deadline = time.monotonic() + args.retry_for
    attempts = 0
    while not stop():
        # Windows SO_REUSEADDR could share a live socket: only use it once
        # the previous holder has exited, to pass a lingering TIME_WAIT.
        released = args.holder_pid is None or not alive(args.holder_pid, args.holder_born)
        reuse = os.name != "nt" or released
        try:
            server = bind(args.port, reuse)
            break
        except OSError as error:
            attempts += 1
            if error.errno not in IN_USE:
                report.publish(state="error", error=repr(error))
                return
            if attempts == 1:
                report.publish(state="waiting", error=error.errno, holder_alive=not released)
            if time.monotonic() >= deadline:
                report.publish(state="timeout", attempts=attempts, error=error.errno)
                return
            time.sleep(0.001)
    else:
        return
    report.publish(attempts=attempts, reuse=reuse)
    serve(server, args.port, report, stop)


def race(args, report, stop):
    """Watch the ledger for the next generation's fence and take its port
    before the kernel binds it. One bind attempt: a failure means the
    kernel already holds the port (the race was lost)."""
    db = sqlite3.connect(Path(args.ledger).as_uri() + "?mode=ro", uri=True)
    needle = args.instance.encode()
    deadline = time.monotonic() + args.timeout
    report.publish(state="watching", after=args.after)
    while time.monotonic() < deadline and not stop():
        try:
            rows = db.execute("SELECT payload FROM effects WHERE instr(payload, ?) > 0 AND instr(payload, ?) > 0",
                              (needle, b'"fence"')).fetchall()
        except sqlite3.OperationalError:
            time.sleep(0.001)
            continue
        for (payload,) in rows:
            record = json.loads(payload)
            scope = record.get("scope")
            generation = scope.get("instance") if isinstance(scope, dict) else None
            if (record.get("kind") in FENCE_KINDS and generation and generation.get("instance") == args.instance
                    and generation.get("epoch", 0) > args.after):
                port, epoch = record["key"]["port"], generation["epoch"]
                seen = time.time()
                try:
                    server = bind(port, reuse=False)
                except OSError as error:
                    report.publish(state="lost", port=port, epoch=epoch, error=error.errno,
                                   record_state=record.get("state"), seen_at=seen)
                    return
                db.close()
                report.publish(epoch=epoch, record_state=record.get("state"), seen_at=seen)
                serve(server, port, report, stop)
                return
        time.sleep(0.0005)
    report.publish(state="timeout")


UTUN_CONTROL = b"com.apple.net.utun_control"
CTLIOCGINFO = 0xC0644E03  # _IOWR('N', 3, struct ctl_info)
UTUN_OPT_IFNAME = 2


def utun(args, report, stop):
    """Hold utun<unit> open with a point-to-point address (macOS)."""
    import fcntl
    import struct
    deadline = time.monotonic() + args.retry_for
    attempts = 0
    while not stop():
        control = socket.socket(socket.PF_SYSTEM, socket.SOCK_DGRAM, socket.SYSPROTO_CONTROL)
        try:
            info = fcntl.ioctl(control.fileno(), CTLIOCGINFO, struct.pack("I96s", 0, UTUN_CONTROL))
            control_id = struct.unpack("I96s", info)[0]
            control.connect((control_id, args.unit + 1))
            break
        except OSError as error:
            control.close()
            attempts += 1
            if error.errno != errno.EBUSY:
                report.publish(state="error", error=repr(error))
                return
            if attempts == 1:
                report.publish(state="waiting", error=error.errno)
            if time.monotonic() >= deadline:
                report.publish(state="timeout", attempts=attempts)
                return
            time.sleep(0.002)
    else:
        return

    def name():
        raw = control.getsockopt(socket.SYSPROTO_CONTROL, UTUN_OPT_IFNAME, 16)
        return raw.split(b"\0", 1)[0].decode()

    held = name()
    subprocess.run(["/sbin/ifconfig", held, "inet", args.address, args.peer, "up"], check=True,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    report.publish(state="held", name=held, index=socket.if_nametoindex(held), attempts=attempts,
                   held_at=time.time())
    while not stop():
        time.sleep(0.2)
    report.publish(state="released", name_at_release=name(), index_at_release=socket.if_nametoindex(held))
    control.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["squat", "race", "utun"])
    parser.add_argument("--status", required=True)
    parser.add_argument("--stop", required=True)
    parser.add_argument("--parent-pid", type=int, required=True)
    parser.add_argument("--parent-born", type=float, required=True)
    parser.add_argument("--port", type=int)
    parser.add_argument("--holder-pid", type=int)
    parser.add_argument("--holder-born", type=float)
    parser.add_argument("--retry-for", type=float, default=30)
    parser.add_argument("--ledger")
    parser.add_argument("--instance")
    parser.add_argument("--after", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=240)
    parser.add_argument("--unit", type=int)
    parser.add_argument("--address")
    parser.add_argument("--peer")
    args = parser.parse_args()
    report = Reporter(args.status)
    {"squat": squat, "race": race, "utun": utun}[args.mode](args, report, Stop(args.stop, args.parent_pid, args.parent_born))


if __name__ == "__main__":
    sys.exit(main())
