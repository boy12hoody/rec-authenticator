#!/usr/bin/env python3
"""Fake AERA host: drives the host-built plugin over fd 4 and checks the
protocol rules recovery enforces (generic_plugin_scene.cpp, session.cpp)."""
import base64
import hashlib
import hmac
import os
import select
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from make_migration import migration, otp  # noqa: E402

FMT = "<6I96s1024s"
SIZE = struct.calcsize(FMT)
MAGIC, API = 0x41325049, 2
HELLO, BEGIN, BUTTON, COMMIT, STATUS, OPERATION, CLOSE, SECTION, METRIC, UPDATE, BACK = range(1, 12)
HELLO_ACK, ACTION, LIFECYCLE = 64, 65, 66
DISABLED = 4
ROW_CODE = 1000
ROW_NTP = 10


class FakeNtp:
    """SNTP server on 127.0.0.1 whose clock runs `offset` seconds ahead."""

    def __init__(self):
        self.offset = 0.0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    @staticmethod
    def stamp(t):
        return struct.pack(">II", int(t) + 2208988800, int((t % 1) * 2**32))

    def serve(self):
        while True:
            req, addr = self.sock.recvfrom(512)
            assert len(req) == 48 and req[0] == 0x23, req
            now = self.stamp(time.time() + self.offset)
            self.sock.sendto(bytes([0x24, 1]) + bytes(22) + req[40:48] + now + now, addr)


NTP = FakeNtp()


class Host:
    def __init__(self, exe, data_dir, ntp_port=None):
        try:
            self.sock, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        except OSError:  # macOS has no AF_UNIX SEQPACKET; DGRAM keeps boundaries too
            self.sock, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
            # Darwin fails sends with ENOBUFS instead of blocking; give it room.
            for s in (self.sock, child):
                s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 << 20)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 << 20)
        child_fd = child.fileno()

        def to_fd4():
            os.dup2(child_fd, 4)
            os.set_inheritable(4, True)

        env = dict(os.environ, AERA_AUTH_DIR=data_dir, AERA_NTP_TEST_PORT=str(ntp_port or NTP.port))
        self.proc = subprocess.Popen([exe, "--aera-host-api=2"], preexec_fn=to_fd4,
                                     close_fds=False, env=env)
        child.close()
        self.page = None
        self.status = ""
        self.window = (time.monotonic(), 0)
        msg = self.recv(10)
        assert msg[0] == HELLO and msg[2] == API and msg[3] == API, msg
        self.send(HELLO_ACK, value=API, flags=3)
        self.send(LIFECYCLE, value=1)

    def send(self, kind, rid=0, value=0, flags=0):
        self.sock.send(struct.pack(FMT, MAGIC, API, kind, rid, value, flags, b"", b""))

    def recv(self, timeout):
        ready, _, _ = select.select([self.sock], [], [], timeout)
        if not ready:
            return None
        data = self.sock.recv(SIZE + 1)
        assert len(data) == SIZE, f"packet size {len(data)}"
        magic, version, kind, rid, value, flags, title, text = struct.unpack(FMT, data)
        assert magic == MAGIC and version == API
        assert b"\0" in title and b"\0" in text
        title = title.split(b"\0")[0].decode()  # also proves valid UTF-8
        text = text.split(b"\0")[0].decode()
        start, count = self.window
        now = time.monotonic()
        if now - start >= 1:
            start, count = now, 0
        self.window = (start, count + 1)
        assert count + 1 <= 128, "rate limit exceeded"
        return kind, rid, value, flags, title, text

    def handle(self, msg):
        kind, rid, value, flags, title, text = msg
        if kind == BEGIN:
            self.building = {"title": title, "body": text, "buttons": {}, "metrics": {}, "back": 0,
                             "sections": 0, "section": None}
        elif kind == BUTTON:
            b = self.building
            assert rid and title and rid not in b["buttons"] and len(b["buttons"]) < 12
            assert flags & ~7 == 0
            b["buttons"][rid] = (flags, title, text)
        elif kind == SECTION:
            b = self.building
            assert title and not flags and b["sections"] < 16
            b["sections"] += 1
            b["section"] = title
        elif kind == METRIC:
            b = self.building
            assert rid and title and rid not in b["metrics"] and len(b["metrics"]) < 64
            b["metrics"][rid] = [title, text, flags, b["section"]]
        elif kind == BACK:
            self.building["back"] = rid
        elif kind == COMMIT:
            b = self.building
            if b["back"]:
                assert b["back"] in b["buttons"] and not b["buttons"][b["back"]][0] & DISABLED
            self.page, self.building = b, None
            self.status = ""
        elif kind == UPDATE:
            assert self.page and rid in self.page["metrics"], f"update of unknown row {rid}"
            self.page["metrics"][rid][1:3] = [text, flags]
        elif kind == STATUS:
            self.status = text
        else:
            raise AssertionError(f"unexpected kind {kind}")

    def pump(self, cond, timeout=30):
        deadline = time.monotonic() + timeout
        while not cond():
            msg = self.recv(max(0.0, deadline - time.monotonic()))
            assert msg, f"timeout; page={self.page and self.page['title']!r} status={self.status!r}"
            self.handle(msg)

    def wait_page(self, title):
        self.pump(lambda: self.page and self.page["title"] == title)

    def wait_row(self, row, fragment):
        self.pump(lambda: row in self.page["metrics"] and fragment in self.page["metrics"][row][1])

    def wait_status(self, fragment):
        self.pump(lambda: fragment in self.status)

    def tap(self, label):
        matches = [rid for rid, (flags, t, _) in self.page["buttons"].items() if t == label]
        assert len(matches) == 1, f"button {label!r} not on {self.page['title']!r}"
        assert not self.page["buttons"][matches[0]][0] & DISABLED
        self.send(ACTION, matches[0])

    def enter_pin(self, digits):
        for d in digits:  # actions queue in order; the page stays the same
            self.tap(d)
        self.tap("OK")

    def stop(self):
        self.send(LIFECYCLE, value=3)
        assert self.proc.wait(10) == 0


def totp(secret, t, algo="sha1", digits=6, period=30):
    mac = hmac.new(secret, struct.pack(">Q", t // period), algo).digest()
    off = mac[-1] & 15
    code = struct.unpack(">I", mac[off:off + 4])[0] & 0x7FFFFFFF
    return str(code % 10 ** digits).zfill(digits)


def check_codes(host, expected):
    rows = {r: v for r, v in host.page["metrics"].items() if r >= ROW_CODE}
    assert len(rows) == len(expected), rows
    for row, (label, secret, algo, digits, period) in zip(sorted(rows), expected):
        title, value, _, section = rows[row]
        assert title == " " and section == label, (title, section, label)
        shown = value.split("  ")[0].replace(" ", "")
        t = int(time.time())
        ok = {totp(secret, t + d, algo, digits, period) for d in (-1, 0, 1)}
        assert shown in ok, (label, value, ok)


def main(exe):
    data = tempfile.mkdtemp(prefix="aera-auth-e2e-")
    s1, s2, s3 = b"12345678901234567890", b"12345678901234567890123456789012", b"hello world 12"
    expected = [
        ("Example: alice@example.com", s1, "sha1", 6, 30),
        ("Ünïcødé: bob", s2, "sha256", 8, 30),
        ("ACME Co: john@x.com", s3, "sha512", 6, 60),
    ]
    b32 = base64.b32encode(s3).decode().rstrip("=")
    export = "\n".join([
        migration([otp(s1, "alice@example.com", "Example"),
                   otp(s2, "Ünïcødé:bob", algo=2, digits=2),
                   otp(b"md5secret", "md5", algo=4),
                   otp(b"hotpsecret", "counter", type_=1)]),
        f"otpauth://totp/ACME%20Co:john@x.com?secret={b32.lower()}&algorithm=SHA512&period=60",
        "this line is garbage",
        "",
    ])

    NTP.offset = 20
    host = Host(exe, data)
    host.wait_page("Create a PIN")
    for label in "987":
        host.tap(label)
    host.tap("Delete")
    host.wait_status("(2 digits)")
    host.tap("Delete")  # second tap within a second clears everything
    host.wait_status("Enter your PIN")
    host.enter_pin("1234567")
    host.wait_status("at least 8")
    host.enter_pin("8")
    host.wait_page("Confirm PIN")
    host.enter_pin("12345678")
    host.wait_page("Rec Authenticator")
    assert "No accounts" in host.page["body"]
    host.wait_row(ROW_NTP, "s behind")
    assert host.page["metrics"][ROW_NTP][1] in ("19.9 s behind", "20.0 s behind")
    assert host.page["metrics"][ROW_NTP][2] == 1 << 10  # critical

    import_file = os.path.join(data, "import", "export.txt")
    with open(import_file, "w") as f:
        f.write(export)
    host.tap("Import accounts")
    host.wait_page("Import accounts")
    host.tap("export.txt")
    host.wait_page("Import preview")
    body = host.page["body"]
    for fragment in ("3 new accounts", "1 counter-based", "1 MD5", "1 line(s)"):
        assert fragment in body, body
    host.tap("Import 3 accounts")
    host.wait_page("Import complete")
    host.tap("Delete the import file")
    host.wait_page("Rec Authenticator")
    host.wait_status("Deleted export.txt")
    assert not os.path.exists(import_file)
    check_codes(host, expected)
    # Let a few one-second updates arrive, then check again.
    end = time.monotonic() + 2.5
    while time.monotonic() < end:
        msg = host.recv(end - time.monotonic())
        if msg:
            host.handle(msg)
    check_codes(host, expected)

    with open(os.path.join(data, "vault.bin"), "rb") as f:
        vault = f.read()
    assert vault.startswith(b"AERATOTP")
    for secret in (s1, s2, s3, b"alice", b"Example", b"ACME"):
        assert secret not in vault, secret

    # Re-importing the same lines finds only duplicates.
    with open(import_file, "w") as f:
        f.write(export)
    host.tap("Import accounts")
    host.wait_page("Import accounts")
    host.tap("export.txt")
    host.wait_page("Import preview")
    assert "0 new accounts" in host.page["body"] and "3 already" in host.page["body"]
    host.tap("Cancel")
    host.wait_page("Import accounts")
    host.tap("Back")
    host.wait_page("Rec Authenticator")

    host.tap("Lock")
    host.wait_page("Unlock")
    host.enter_pin("87654321")
    host.wait_status("Wrong PIN")
    host.enter_pin("12345678")
    host.wait_page("Rec Authenticator")

    host.tap("Settings")
    host.wait_page("Settings")
    NTP.offset = -0.2
    host.tap("Check network time")
    host.wait_row(ROW_NTP, "Matches")
    host.tap("Change PIN")
    host.wait_page("Change PIN")
    host.tap("1")
    for _ in range(3):  # clear, then a quick third tap must not cancel
        host.tap("Delete")
    host.wait_status("Enter your PIN")
    while msg := host.recv(0.5):
        host.handle(msg)
    assert host.page["title"] == "Change PIN"
    host.enter_pin("00000000")
    host.wait_status("Wrong PIN")
    host.enter_pin("12345678")
    host.wait_page("New PIN")
    host.enter_pin("1111222233")
    host.wait_page("Confirm new PIN")
    host.enter_pin("1111222233")
    host.wait_status("PIN changed")
    assert host.page["title"] == "Settings"

    host.tap("Delete an account")
    host.wait_page("Delete an account")
    host.tap("Example")
    host.wait_page("Delete this account?")
    host.tap("Delete")
    host.wait_status("Account deleted")
    host.tap("Back")
    host.wait_page("Settings")
    host.tap("Lock now")
    host.wait_page("Unlock")
    host.enter_pin("12345678")
    host.wait_status("Wrong PIN")
    host.stop()

    # A new process (a reboot) opens the vault with the new PIN. No time
    # server answers this time: a closed port fails every server.
    closed = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    host = Host(exe, data, port)
    host.wait_page("Unlock")
    host.enter_pin("1111222233")
    host.wait_page("Rec Authenticator")
    check_codes(host, expected[1:])
    host.wait_row(ROW_NTP, "No reply")
    host.stop()
    shutil.rmtree(data)
    print("e2e passed")


if __name__ == "__main__":
    main(os.path.abspath(sys.argv[1]))
