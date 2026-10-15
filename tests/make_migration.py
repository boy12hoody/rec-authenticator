#!/usr/bin/env python3
"""Builds otpauth-migration:// URIs for tests (Google Authenticator export format)."""
import base64
import sys
import urllib.parse


def varint(n):
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            return out + bytes([b])


def field(num, value):
    if isinstance(value, int):
        return varint(num << 3) + varint(value)
    return varint(num << 3 | 2) + varint(len(value)) + value


def otp(secret, name, issuer="", algo=1, digits=1, type_=2):
    body = field(1, secret) + field(2, name.encode())
    if issuer:
        body += field(3, issuer.encode())
    return body + field(4, algo) + field(5, digits) + field(6, type_)


def migration(entries, batch_index=0, batch_size=1):
    payload = b"".join(field(1, e) for e in entries)
    payload += field(2, 1) + field(3, batch_size) + field(4, batch_index) + field(5, 42)
    data = base64.b64encode(payload).decode()
    return "otpauth-migration://offline?data=" + urllib.parse.quote(data, safe="")


if __name__ == "__main__":
    print(migration([
        otp(b"12345678901234567890", "alice@example.com", "Example"),
        otp(b"12345678901234567890123456789012", "Ünïcødé:bob", algo=2, digits=2),
        otp(b"md5secret", "md5", algo=4),
        otp(b"hotpsecret", "counter", type_=1),
    ]))
    sys.stdout.flush()
