"""All repository tests are offline; no accidental provider/DNS requests."""
import os
import socket

os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "True"
_connect = socket.socket.connect
_connect_ex = socket.socket.connect_ex
_resolve = socket.getaddrinfo


def _local(address):
    return not isinstance(address, tuple) or address[0] in ("127.0.0.1", "::1", "localhost")


def _offline_connect(self, address):
    if not _local(address):
        raise RuntimeError("External network disabled during tests")
    return _connect(self, address)


def _offline_connect_ex(self, address):
    if not _local(address):
        raise RuntimeError("External network disabled during tests")
    return _connect_ex(self, address)


def _offline_resolve(host, *args, **kwargs):
    if host not in (None, "localhost", "127.0.0.1", "::1", b"localhost", b"127.0.0.1", b"::1"):
        raise RuntimeError("External DNS disabled during tests")
    return _resolve(host, *args, **kwargs)


socket.socket.connect = _offline_connect
socket.socket.connect_ex = _offline_connect_ex
socket.getaddrinfo = _offline_resolve

