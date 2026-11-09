import hashlib
import random
import secrets
import string

from Crypto.Cipher import AES, DES
from cryptography.hazmat.primitives.ciphers import algorithms, modes


def digests(data: bytes) -> None:
    # ruleid: python-weak-hash
    hashlib.md5(data).hexdigest()
    # ruleid: python-weak-hash
    hashlib.sha1(data)
    # ruleid: python-weak-hash
    hashlib.new("md5", data)
    # ok: python-weak-hash
    hashlib.sha256(data)
    # ok: python-weak-hash
    hashlib.md5(data, usedforsecurity=False)
    # ok: python-weak-hash
    hashlib.new("sha256", data)


def ciphers(key: bytes) -> None:
    # ruleid: python-weak-cipher
    DES.new(key, DES.MODE_CBC)
    # ruleid: python-weak-cipher
    AES.new(key, AES.MODE_ECB)
    # ruleid: python-weak-cipher
    modes.ECB()
    # ruleid: python-weak-cipher
    algorithms.TripleDES(key)
    # ok: python-weak-cipher
    AES.new(key, AES.MODE_GCM)
    # ok: python-weak-cipher
    modes.GCM(b"0" * 12)


def tokens() -> None:
    # ruleid: python-insecure-random-secret
    reset_token = random.getrandbits(128)
    # ruleid: python-insecure-random-secret
    api_key = "".join(random.choice(string.ascii_letters) for _ in range(32))
    # ruleid: python-insecure-random-secret
    salt = random.randbytes(16)
    # ok: python-insecure-random-secret
    session_token = secrets.token_urlsafe(32)
    # ok: python-insecure-random-secret
    jitter = random.random()
    print(reset_token, api_key, salt, session_token, jitter)
