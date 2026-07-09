import hashlib
import hmac
from itertools import count


def keystream(passphrase: str, salt: bytes):
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 200_000, dklen=32)
    for index in count():
        yield hmac.new(key, salt + index.to_bytes(8, "big"), hashlib.sha256).digest()


def xor_crypt(data: bytes, passphrase: str, salt: bytes) -> bytes:
    out = bytearray()
    stream = keystream(passphrase, salt)
    while len(out) < len(data):
        block = next(stream)
        remaining = data[len(out) : len(out) + len(block)]
        out.extend(a ^ b for a, b in zip(remaining, block))
    return bytes(out)

