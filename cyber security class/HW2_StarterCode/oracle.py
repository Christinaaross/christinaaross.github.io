"""
oracle.py

Vulnerable services for Homework 2.

Students should treat the service objects as black boxes and use only the
public interfaces described in the homework handout.

Dependency:
    python -m pip install pycryptodome
"""

from __future__ import annotations

import os
from typing import Callable, Optional

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

AES_BLOCK_SIZE = 16
CTR_COUNTER_SIZE = AES_BLOCK_SIZE


class QueryLimitExceeded(RuntimeError):
    """Raised when an attack exceeds its allowed oracle-query budget."""


class CountingOracle:
    """Wrap a Boolean oracle and count how many queries it receives."""

    def __init__(self, fn: Callable[[bytes], bool], limit: Optional[int] = None):
        self._fn = fn
        self.limit = limit
        self.queries = 0

    def __call__(self, ciphertext: bytes) -> bool:
        self.queries += 1
        if self.limit is not None and self.queries > self.limit:
            raise QueryLimitExceeded(
                f"oracle query limit exceeded: {self.queries} > {self.limit}"
            )
        return bool(self._fn(ciphertext))

    def reset(self) -> None:
        self.queries = 0


def _xor_bytes(x: bytes, y: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(x, y))


def _ctr_crypt(key: bytes, ctr: bytes, data: bytes) -> bytes:
    """
    CTR construction used in the homework handout.

    AES-ECB is used as the PRF f_k. For block i = 1, 2, ..., the keystream is
        f_k(ctr XOR i),
    where i is represented as a 16-byte big-endian string.

    The same routine is used for encryption and decryption. A final partial
    block is supported by truncating the keystream block.
    """
    if len(ctr) != CTR_COUNTER_SIZE:
        raise ValueError("CTR counter must be 16 bytes")

    prf = AES.new(key, AES.MODE_ECB)
    out = bytearray()

    for block_index, offset in enumerate(range(0, len(data), AES_BLOCK_SIZE), start=1):
        chunk = data[offset : offset + AES_BLOCK_SIZE]
        i_bytes = block_index.to_bytes(CTR_COUNTER_SIZE, "big")
        prf_input = _xor_bytes(ctr, i_bytes)
        keystream = prf.encrypt(prf_input)
        out.extend(_xor_bytes(chunk, keystream[: len(chunk)]))

    return bytes(out)


class CTRTransactionService:
    """
    Warm-up service for the CTR bit-flipping task.

    The message is always:
        b"from=alice&to=bob&amount=1000"

    Ciphertext format:
        16-byte ctr || CTR ciphertext
    """

    KNOWN_TRANSACTION = b"from=alice&to=bob&amount=1000"
    COUNTER_SIZE = CTR_COUNTER_SIZE

    def __init__(self):
        self.__key = os.urandom(AES_BLOCK_SIZE)

    def get_transaction(self) -> bytes:
        ctr = os.urandom(self.COUNTER_SIZE)
        body = _ctr_crypt(self.__key, ctr, self.KNOWN_TRANSACTION)
        return ctr + body

    # Public-test verification helper only. Students must not call this method.
    def _verify_transaction(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) < self.COUNTER_SIZE:
            raise ValueError("ciphertext too short")
        ctr, body = ciphertext[: self.COUNTER_SIZE], ciphertext[self.COUNTER_SIZE :]
        return _ctr_crypt(self.__key, ctr, body)


class CTRFormatOracleService:
    """
    CTR service exposing only a one-bit null-byte format oracle.

    Ciphertext format:
        16-byte ctr || CTR ciphertext

    The challenge message must not contain byte 0x00.
    """

    COUNTER_SIZE = CTR_COUNTER_SIZE

    def __init__(self, message: bytes):
        if b"\x00" in message:
            raise ValueError("CTR challenge message must be null-free")
        self.__key = os.urandom(AES_BLOCK_SIZE)
        self.__message = bytes(message)
        self.__challenge = self.__encrypt(self.__message)

    def __encrypt(self, message: bytes) -> bytes:
        ctr = os.urandom(self.COUNTER_SIZE)
        return ctr + _ctr_crypt(self.__key, ctr, message)

    def get_challenge(self) -> bytes:
        """Return the challenge ciphertext."""
        return bytes(self.__challenge)

    def has_null(self, ciphertext: bytes) -> bool:
        """Return True iff the decrypted message contains at least one 0x00 byte."""
        try:
            if len(ciphertext) < self.COUNTER_SIZE:
                return False
            ctr, body = ciphertext[: self.COUNTER_SIZE], ciphertext[self.COUNTER_SIZE :]
            message = _ctr_crypt(self.__key, ctr, body)
            return b"\x00" in message
        except Exception:
            return False

    # Public-test helper only. Students must not call this method.
    def _expected_message(self) -> bytes:
        return self.__message


class CBCPaddingOracleService:
    """
    AES-CBC service with PKCS#7 padding and a Boolean padding oracle.

    Challenge ciphertext format:
        IV || C1 || C2 || ... || Cn
    """

    BLOCK_SIZE = AES_BLOCK_SIZE

    def __init__(self, message: bytes):
        self.__key = os.urandom(AES_BLOCK_SIZE)
        self.__message = bytes(message)
        self.__challenge = self.__encrypt(self.__message)

    def __encrypt(self, message: bytes) -> bytes:
        iv = os.urandom(self.BLOCK_SIZE)
        cipher = AES.new(self.__key, AES.MODE_CBC, iv=iv)
        body = cipher.encrypt(pad(message, self.BLOCK_SIZE))
        return iv + body

    def get_challenge(self) -> bytes:
        """Return the challenge ciphertext."""
        return bytes(self.__challenge)

    def valid_padding(self, ciphertext: bytes) -> bool:
        """Return True iff CBC decryption has valid PKCS#7 padding."""
        try:
            if len(ciphertext) < 2 * self.BLOCK_SIZE:
                return False
            if len(ciphertext) % self.BLOCK_SIZE != 0:
                return False

            iv, body = ciphertext[: self.BLOCK_SIZE], ciphertext[self.BLOCK_SIZE :]
            cipher = AES.new(self.__key, AES.MODE_CBC, iv=iv)
            padded_message = cipher.decrypt(body)
            unpad(padded_message, self.BLOCK_SIZE)
            return True
        except Exception:
            return False

    # Public-test helpers only. Students must not call these methods.
    def _expected_message(self) -> bytes:
        return self.__message

    def _decrypt_for_testing(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) < 2 * self.BLOCK_SIZE:
            raise ValueError("ciphertext too short")
        if len(ciphertext) % self.BLOCK_SIZE != 0:
            raise ValueError("ciphertext length must be a multiple of 16")
        iv, body = ciphertext[: self.BLOCK_SIZE], ciphertext[self.BLOCK_SIZE :]
        cipher = AES.new(self.__key, AES.MODE_CBC, iv=iv)
        padded = cipher.decrypt(body)
        return unpad(padded, self.BLOCK_SIZE)
