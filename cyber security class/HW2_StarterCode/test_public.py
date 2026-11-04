"""
Small public test suite for Homework 2.

Run with:
    python -m unittest -v test_public.py

These tests are intentionally limited. The grading tests will use fresh random
keys and fresh random messages and will include the edge cases described in the
homework handout.
"""

import unittest

from oracle import (
    CBCPaddingOracleService,
    CTRFormatOracleService,
    CTRTransactionService,
    CountingOracle,
)
from attacks import (
    change_amount,
    recover_ctr_byte,
    recover_ctr,
    recover_cbc_block,
    recover_cbc,
)


class TestCTRBitFlipping(unittest.TestCase):
    def test_change_amount(self):
        service = CTRTransactionService()
        ciphertext = service.get_transaction()

        modified = change_amount(ciphertext)
        message = service._verify_transaction(modified)

        self.assertEqual(message, b"from=alice&to=bob&amount=9000")


class TestCTRFormatOracle(unittest.TestCase):
    def test_recover_one_byte(self):
        message = b"graduate crypto"
        service = CTRFormatOracleService(message)
        ciphertext = service.get_challenge()

        position = 5
        oracle = CountingOracle(service.has_null, limit=255)
        recovered = recover_ctr_byte(ciphertext, position, oracle)

        self.assertEqual(recovered, message[position])
        self.assertLessEqual(oracle.queries, 255)

    def test_recover_complete_message(self):
        message = b"chosen ciphertext attacks"
        service = CTRFormatOracleService(message)
        ciphertext = service.get_challenge()

        oracle = CountingOracle(service.has_null, limit=255 * len(message))
        recovered = recover_ctr(ciphertext, oracle)

        self.assertEqual(recovered, message)
        self.assertLessEqual(oracle.queries, 255 * len(message))


class TestCBCPaddingOracle(unittest.TestCase):
    def test_recover_single_block(self):
        # 15 bytes => PKCS#7 appends one 0x01 byte.
        message = b"attack at dawn!"
        self.assertEqual(len(message), 15)

        service = CBCPaddingOracleService(message)
        ciphertext = service.get_challenge()

        iv = ciphertext[:16]
        c1 = ciphertext[16:32]

        oracle = CountingOracle(service.valid_padding, limit=5000)
        recovered_block = recover_cbc_block(iv, c1, oracle)

        self.assertEqual(recovered_block, message + b"\x01")
        self.assertLessEqual(oracle.queries, 5000)

    def test_recover_complete_message(self):
        message = b"this message spans more than one AES block"
        service = CBCPaddingOracleService(message)
        ciphertext = service.get_challenge()

        n_cipher_blocks = (len(ciphertext) // 16) - 1
        oracle = CountingOracle(
            service.valid_padding,
            limit=5000 * n_cipher_blocks,
        )

        recovered = recover_cbc(ciphertext, oracle)

        self.assertEqual(recovered, message)
        self.assertLessEqual(oracle.queries, 5000 * n_cipher_blocks)


if __name__ == "__main__":
    unittest.main(verbosity=2)
