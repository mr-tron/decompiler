import unittest
from hashlib import sha256
from decompiler.boc import BocError, code_hash, parse_boc, crc32c


class BocTests(unittest.TestCase):
    def test_empty_cell_and_crc(self):
        boc = bytes.fromhex('b5ee9c72010101010002000000')
        self.assertEqual(code_hash(boc), sha256(b'\0\0').hexdigest())
        crc_boc = boc[:4] + b'\x41' + boc[5:]
        self.assertEqual(code_hash(crc_boc + crc32c(crc_boc)), code_hash(boc))
        with self.assertRaises(BocError):
            parse_boc(crc_boc + b'\0' * 4)

    def test_reference_hash_and_index(self):
        boc = bytes.fromhex('b5ee9c728101020100050003050100010000')
        expected = sha256(b'\x01\x00\x00\x00' + sha256(b'\0\0').digest()).hexdigest()
        self.assertEqual(code_hash(boc), expected)
        for invalid in (boc[:-1], boc + b'\0', boc[:11] + b'\x04' + boc[12:]):
            with self.assertRaises(BocError):
                parse_boc(invalid)

    def test_reject_exotic_cycles_topup_and_extra_roots(self):
        for value in ('b5ee9c72010101010002000800',
                      'b5ee9c7201010101000300010000',
                      'b5ee9c7201010101000300000180',
                      'b5ee9c72010101020002000000'):
            with self.assertRaises(BocError):
                parse_boc(bytes.fromhex(value))


if __name__ == '__main__':
    unittest.main()
