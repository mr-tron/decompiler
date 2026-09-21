"""Run with python3 -m unittest tests.test_toolchain (requires bootstrap)."""
import tempfile
import unittest
from pathlib import Path
from decompiler.toolchain import Toolchain, ToolchainError, _run

class ToolchainTests(unittest.TestCase):
    def test_real_compilers_cache_and_disassembler(self):
        tools = Toolchain()
        if not tools.configs():
            self.skipTest('Run scripts/bootstrap.py for integration test')
        hashes = set()
        for version in tools.versions():
            result = tools.compile('() recv_internal() impure { throw(42); }', version)
            self.assertIn('42 THROW', result.asm)
            self.assertEqual(tools.disassemble(result.boc), result.asm)
            self.assertEqual(tools.compile('() recv_internal() impure { throw(42); }', version), result)
            hashes.add(result.code_hash)
        self.assertEqual(len(hashes), 1)
        for flag in ('-O0', '-O1', '-O2', '-O3'):
            result = tools.compile('() recv_internal() impure { throw(42); }', flags=[flag])
            self.assertIn(result.code_hash, hashes)
        # A release ID must select its own binary even when semantic versions match.
        for config in tools.configs():
            item, _ = tools._compiler(config['id'])
            self.assertEqual(item['id'], config['id'])
        with self.assertRaises(ToolchainError):
            tools.compile({'../escape.fc': '() main() {}'})
        with self.assertRaises(ToolchainError):
            tools.compile('() main() {}', flags=['--evil'])

    def test_cache_eviction(self):
        with tempfile.TemporaryDirectory() as td:
            tools = Toolchain()
            tools.cache = Path(td)
            tools.cache_max_bytes = 180
            tools._store(tools.cache / 'first.json', {'asm': 'a' * 30})
            tools._store(tools.cache / 'second.json', {'asm': 'b' * 30})
            self.assertFalse((tools.cache / 'first.json').exists())
            self.assertIsNotNone(tools._load(tools.cache / 'second.json'))
            (tools.cache / 'second.json').write_text('{bad json')
            self.assertIsNone(tools._load(tools.cache / 'second.json'))

    def test_subprocess_deadline(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaisesRegex(ToolchainError, 'time limit'):
                _run(['/bin/sleep', '30'], td, .05)

if __name__ == '__main__':
    unittest.main()
