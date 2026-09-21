import tempfile
import unittest
from pathlib import Path
from decompiler.cli import source_bundle


class CliTests(unittest.TestCase):
    def test_reachable_relative_include_graph(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'sub').mkdir()
            (root / 'stdlib.fc').write_text(';; standard library')
            (root / 'unrelated.fc').write_text('not valid FunC')
            main = root / 'sub' / 'main.fc'
            main.write_text('#include "../stdlib.fc"; () recv_internal() {}')
            sources, entries = source_bundle(main)
            self.assertEqual(set(sources), {'sub/main.fc', 'stdlib.fc'})
            self.assertEqual(entries, ['sub/main.fc'])
