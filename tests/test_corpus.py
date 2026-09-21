import tempfile
import unittest
from pathlib import Path
import json

from decompiler.corpus import Contract, assign_splits, load_corpus, source_tokens, compilation_bundle
from decompiler.fingerprint import Fingerprints, differential_report


def test_corpus():
    assert source_tokens('a {- outer {- inner -} -} ;; line\n "a ;; b"') == ['a', '"a ;; b"']
    a = Contract('a', {'a.fc': 'int f(int x) { return x + 1; }'}, ['a.fc'], '0.4.4', [], 'x')
    b = Contract('b', {'b.fc': ';; duplicate\nint f(int x) { return x + 77; }'}, ['b.fc'], '0.3.0', [], 'y')
    flattened = Contract('flat', {'main.fc': '#include \"../stdlib.fc\"; () recv_internal() {}', 'stdlib.fc': 'int f() { return 1; }'}, ['main.fc'], '0.4.4', [], None)
    sources, targets = compilation_bundle(flattened)
    assert targets == ['bundle/main.fc'] and sources['stdlib.fc'] == flattened.sources['stdlib.fc']
    assign_splits([a, b])
    assert a.group == b.group and a.split == b.split
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / '001'
        (path / 'src').mkdir(parents=True)
        (path / 'src' / 'main.fc').write_text('() recv_internal() {}')
        (path / 'src' / '.DS_Store').write_bytes(b'not source')
        (path / 'info.json').write_text(json.dumps({'funcCmdLine': 'func -o output.fif -SPA ./main.fc', 'funcVersion': '0.4.4'}))
        row = load_corpus(d)[0]
        assert row.targets == ['main.fc'] and row.flags == ['-SPA'] and row.error is None
        assert set(row.sources) == {'main.fc'}
    rows = [{'contract': 'a', 'version': v, 'flags': ['-O2'], 'split': 'train', 'success': True,
             'asm': '1 PUSHINT\nADD', 'code_hash': 'same'} for v in ['0.3.0', '0.4.4']]
    assert Fingerprints(rows).training_sha256 == Fingerprints([dict(r, runtime_ms=999) for r in rows]).training_sha256
    ranked = Fingerprints(rows).rank('1 PUSHINT\nADD')
    assert ranked[0]['weight'] == ranked[1]['weight'] == .5
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / 'profiles.json'
        Fingerprints(rows).save(path)
        assert Fingerprints.load(path).rank('1 PUSHINT\nADD') == ranked
    assert len(differential_report(rows)['ambiguous_sources']) == 1
    different = dict(rows[0], code_hash='different', asm='2 PUSHINT\nMUL')
    changes = differential_report(rows + [different])['development_instruction_changes']
    assert changes[0]['before'] == ['ADD'] and changes[0]['after'] == ['MUL']
    assert not Fingerprints([dict(rows[0], split='holdout')]).profiles


if __name__ == '__main__':
    test_corpus()
    print('corpus checks passed')


class CorpusChecks(unittest.TestCase):
    def test_corpus(self):
        test_corpus()
