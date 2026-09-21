"""Wallet V5 reconstruction checked against the official TVM."""
import base64
from pathlib import Path
import tempfile
import unittest

from decompiler.asm import parse_asm
from decompiler.ir import analyze, UnsupportedInstruction
from decompiler.service import decompile
from decompiler.toolchain import Toolchain, _run

TOOLS = Toolchain()
ORIGINAL = base64.b64decode((Path(__file__).parent / 'data/wallet_v5.b64').read_text())

def run(boc, external=True, seqno=1, wallet=42, until=1800000000,
        valid=True, actions='0 2 u,', extension=False):
    fift, library = TOOLS._fift()
    prefix = '0x7369676e' if external else '0x73696e74'
    prelude = '''"Asm.fif" include
    B{0000000000000000000000000000000000000000000000000000000000000001} constant private_key
    private_key priv>pub 256 B>u@ constant public_key
    <b 4 3 u, 0 8 i, 0 256 u, b> <s constant address
    0x076ef1ea 0 0 1700000000 0 0 0 0 null pair address null 10 tuple 1 tuple constant context
    '''
    if extension:
        prelude += '<b -1 1 i, 0 null 256 <{ DICTUSETB }>s runvmcode drop constant extensions\n'
    tail = '1 1 u, extensions ref,' if extension else '0 1 u,'
    prelude += f'<b -1 1 i, 1 32 u, 42 32 u, public_key 256 u, {tail} b> constant data\n'
    if extension:
        prelude += f'<b 0x6578746e 32 u, 0 64 u, {actions} b> constant body\n'
        stack = '0 0 <b 0 4 u, address s, b> body <s 0'
    else:
        prelude += f'<b {prefix} 32 u, {wallet} 32 u, {until} 32 u, {seqno} 32 u, {actions} b> constant body\n'
        prelude += 'body hashu private_key ed25519_sign_uint constant signature\n'
        stack = '' if external else '0 0 <b b> '
        stack += '<b body <s s, ' + ('signature B,' if valid else '0 256 u, 0 256 u,') + ' b> <s ' + ('-1' if external else '0')
    script = prelude + stack + ' "code.boc" file>B B>boc <s data context 0x35 runvmx .s\n'
    with tempfile.TemporaryDirectory() as directory:
        Path(directory, 'code.boc').write_bytes(boc)
        Path(directory, 'run.fif').write_text(script)
        return _run([fift, '-I', library, '-s', 'run.fif'], directory).strip()


class WalletV5Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not TOOLS.configs():
            raise unittest.SkipTest('Run scripts/bootstrap.py for official compiler and VM checks')
        cls.result = decompile(ORIGINAL, toolchain=TOOLS)
        readable = cls.result['readable']
        compiler = readable['compiler']
        cls.compiled = TOOLS.compile(readable['func'], compiler['selected_version'], compiler['flags'])

    def test_all_original_methods_and_both_receivers_are_readable(self):
        self.assertTrue(self.result['decompilation']['exact_hash_match'])
        readable = self.result['readable']
        self.assertEqual(readable['decompilation']['structured_method_count'], 7)
        self.assertEqual(readable['decompilation']['method_count'], 7)
        self.assertNotIn('asm_', readable['contract'])
        self.assertIn('recv_external(slice ', readable['contract'])
        self.assertIn('recv_internal(cell in_msg_full, slice in_msg_body)', readable['contract'])
        self.assertIn('while (-1)', readable['contract'])
        self.assertIn('check_signature(', readable['contract'])
        self.assertEqual(self.compiled.code_hash, readable['decompilation']['candidate_code_hash'])
        self.assertFalse(readable['decompilation']['exact_hash_match'])

    def test_signature_validation_state_actions_and_loop_returns_against_vm(self):
        cases = [({}, 0), ({'external': False}, 0), ({'valid': False}, 135),
                 ({'external': False, 'valid': False}, 0), ({'seqno': 2}, 133),
                 ({'wallet': 43}, 134), ({'until': 1600000000}, 136),
                 ({'actions': '0 1 u, 1 1 u, 0 8 u,'}, 141),
                 ({'actions': '0 1 u, 1 1 u, 2 8 u, address s,'}, 0),
                 ({'actions': '0 1 u, 1 1 u, 3 8 u, address s,'}, 140),
                 ({'actions': '0 1 u, 1 1 u, 4 8 u, 0 1 u,'}, 146),
                 ({'actions': '0 1 u, 1 1 u, 2 8 u, address s, <b 3 8 u, address s, b> ref,'}, 0),
                 ({'actions': '1 1 u, <b 0x0ec3c86d 32 u, 2 8 u, <b b> ref, <b b> ref, b> ref, 0 1 u,'}, 0),
                 ({'actions': '1 1 u, <b 0x0ec3c86d 32 u, 0 8 u, <b b> ref, <b b> ref, b> ref, 0 1 u,'}, 137)]
        cases += [({'extension': True}, 0),
                  ({'extension': True, 'actions': '0 1 u, 1 1 u, 4 8 u, 0 1 u,'}, 0),
                  ({'extension': True, 'actions': '0 1 u, 1 1 u, 3 8 u, address s,'}, 0),
                  ({'extension': True, 'actions': '0 1 u, 1 1 u, 2 8 u, address s,'}, 139),
                  ({'extension': True, 'actions': '0 1 u, 1 1 u, 4 8 u, 0 1 u, <b 3 8 u, address s, b> ref,'}, 144)]
        for options, exit_code in cases:
            with self.subTest(options=options):
                expected = run(ORIGINAL, **options)
                # Last two VM values are persistent data and the action cell.
                self.assertEqual(int(expected.split()[-3]), exit_code)
                self.assertEqual(run(self.compiled.boc, **options), expected)

    def test_unscoped_alternate_return_and_loop_jump_remain_unsupported(self):
        with self.assertRaises(UnsupportedInstruction):
            analyze(parse_asm('RETALT').instructions)
        nested = 'DUP\nIF:<{\nDUP\nIFJMP:<{\n}>\n}>\nINC'
        self.assertEqual(analyze(parse_asm(nested).instructions).returns[0].value, '+')
        code = '0 PUSHINT\nAGAINEND\nDUP\nIFJMP:<{\n}> '
        self.assertEqual(analyze(parse_asm(code).instructions).statements[-1].kind, 'while')


if __name__ == '__main__':
    unittest.main()
