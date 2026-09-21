"""Regression checks for difficult corpus patterns, using the official VM."""
from pathlib import Path
import tempfile
import unittest

from decompiler.asm import parse_asm
from decompiler.boc import method_cells
from decompiler.func import reconstruct, render, resolve_references
from decompiler.ir import UnsupportedInstruction
from decompiler.toolchain import Toolchain, _run


class DifficultCaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = Toolchain()
        if not cls.tools.configs():
            raise unittest.SkipTest('Run scripts/bootstrap.py for official VM checks')

    def vm(self, boc, arguments, method=100):
        fift, library = self.tools._fift()
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'code.boc').write_bytes(boc)
            Path(directory, 'run.fif').write_text(
                f'"Asm.fif" include {arguments} {method} "code.boc" file>B B>boc <s runvmcode .s')
            return _run([fift, '-I', library, '-s', 'run.fif'], directory).strip()

    def test_early_return_helper_inlining_preserves_results_and_exceptions(self):
        source = '''int helper(int x) impure asm
          "<{ DUP 0 EQINT IFJMP:<{ DROP 7 PUSHINT }> 1 PUSHINT ADD }>c CALLREF";
          () recv_internal() { }
          int example(int x) impure method_id(1) { return helper(x); }
        '''
        original = self.tools.compile(source)
        candidate = self.tools.compile(render(reconstruct(parse_asm(original.asm)), readable=True))
        self.assertEqual(set(method_cells(candidate.boc)), {0, 1})
        for value in (0, -1, 9, 2**256-1):
            self.assertEqual(self.vm(original.boc, str(value), 1), self.vm(candidate.boc, str(value), 1))

    def test_nested_continuation_jump_does_not_return_from_function(self):
        source = ('int operation(int x) impure asm "DUP IF:<{ DUP IFJMP:<{ }> }> INC"; '
                  '() recv_internal() { } int example(int x) impure method_id(100) { return operation(x); }')
        original = self.tools.compile(source)
        candidate = self.tools.compile(render(reconstruct(parse_asm(original.asm)), readable=True))
        for value in (-1, 0, 1, 20):
            self.assertEqual(self.vm(original.boc, str(value)), self.vm(candidate.boc, str(value)))

    def test_tick_tock_keeps_its_entrypoint_name_and_id(self):
        source = '() recv_internal() { } () run_ticktock(int is_tock) impure { throw_if(42, is_tock); }'
        original = self.tools.compile(source)
        readable = render(reconstruct(parse_asm(original.asm)), readable=True)
        self.assertIn('run_ticktock(', readable)
        self.assertNotIn('method_neg_2', readable)
        self.assertEqual(self.tools.compile(readable).code_hash, original.code_hash)

    def test_random_uint256_preserves_stateful_primitive(self):
        source = ('int random_uint256() impure asm "RANDU256"; () recv_internal() { } '
                  'int example() impure method_id(100) { return random_uint256(); }')
        original = self.tools.compile(source)
        candidate = self.tools.compile(render(reconstruct(parse_asm(original.asm)), readable=True))
        self.assertEqual(original.code_hash, candidate.code_hash)

    def test_referenced_slice_includes_its_nested_cells(self):
        source = '''slice literal() asm "<b 171 8 u, <b 42 8 u, b> ref, b> PUSHREFSLICE";
          () recv_internal() { }
          slice example() method_id(100) { return literal(); }
        '''
        original = self.tools.compile(source)
        self.assertIn('PUSHREFSLICE', original.asm)
        program = resolve_references(parse_asm(original.asm), original.boc)
        candidate = self.tools.compile(render(reconstruct(program), readable=True))
        self.assertEqual(original.code_hash, candidate.code_hash)
        self.assertEqual(self.vm(original.boc, ''), self.vm(candidate.boc, ''))

    def test_stable_dispatcher_call_and_mutated_dispatcher_guard(self):
        source = '''int dispatch(int x) impure asm "101 PUSHINT" "c3 PUSH" "EXECUTE";
          () recv_internal() { }
          int example(int x) impure method_id(100) { return dispatch(x); }
          int target(int x) method_id(101) { return x + 1; }
        '''
        original = self.tools.compile(source)
        program = parse_asm(original.asm)
        candidate = self.tools.compile(render(reconstruct(program), readable=True))
        for value in (-1, 0, 17):
            self.assertEqual(self.vm(original.boc, str(value)), self.vm(candidate.boc, str(value)))
        for mutation in ('c3 POP', '3 PUSHINT\nPOPCTRX', 'BLESS'):
            program.methods[102] = parse_asm(mutation).instructions
            with self.assertRaises(UnsupportedInstruction):
                reconstruct(program)

    def test_loop_carried_cells_and_generic_callees_against_vm(self):
        sources = [
            ('builder fresh() asm "NEWC"; builder refstore(cell c, builder b) asm "STREF"; '
             'cell finish(builder b) asm "ENDC"; () recv_internal() { } '
             'cell example(cell c, int n) method_id(100) { while (n > 0) { '
             'c = finish(refstore(c, fresh())); n -= 1; } return c; }',
             ['<b 42 8 u, b> 0', '<b 42 8 u, b> 3']),
            ('forall X -> int is_null_value(X x) asm "ISNULL"; () recv_internal() { } '
             'forall X -> int check(X x) impure method_id(101) { return is_null_value(x); } '
             'int example(slice s) impure method_id(100) { return check(s); }',
             ['x{ab}', 'null']),
        ]
        for source, inputs in sources:
            original = self.tools.compile(source)
            candidate = self.tools.compile(render(reconstruct(parse_asm(original.asm)), readable=True))
            for arguments in inputs:
                self.assertEqual(self.vm(original.boc, arguments), self.vm(candidate.boc, arguments))

    def test_scalar_dictionary_and_prefix_helpers_match_vm(self):
        examples = [
            ('int', 'int x', 'UBITSIZE', ['0', '255', '-1']),
            ('int', 'int x', 'BITSIZE', ['0', '255', '-1']),
            ('int', 'int x', 'ABS', ['0', '255', '-1']),
            ('int', 'int x', 'POW2', ['0', '8', '255']),
            ('int', 'int x', '9 MODPOW2#', ['0', '513', '-1']),
            ('(cell, int)', 'int key, cell d, int bits', 'DICTIDEL', ['0 null 8', '-1 x{ab} -1 null 8 <{ DICTISET }>s runvmcode drop 8']),
            ('(slice, slice, slice, int)', 'slice key, cell d, int bits',
             'PFXDICTGETQ NULLSWAPIFNOT2', ['x{ab} null 8',
              'x{ab} x{77} x{a} null 8 <{ PFXDICTSET }>s runvmcode drop drop 8',
              'x{bc} x{77} x{a} null 8 <{ PFXDICTSET }>s runvmcode drop drop 8']),
        ]
        for result, arguments, assembly, inputs in examples:
            with self.subTest(assembly=assembly):
                source = (f'{result} operation({arguments}) impure asm "{assembly}"; '
                          f'() recv_internal() {{ }} {result} example({arguments}) impure method_id(100) {{ '
                          f'return operation({", ".join(x.split()[-1] for x in arguments.split(","))}); }}')
                original = self.tools.compile(source)
                candidate = self.tools.compile(render(reconstruct(parse_asm(original.asm)), readable=True))
                for values in inputs:
                    self.assertEqual(self.vm(original.boc, values), self.vm(candidate.boc, values))


if __name__ == '__main__':
    unittest.main()
