"""Small fixed-signature opcode checks for the readable-100 expansion."""
from pathlib import Path
import tempfile
import unittest

from decompiler.asm import parse_asm
from decompiler.func import reconstruct, render
from decompiler.ir import analyze
from decompiler.toolchain import Toolchain, _run


class Pattern100Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = Toolchain()
        if not cls.tools.configs():
            raise unittest.SkipTest("Run scripts/bootstrap.py for official compiler checks")

    def test_rist255_fixed_stack_shapes(self):
        validate = analyze(parse_asm("RIST255_VALIDATE").instructions, arguments=1)
        self.assertEqual((validate.primitives[0].inputs, validate.primitives[0].outputs),
                         (("int",), ()))
        mulbase = analyze(parse_asm("RIST255_MULBASE").instructions, arguments=1)
        self.assertEqual((mulbase.primitives[0].inputs, mulbase.primitives[0].outputs),
                         (("int",), ("int",)))

    def test_train100_slice_and_dictionary_stack_shapes(self):
        cases = {
            'PUSHSLICE x{00}\nPUSHSLICE x{0}\nSDPFXREV':
                (("slice", "slice"), ("int",)),
            'PUSHSLICE x{00}\nNEWC\nENDC\n16 PUSHINT\nDICTGET\nNULLSWAPIFNOT':
                (("slice", "cell", "int"), ("slice", "int")),
            'NEWC\nENDC\n16 PUSHINT\nDICTREMMIN\nNULLSWAPIFNOT2':
                (("cell", "int"), ("cell", "slice", "slice", "int")),
            'NEWC\nENDC\n16 PUSHINT\nDICTUMINREF\nNULLSWAPIFNOT2':
                (("cell", "int"), ("cell", "int", "int")),
        }
        for assembly, expected in cases.items():
            with self.subTest(assembly=assembly):
                ir = analyze(parse_asm(assembly).instructions, arguments=0)
                primitive = ir.primitives[-1]
                self.assertEqual((primitive.inputs, primitive.outputs), expected)

    def test_incomplete_corpus_fixed_stack_shapes(self):
        cases = {
            'ABS': (("int",), ("int",)),
            'POW2': (("int",), ("int",)),
            'SREMPTY': (("slice",), ("int",)),
            'SDCNTLEAD0': (("slice",), ("int",)),
            'SDATASIZE': (("slice", "int"), ("int", "int", "int")),
            'STZEROES': (("builder", "int"), ("builder",)),
            'DICTSETB': (("builder", "slice", "cell", "int"), ("cell",)),
            'DICTADDB': (("builder", "slice", "cell", "int"), ("cell", "int")),
            'DICTDEL': (("slice", "cell", "int"), ("cell", "int")),
            'SDCUTFIRST': (("slice", "int"), ("slice",)),
            'SDCNTTRAIL1': (("slice",), ("int",)),
        }
        for opcode, expected in cases.items():
            with self.subTest(opcode=opcode):
                arguments = len(expected[0])
                ir = analyze(parse_asm(opcode).instructions, arguments=arguments,
                             argument_types_hint=expected[0])
                primitive = ir.primitives[-1]
                self.assertEqual((primitive.inputs, primitive.outputs), expected)

        fixed = analyze(parse_asm('4 LDSLICE').instructions, arguments=1,
                        argument_types_hint=('slice',)).primitives[-1]
        self.assertEqual((fixed.inputs, fixed.outputs), (("slice",), ("slice", "slice")))

    def test_empty_vector_branch_infers_the_filled_vector_type(self):
        ir = analyze(parse_asm('0 TUPLE\ns2 PUSH\nIF:<{\nNIP\n}>ELSE<{\nSWAP\nTPUSH\n}>').instructions,
                     arguments=2, argument_types_hint=('int', 'slice'))
        self.assertEqual(ir.returns[-1].type, 'vector_slice')

    def test_empty_vector_length_is_zero(self):
        ir = analyze(parse_asm('0 TUPLE\nTLEN').instructions, arguments=0)
        self.assertEqual(ir.returns[0].value, 0)
        generic = analyze(parse_asm('TLEN').instructions, arguments=1)
        self.assertEqual(generic.argument_types, ('tuple',))

    def test_mixed_case_debug_mnemonic_is_preserved(self):
        self.assertEqual(parse_asm('DUMPs0').instructions[0].opcode, 'DUMPs0')

    def test_rist255_wrappers_recompile_exactly(self):
        sources = (
            '() validate(int point) impure asm "RIST255_VALIDATE"; '
            '() recv_internal() { } int check(int point) impure method_id(100) '
            '{ validate(point); return 1; }',
            'int mulbase(int scalar) impure asm "RIST255_MULBASE"; '
            '() recv_internal() { } int multiply(int scalar) impure method_id(101) '
            '{ return mulbase(scalar); }',
        )
        for source in sources:
            with self.subTest(source=source[:30]):
                original = self.tools.compile(source)
                module = reconstruct(parse_asm(original.asm))
                self.assertTrue(all(f.assembly is None for f in module.functions))
                readable = render(module, readable=True)
                candidate = self.tools.compile(readable, version=original.version,
                                                flags=original.flags)
                self.assertEqual(original.code_hash, candidate.code_hash)

    def test_rist255_mulbase_vm_edges_match(self):
        source = ('int mulbase(int scalar) impure asm "RIST255_MULBASE"; '
                  '() recv_internal() { } int multiply(int scalar) impure method_id(101) '
                  '{ return mulbase(scalar); }')
        original = self.tools.compile(source)
        readable = render(reconstruct(parse_asm(original.asm)), readable=True)
        candidate = self.tools.compile(readable, version=original.version,
                                       flags=original.flags)
        fift, library = self.tools._fift()
        for scalar in ('0', '1', '-1', str(2 ** 256 - 1)):
            outputs = []
            for boc in (original.boc, candidate.boc):
                with tempfile.TemporaryDirectory() as directory:
                    Path(directory, 'code.boc').write_bytes(boc)
                    Path(directory, 'run.fif').write_text(
                        f'"Asm.fif" include {scalar} 101 "code.boc" file>B B>boc <s runvmcode .s')
                    outputs.append(_run([fift, '-I', library, '-s', 'run.fif'], directory).strip())
            self.assertEqual(outputs[0], outputs[1], scalar)

    def _compile_pair(self, source):
        original = self.tools.compile(source)
        module = reconstruct(parse_asm(original.asm))
        self.assertTrue(all(f.assembly is None for f in module.functions))
        readable = render(module, readable=True)
        candidate = self.tools.compile(readable, version=original.version,
                                       flags=original.flags)
        self.assertEqual(original.code_hash, candidate.code_hash)
        return original, candidate

    def _vm(self, boc, method):
        fift, library = self.tools._fift()
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'code.boc').write_bytes(boc)
            Path(directory, 'run.fif').write_text(
                f'"Asm.fif" include {method} "code.boc" file>B B>boc <s runvmcode .s')
            return _run([fift, '-I', library, '-s', 'run.fif'], directory).strip()

    def test_incomplete_corpus_primitives_recompile_exactly(self):
        cases = (
            'int operation(slice s) asm "SREMPTY";',
            'int operation(slice s) asm "SDCNTLEAD0";',
            'int operation(slice s) asm "SDCNTTRAIL1";',
            '(int,int,int) operation(slice s, int n) impure asm "SDATASIZE";',
            'builder operation(builder b, int n) impure asm "STZEROES";',
            '(slice,slice) operation(slice s) impure asm "4 LDSLICE";',
            'slice operation(slice s, int n) impure asm "SDCUTFIRST";',
            'cell operation(builder v, slice k, cell d, int n) impure asm(v k d n) "DICTSETB";',
            '(cell,int) operation(builder v, slice k, cell d, int n) impure asm(v k d n) "DICTADDB";',
            '(cell,int) operation(slice k, cell d, int n) impure asm(k d n) "DICTDEL";',
        )
        for index, declaration in enumerate(cases, 100):
            arguments = declaration.split('operation(', 1)[1].split(')', 1)[0]
            names = ', '.join(part.strip().split()[-1] for part in arguments.split(','))
            result = declaration.split(' operation', 1)[0]
            source = (f'{declaration} () recv_internal() {{ }} '
                      f'{result} example({arguments}) impure method_id({index}) '
                      f'{{ return operation({names}); }}')
            with self.subTest(declaration=declaration):
                self._compile_pair(source)

    def test_slice_and_dictionary_vm_empty_missing_present(self):
        cases = [
            ('''slice key() asm "x{03} PUSHSLICE";
                forall X -> X empty_cell() asm "PUSHNULL";
                cell put(slice v, int k, cell d, int n) impure asm(v k d n) "DICTUSET";
                (slice,int) get(slice k, cell d, int n) impure asm(k d n) "DICTGET" "NULLSWAPIFNOT";
                int prefix(slice a, slice b) asm(a b) "SDPFXREV";
                () recv_internal() { }
                int missing() method_id(114) { var (v,f) = get(key(), empty_cell(), 8); return f; }
                int present() method_id(115) { var d = put(key(), 3, empty_cell(), 8); var (v,f) = get(key(), d, 8); return f; }
                slice long() asm "x{0011} PUSHSLICE";
                slice short() asm "x{00} PUSHSLICE";
                slice other() asm "x{01} PUSHSLICE";
                int prefixes() method_id(116) { return prefix(long(), short()); }
                int nonprefix() method_id(121) { return prefix(long(), other()); }''',
             (114, 115, 116, 121), {114: 0, 115: -1, 116: -1, 121: 0}),
            ('''slice val() asm "x{aa} PUSHSLICE";
                slice key() asm "x{03} PUSHSLICE";
                forall X -> X empty_cell() asm "PUSHNULL";
                cell put(slice v, int k, cell d, int n) impure asm(v k d n) "DICTUSET";
                (cell,slice,slice,int) rem(cell d, int n) impure asm(d n) "DICTREMMIN" "NULLSWAPIFNOT2";
                int bits(slice s) asm "SBITS";
                () recv_internal() { }
                int empty() method_id(117) { var (d,v,k,f) = rem(empty_cell(), 8); return f; }
                int present() method_id(118) { var d = put(val(), 3, empty_cell(), 8); var (nd,v,k,f) = rem(d, 8); return f ? f + bits(v) + bits(k) : 0; }''',
             (117, 118), {117: 0, 118: 15}),
            ('''slice val() asm "x{aa} PUSHSLICE";
                forall X -> X empty_cell() asm "PUSHNULL";
                cell make() asm "NEWC ENDC";
                cell put(cell v, int k, cell d, int n) impure asm(v k d n) "DICTUSETREF";
                (cell,int,int) rem(cell d, int n) impure asm(d n) "DICTUMINREF" "NULLSWAPIFNOT2";
                () recv_internal() { }
                int empty() method_id(119) { var (v,k,f) = rem(empty_cell(), 8); return f; }
                int present() method_id(120) { var d = put(make(), 3, empty_cell(), 8); var (v,k,f) = rem(d, 8); return f; }''',
             (119, 120), {119: 0, 120: -1}),
        ]
        for source, methods, expected in cases:
            original, candidate = self._compile_pair(source)
            for method in methods:
                with self.subTest(method=method):
                    original_output = self._vm(original.boc, method)
                    self.assertEqual(original_output, self._vm(candidate.boc, method))
                    self.assertEqual(original_output.split(), [str(expected[method]), '0'])


if __name__ == "__main__":
    unittest.main()
