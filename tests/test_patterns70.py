"""Small compiler and official-VM checks for general opcode lifts."""
from pathlib import Path
import tempfile
import unittest

from decompiler.asm import parse_asm
from decompiler.func import reconstruct, render
from decompiler.toolchain import Toolchain, _run


class PatternOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = Toolchain()
        if not cls.tools.configs():
            raise unittest.SkipTest("Run scripts/bootstrap.py for official VM checks")

    def vm(self, boc, arguments, method=100):
        fift, library = self.tools._fift()
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "code.boc").write_bytes(boc)
            Path(directory, "run.fif").write_text(
                f'"Asm.fif" include {arguments} {method} "code.boc" file>B B>boc <s runvmcode .s')
            return _run([fift, "-I", library, "-s", "run.fif"], directory).strip()

    def assert_vm_equivalent(self, source, argument_sets, method=100):
        original = self.tools.compile(source)
        module = reconstruct(parse_asm(original.asm))
        candidate = self.tools.compile(render(module, readable=True))
        for arguments in argument_sets:
            with self.subTest(arguments=arguments):
                self.assertEqual(self.vm(original.boc, arguments, method),
                                 self.vm(candidate.boc, arguments, method))

    def assert_exact_recompile(self, source):
        original = self.tools.compile(source)
        candidate = self.tools.compile(render(reconstruct(parse_asm(original.asm)), readable=True))
        self.assertEqual(original.code_hash, candidate.code_hash)

    def test_arithmetic_source_roundtrips_through_vm_oracle(self):
        self.assert_vm_equivalent(
            "() recv_internal() { } int example(int x) method_id(100) { return x * 3 + 7; }",
            ["0", "-9", "12", str(2**256 - 1)],
        )

    def test_common_slice_opcodes_roundtrip_through_vm_oracle(self):
        examples = [
            ('int digest(slice s) asm "SHA256U"; '
             '() recv_internal() { } int example(slice s) method_id(100) { return digest(s); }',
             ['x{}', 'x{00}', 'x{aabbccdd}']),
            ('(int, int) counts(slice s) asm "SBITREFS"; '
             '() recv_internal() { } int example(slice s) method_id(100) { '
             'var (bits, refs) = counts(s); return bits + refs; }',
             ['x{}', 'x{aabbccdd}']),
            ('slice substr(slice s, int start, int count) asm "SDSUBSTR"; '
             'int bits(slice s) asm "SBITS"; () recv_internal() { } '
             'int example(slice s, int start, int count) method_id(100) { '
             'return bits(substr(s, start, count)); }',
             ['x{aabbccdd} 0 8', 'x{aabbccdd} 8 16', 'x{aabbccdd} 24 8']),
            ('slice skip_dict(slice s) asm "SKIPDICT"; '
             'int bits(slice s) asm "SBITS"; () recv_internal() { } '
             'int example(slice s) method_id(100) { return bits(skip_dict(s)); }',
             ['x{00}', 'x{01}']),
        ]
        for source, inputs in examples:
            with self.subTest(source=source[:50]):
                self.assert_vm_equivalent(source, inputs)

    def test_global_null_check_preserves_untyped_global(self):
        from decompiler.ir import analyze

        ir = analyze(parse_asm('1 GETGLOB\nISNULL').instructions, arguments=0)
        self.assertEqual(ir.returns[0].type, 'int')
        self.assertEqual(ir.primitives[0].assembly, '1 GETGLOB ISNULL')
        self.assert_vm_equivalent(
            'int global_is_null() impure asm "1 GETGLOB ISNULL"; '
            '() recv_internal() { } int example() impure method_id(100) { return global_is_null(); }',
            [''],
        )

    def test_two_over_stack_order_matches_official_vm(self):
        from decompiler.ir import analyze

        result = analyze(parse_asm('2OVER').instructions, arguments=4)
        self.assertEqual([value.value for value in result.returns],
                         ['arg0', 'arg1', 'arg2', 'arg3', 'arg0', 'arg1'])
        fift, library = self.tools._fift()
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'run.fif').write_text(
                '"Asm.fif" include 10 20 30 40 <{ 2OVER }>s runvmcode .s')
            output = _run([fift, '-I', library, '-s', 'run.fif'], directory)
        self.assertEqual(output.split(), ['10', '20', '30', '40', '10', '20', '0'])

    def test_dictionary_add_and_delete_primitives_keep_stack_shapes(self):
        from decompiler.ir import analyze

        cases = [
            ('DICTUDELGET\nNULLSWAPIFNOT', 3, ('int', 'cell', 'int'),
             ('cell', 'slice', 'int'), 'DICTUDELGET NULLSWAPIFNOT'),
            ('DICTIDELGET\nNULLSWAPIFNOT', 3, ('int', 'cell', 'int'),
             ('cell', 'slice', 'int'), 'DICTIDELGET NULLSWAPIFNOT'),
            ('DICTUADD', 4, ('slice', 'int', 'cell', 'int'),
             ('cell', 'int'), 'DICTUADD'),
            ('DICTIADD', 4, ('slice', 'int', 'cell', 'int'),
             ('cell', 'int'), 'DICTIADD'),
        ]
        for assembly, arguments, inputs, outputs, expected_assembly in cases:
            with self.subTest(assembly=assembly):
                ir = analyze(parse_asm(assembly).instructions, arguments=arguments)
                primitive = ir.primitives[0]
                self.assertEqual((primitive.inputs, primitive.outputs, primitive.assembly),
                                 (inputs, outputs, expected_assembly))
                self.assertEqual(tuple(value.type for value in ir.returns), outputs)

        sources = [
            ('(cell, slice, int) op(int k, cell d, int n) impure asm(k d n) '
             '"DICTUDELGET" "NULLSWAPIFNOT"; () recv_internal() { } '
             'int example(int k, cell d) impure method_id(100) { '
             'var (nd, v, found) = op(k,d,256); return found; }'),
            ('(cell, slice, int) op(int k, cell d, int n) impure asm(k d n) '
             '"DICTIDELGET" "NULLSWAPIFNOT"; () recv_internal() { } '
             'int example(int k, cell d) impure method_id(100) { '
             'var (nd, v, found) = op(k,d,256); return found; }'),
            ('(cell, int) op(slice v, int k, cell d, int n) impure asm(v k d n) '
             '"DICTUADD"; () recv_internal() { } '
             'int example(slice v, int k, cell d) impure method_id(100) { '
             'var (nd, added) = op(v,k,d,256); return added; }'),
            ('(cell, int) op(slice v, int k, cell d, int n) impure asm(v k d n) '
             '"DICTIADD"; () recv_internal() { } '
             'int example(slice v, int k, cell d) impure method_id(100) { '
             'var (nd, added) = op(v,k,d,256); return added; }'),
        ]
        for source in sources:
            with self.subTest(source=source[:40]):
                self.assert_exact_recompile(source)

    def test_division_and_stateful_integer_primitives_recompile_exactly(self):
        from decompiler.ir import analyze

        cases = [
            ('DIVC', 2, ('int', 'int'), ('int',)),
            ('DIVR', 2, ('int', 'int'), ('int',)),
            ('SETRAND', 1, ('int',), ()),
            ('SETGASLIMIT', 1, ('int',), ()),
        ]
        for assembly, arguments, inputs, outputs in cases:
            with self.subTest(assembly=assembly):
                ir = analyze(parse_asm(assembly).instructions, arguments=arguments)
                self.assertEqual((ir.primitives[0].inputs, ir.primitives[0].outputs),
                                 (inputs, outputs))

        sources = [
            ('int op(int x, int y) asm "DIVC"; () recv_internal() { } '
             'int example(int x, int y) method_id(100) { return op(x,y); }'),
            ('int op(int x, int y) asm "DIVR"; () recv_internal() { } '
             'int example(int x, int y) method_id(100) { return op(x,y); }'),
            ('() set_seed(int x) impure asm "SETRAND"; () recv_internal() { } '
             'int example(int x) impure method_id(100) { set_seed(x); return 1; }'),
            ('() set_limit(int x) impure asm "SETGASLIMIT"; () recv_internal() { } '
             'int example(int x) impure method_id(100) { set_limit(x); return 1; }'),
        ]
        for source in sources:
            with self.subTest(source=source[:40]):
                self.assert_exact_recompile(source)

    def test_fee_and_current_code_primitives_keep_stack_shapes_and_recompile(self):
        from decompiler.ir import analyze

        cases = [
            ('GETGASFEE', 2, ('int', 'int'), ('int',)),
            ('GETSTORAGEFEE', 4, ('int', 'int', 'int', 'int'), ('int',)),
            ('GETFORWARDFEE', 3, ('int', 'int', 'int'), ('int',)),
            ('GETORIGINALFWDFEE', 2, ('int', 'int'), ('int',)),
            ('MYCODE', 0, (), ('cell',)),
        ]
        for assembly, arguments, inputs, outputs in cases:
            with self.subTest(assembly=assembly):
                ir = analyze(parse_asm(assembly).instructions, arguments=arguments)
                self.assertEqual((ir.primitives[0].inputs, ir.primitives[0].outputs),
                                 (inputs, outputs))

        sources = [
            ('int op(int gas, int master) impure asm(gas master) "GETGASFEE"; '
             '() recv_internal() { } int example(int gas, int master) impure '
             'method_id(100) { return op(gas,master); }'),
            ('int op(int cells, int bits, int delta, int master) impure '
             'asm(cells bits delta master) "GETSTORAGEFEE"; () recv_internal() { } '
             'int example(int cells, int bits, int delta, int master) impure '
             'method_id(100) { return op(cells,bits,delta,master); }'),
            ('int op(int cells, int bits, int master) impure asm(cells bits master) '
             '"GETFORWARDFEE"; () recv_internal() { } '
             'int example(int cells, int bits, int master) impure method_id(100) '
             '{ return op(cells,bits,master); }'),
            ('int op(int fee, int master) impure asm(fee master) "GETORIGINALFWDFEE"; '
             '() recv_internal() { } int example(int fee, int master) impure '
             'method_id(100) { return op(fee,master); }'),
            ('cell get_code() impure asm "MYCODE"; () recv_internal() { } '
             'cell example() impure method_id(100) { return get_code(); }'),
        ]
        for source in sources:
            with self.subTest(source=source[:40]):
                self.assert_exact_recompile(source)


if __name__ == "__main__":
    unittest.main()
