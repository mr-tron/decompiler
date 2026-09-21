"""Stdlib stack signatures and compiler-oracle regressions (no corpus rules)."""
import unittest
from pathlib import Path
import tempfile

from decompiler.asm import parse_asm
from decompiler.func import reconstruct, render
from decompiler.ir import UnsupportedInstruction, analyze
from decompiler.toolchain import Toolchain, _run


class StdlibIRTests(unittest.TestCase):
    def test_compound_stack_ops_against_official_vm(self):
        tools = Toolchain()
        if not tools.configs():
            self.skipTest("Run scripts/bootstrap.py for the official VM oracle")
        fift, library = tools._fift()
        # Alias-sensitive and negative adjusted-register encodings. VM outputs
        # are the oracle, independently of the symbolic permutation code.
        cases = ["s0 s0 XCPU", "s2 s(-1) PUXC", "s3 s3 PUSH2",
                 "s0 s0 s0 XCHG3", "s3 s2 s1 XC2PU", "s3 s2 s(-1) XCPUXC",
                 "s3 s2 s1 XCPU2", "s2 s(-1) s(-1) PUXC2",
                 "s2 s(-1) s(-1) PUXCPU", "s2 s(-1) s(-2) PU2XC", "s3 s3 s3 PUSH3"]
        with tempfile.TemporaryDirectory() as directory:
            for assembly in cases:
                with self.subTest(assembly=assembly):
                    Path(directory, "test.fif").write_text('"Asm.fif" include\n10 20 30 40 <{ ' + assembly + ' }>s runvmcode .s\n')
                    values = [int(value) for value in _run([fift, "-I", library, "-s", "test.fif"], directory).split()]
                    self.assertEqual(values.pop(), 0)
                    result = analyze(parse_asm(assembly).instructions, 4)
                    self.assertEqual([10 + int(value.value[3:]) * 10 for value in result.returns], values)

    def test_xchg2_sequential_aliases_and_blkdrop2(self):
        result = analyze(parse_asm("s0 s2 XCHG2").instructions, 4)
        self.assertEqual([v.value for v in result.returns], ["arg0", "arg2", "arg3", "arg1"])
        result = analyze(parse_asm("s3 s3 XCHG2\n1 2 BLKDROP2").instructions, 4)
        self.assertEqual([v.value for v in result.returns], ["arg3", "arg0", "arg2"])

    def test_stdlib_output_order_and_nullable_results(self):
        result = analyze(parse_asm("BALANCE\n1 INDEX").instructions)
        self.assertEqual(result.returns[0].type, "cell")
        result = analyze(parse_asm("LDMSGADDR\nLDGRAMS\nLDDICT").instructions)
        self.assertEqual(result.argument_types, ("slice",))
        self.assertEqual([v.type for v in result.returns], ["slice", "int", "cell", "slice"])
        result = analyze(parse_asm("DUP\nISNULL\nIFJMP:<{\nDROP\nPUSHNULL\n}>\nCTOS").instructions)
        self.assertEqual(result.argument_types, ("cell",))
        self.assertEqual(result.returns[0].type, "slice")
        early = next(s for s in result.statements if s.kind == "if").then[-1].values[0]
        self.assertEqual((early.value, early.type), ("null()", "slice"))

    def test_materialization_preserves_order_and_shared_values(self):
        code = "ADD\nDUP\n2 PUSHINT\nMUL\nSWAP\n1 PUSHINT\nIFJMP:<{\n}>"
        result = analyze(parse_asm(code).instructions)
        first, second, branch = result.statements
        self.assertEqual(first.values[1].args[0].value, "+")
        self.assertEqual(second.values[1].args[0].value, "*")
        self.assertEqual(second.values[1].args[0].args[0], first.values[0])
        self.assertEqual(result.returns, (second.values[0], first.values[0]))
        self.assertEqual(branch.kind, "if")
        with self.assertRaises(UnsupportedInstruction):
            analyze(parse_asm("DICTUGETREF").instructions)

    def test_optional_literal_scheduling_exact_roundtrip(self):
        tools = Toolchain()
        if not tools.configs():
            self.skipTest("Run scripts/bootstrap.py for the official compiler oracle")
        source = 'builder begin_cell() asm "NEWC"; cell end_cell(builder b) asm "ENDC"; () recv_internal() { } cell example() method_id(100) { return end_cell(store_uint(begin_cell(), 0, 2)); }'
        original = tools.compile(source)
        program = parse_asm(original.asm)
        module = reconstruct(program, preserve_constants={100})
        self.assertEqual(original.code_hash, tools.compile(render(module)).code_hash)

    def test_official_compiler_exact_stdlib_roundtrips(self):
        tools = Toolchain()
        if not tools.configs():
            self.skipTest("Run scripts/bootstrap.py for the official compiler oracle")
        examples = {
            "balance": '[int,cell] get_balance() asm "BALANCE"; int example() method_id(100) { var [coins, extra] = get_balance(); return coins; }',
            "address": '(int,int) parse_std_addr(slice s) asm "REWRITESTDADDR"; int example(slice s) method_id(100) { var (wc, addr) = parse_std_addr(s); return wc; }',
            "null": 'int cell_null?(cell c) asm "ISNULL"; int example(cell c) method_id(100) { return cell_null?(c); }',
            "load_address": '(slice,slice) load_msg_addr(slice s) asm( -> 1 0) "LDMSGADDR"; slice example(slice s) method_id(100) { return s~load_msg_addr(); }',
            "dict_lookup": '(cell,int) udict_get_ref?(cell d,int n,int k) asm(k d n) "DICTUGETREF" "NULLSWAPIFNOT"; cell example(cell d,int k) method_id(100) { var (c,found) = udict_get_ref?(d,256,k); return c; }',
            "pending_early_return": 'int example(int x,int t) method_id(100) { int y = x * 1000; if (t > 21) { return y; } repeat (t) { y = y * 90 / 100; } return y; }',
            "nullable_return": 'forall X -> X null() asm "PUSHNULL"; int cell_null?(cell c) asm "ISNULL"; slice begin_parse(cell c) asm "CTOS"; slice example(cell c) method_id(100) { if (cell_null?(c)) { return null(); } return begin_parse(c); }',
            "wide_muldiv": 'int example(int x, int y, int z) method_id(100) { return muldiv(x, y, z); }',
            "dictionary_update": 'cell udict_set_ref(cell d, int n, int k, cell v) asm(v k d n) "DICTUSETREF"; cell example(cell d, int k, cell v) method_id(100) { return udict_set_ref(d, 256, k, v); }',
            "dictionary_delete": '(cell, int) udict_delete?(cell d, int n, int k) asm(k d n) "DICTUDEL"; (cell, int) example(cell d, int k) method_id(100) { return udict_delete?(d, 256, k); }',
            "config": 'cell config_param(int n) asm "CONFIGOPTPARAM"; cell example(int n) method_id(100) { return config_param(n); }',
            "send": '() send_raw_message(cell c, int mode) impure asm "SENDRAWMSG"; () example(cell c, int mode) impure method_id(100) { send_raw_message(c, mode); }',
        }
        for name, source in examples.items():
            with self.subTest(name=name):
                original = tools.compile('() recv_internal() { } ' + source)
                module = reconstruct(parse_asm(original.asm))
                self.assertTrue(all(f.assembly is None for f in module.functions))
                self.assertEqual(original.code_hash, tools.compile(render(module)).code_hash)


if __name__ == "__main__":
    unittest.main()
