import unittest

from decompiler.asm import AsmError, Program, normalize_asm, parse_asm
from decompiler.func import candidates, reconstruct, reconstruct_partial, render, fallback, fallback_cells
from decompiler.ir import UnsupportedInstruction, analyze, build_cfg


def method_program(text):
    return parse_asm("SETCP0\n19 DICTPUSHCONST\nDICTIGETJMPZ {\n100 => <{\n" + text + "\n}>\n}\n11 THROWARG")


class IRTests(unittest.TestCase):
    def test_symbolic_stack_and_printing(self):
        code = parse_asm("2 PUSHINT\nSWAP\nSUB\n").instructions
        ir = analyze(code)
        self.assertEqual(ir.arguments, 1)
        self.assertEqual(ir.returns[0].args[0].value, 2)
        module = reconstruct(method_program("2 PUSHINT\nSWAP\nSUB"))
        self.assertIn("return (2 - arg0);", render(module))

    def test_real_stack_register_operations(self):
        ir = analyze(parse_asm("s1 PUSH\ns2 POP\n2DUP\n2DROP").instructions)
        self.assertEqual(ir.arguments, 2)
        self.assertEqual([value.value for value in ir.returns], ["arg0", "arg1"])
        ir = analyze(parse_asm("s0 s1 XCHG\nSUB").instructions)
        self.assertEqual([value.value for value in ir.returns[0].args], ["arg1", "arg0"])

    def test_continuation_join_and_cfg(self):
        program = parse_asm("PUSHCONT <{\n1 PUSHINT\n}>\nPUSHCONT <{\n2 PUSHINT\n}>\nIFELSE\n")
        ir = analyze(program.instructions)
        self.assertEqual(ir.arguments, 1)
        self.assertEqual(ir.returns[0].op, "select")
        cfg = build_cfg(program.instructions)
        self.assertEqual(len(cfg.blocks[0].successors), 2)
        self.assertFalse(cfg.unresolved)
        self.assertTrue(build_cfg(parse_asm("CALL:<{\n1 PUSHINT\n}>").instructions).unresolved)
        self.assertEqual(cfg.blocks[2].successors, cfg.blocks[3].successors)

    def test_safe_normalization_and_explicit_failures(self):
        self.assertEqual(normalize_asm("2 PUSHINT // hi\n"), normalize_asm(" 2   PUSHINT\n"))
        self.assertNotEqual(normalize_asm("2 PUSHINT"), normalize_asm("3 PUSHINT"))
        with self.assertRaises(AsmError):
            parse_asm("PUSHCONT <{\n1 PUSHINT")
        with self.assertRaises(UnsupportedInstruction):
            analyze(parse_asm("ALIENOP").instructions)
        discarded = analyze(parse_asm("ADD\nDROP").instructions)
        self.assertEqual(discarded.returns, ())
        self.assertEqual(discarded.statements[0].values[1].value, 'impure_touch')

    def test_ast_alternatives(self):
        module = reconstruct(method_program("ADD"))
        variants = list(candidates(module))
        self.assertEqual(len(variants), 2)
        self.assertNotEqual(render(variants[0]), render(variants[1]))
        self.assertEqual(len(list(candidates(module, method_ids={999}))), 1)
        self.assertEqual(len(list(candidates(module, method_ids={100}))), 2)

    def test_single_use_comparison_condition_has_no_touch_temporary(self):
        module = reconstruct(method_program('DUP\n7 EQINT\nIFJMP:<{\nDROP\n300 PUSHINT\n30 PUSHINT\n}>\nDROP\n0 PUSHINT\n0 PUSHINT'))
        source = render(module, readable=True)
        self.assertIn('if (arg0 == 7) {\n    return (300, 30);', source)
        self.assertNotIn('impure_touch', source)
        reused = render(reconstruct(method_program('7 EQINT\nDUP\nIFJMP:<{\n}>')))
        self.assertIn('impure_touch', reused)

    def test_official_disassembler_format_and_fallback(self):
        program = parse_asm("0 SETCP\n19 (xC_) DICTPUSHCONST\nDICTIGETJMPZ {\n0 => <{\nIF:<{\n42 THROW\n}>ELSE<{\n43 THROW\n}>\n}>\n}\n11 THROWARG\n")
        self.assertEqual(program.methods[0][0].opcode, "IFELSE")
        source = render(fallback(program))
        self.assertIn('"IF:<{"', source)
        self.assertIn("asm_recv_internal();", source)
        opaque = render(fallback_cells(program, {0: bytes.fromhex("b5ee9c72")}))
        self.assertIn("B{b5ee9c72} B>boc <s s,", opaque)
        self.assertIn("Opaque TVM method", opaque)
        with self.assertRaises(UnsupportedInstruction):
            fallback_cells(program, {})

    def test_structured_typed_loops_and_calls_exact_oracle(self):
        from decompiler.toolchain import Toolchain
        tools = Toolchain()
        if not tools.configs():
            self.skipTest("Run scripts/bootstrap.py for official compiler oracle")
        preamble = '() recv_internal() { } '
        cells = 'builder begin_cell() asm "NEWC"; cell end_cell(builder b) asm "ENDC"; '
        examples = {
            "builder": cells + 'cell example(int x) method_id(100) { return end_cell(store_uint(begin_cell(), x, 32)); }',
            "slice": 'slice begin_parse(cell c) asm "CTOS"; int example(cell c) method_id(100) { slice s = begin_parse(c); int x = s~load_uint(32); return x; }',
            "repeat": 'int example(int x, int n) method_id(100) { repeat (n) { x = x + 3; } return x; }',
            "while": 'int example(int x, int n) method_id(100) { while (n > 0) { x = x + 3; n -= 1; } return x; }',
            "conditional_effect": 'int example(int x) method_id(100) { if (x < 0) { throw(42); } return x + 1; }',
            "builder_phi": cells + 'cell example(int x) method_id(100) { builder b = begin_cell(); if (x) { b = store_uint(b, 3, 8); } else { b = store_uint(b, 9, 8); } return end_cell(b); }',
            "method_call": 'int twice(int x) { return x * 2; } int example(int x) method_id(100) { return twice(x) + 1; }',
            "typed_slice_loop": 'int slice_empty?(slice s) asm "SEMPTY"; int example(slice s) method_id(100) { int n = 0; while (~ slice_empty?(s)) { s~load_uint(8); n += 1; } return n; }',
        }
        for name, source in examples.items():
            with self.subTest(name=name):
                original = tools.compile(preamble + source)
                module = reconstruct(parse_asm(original.asm))
                self.assertTrue(all(function.assembly is None for function in module.functions))
                candidate = tools.compile(render(module))
                self.assertEqual(original.code_hash, candidate.code_hash)

        state = 'cell get_data() asm "c4 PUSH"; () set_data(cell c) impure asm "c4 POP"; () recv_internal() impure { set_data(get_data()); }'
        original = tools.compile(state)
        self.assertEqual(tools.compile(render(reconstruct(parse_asm(original.asm)))).code_hash, original.code_hash)

    def test_until_and_global_updates_against_official_vm(self):
        import tempfile
        from pathlib import Path
        from decompiler.toolchain import Toolchain, _run
        tools = Toolchain()
        if not tools.configs():
            self.skipTest('Run scripts/bootstrap.py for official VM checks')
        fift, library = tools._fift()
        examples = [
            'int example(int x) method_id(100) { do { x += 1; } until (x >= 3); return x; }',
            'global int counter; int example(int x) impure method_id(100) { counter = x + 1; counter += 3; return counter; }',
        ]
        for source in examples:
            original = tools.compile('() recv_internal() { } ' + source)
            module = reconstruct(parse_asm(original.asm))
            readable = render(module, readable=True)
            rebuilt = tools.compile(readable)
            with tempfile.TemporaryDirectory() as directory:
                Path(directory, 'original.boc').write_bytes(original.boc)
                Path(directory, 'rebuilt.boc').write_bytes(rebuilt.boc)
                for value in (-2, 0, 3, 8):
                    results = []
                    for name in ('original', 'rebuilt'):
                        Path(directory, 'run.fif').write_text(
                            f'"Asm.fif" include {value} 100 "{name}.boc" file>B B>boc <s runvmcode .s')
                        results.append(_run([fift, '-I', library, '-s', 'run.fif'], directory).strip())
                    self.assertEqual(results[0], results[1], readable)

    def test_static_helper_does_not_collide_with_low_method_ids(self):
        from decompiler.toolchain import Toolchain
        tools = Toolchain()
        if not tools.configs():
            self.skipTest('Run scripts/bootstrap.py for compiler checks')
        for tail in ('', '\nDROP\n9 PUSHINT'):
            program = method_program('CALL:<{\n1 PUSHINT\nADD\n}>' + tail)
            program.methods[1] = program.methods.pop(100)
            program.methods[0] = ()
            source = render(reconstruct(program), readable=True)
            self.assertNotIn('inline_ref', source)
            expected = ('return x + 1;' if not tail else 'preserve_value(x + 1); return 9;')
            reference = ('forall X -> X preserve_value(X x) impure asm "NOP"; () recv_internal() { } '
                         'int example(int x) impure method_id(1) { ' + expected + ' }')
            self.assertEqual(tools.compile(source).code_hash, tools.compile(reference).code_hash)

    def test_typed_primitive_inference_and_conflicts(self):
        ir = analyze(parse_asm("CTOS\n32 LDU\nDROP").instructions)
        self.assertEqual(ir.argument_types, ("cell",))
        self.assertEqual(ir.returns[0].type, "int")
        with self.assertRaises(UnsupportedInstruction):
            analyze(parse_asm("CTOS\nINC").instructions)

    def test_hybrid_keeps_readable_getters_and_unknown_callees_opaque(self):
        from decompiler.toolchain import Toolchain
        from decompiler.boc import method_cells
        tools = Toolchain()
        if not tools.configs():
            self.skipTest("Run scripts/bootstrap.py for official compiler oracle")
        source = '() opaque_operation() impure asm "c0 PUSH" "DROP"; () recv_internal() impure { opaque_operation(); } int example(int x) method_id(100) { return x + 1; }'
        original = tools.compile(source)
        debug = {}
        module, unsupported = reconstruct_partial(parse_asm(original.asm), method_cells(original.boc), debug)
        self.assertTrue(unsupported)
        self.assertIsNone(next(f for f in module.functions if f.name == "method_100").assembly)
        self.assertIsNotNone(next(f for f in module.functions if f.name == "recv_internal").assembly)
        self.assertIn("returns", debug["100"])
        self.assertEqual(debug["0"]["opcode"], "register")
        self.assertEqual(tools.compile(render(module)).code_hash, original.code_hash)
        dependent = '() opaque_operation() impure asm "c0 PUSH" "DROP"; () recv_internal() { } int helper(int x) impure { opaque_operation(); return x + 1; } int example(int x) impure method_id(100) { return helper(x); } int independent(int x) method_id(101) { return x + 2; }'
        original = tools.compile(dependent)
        module, unsupported = reconstruct_partial(parse_asm(original.asm), method_cells(original.boc))
        self.assertIsNotNone(next(f for f in module.functions if f.name == "method_100").assembly)
        self.assertIsNone(next(f for f in module.functions if f.name == "method_101").assembly)
        self.assertEqual(tools.compile(render(module)).code_hash, original.code_hash)


if __name__ == "__main__":
    unittest.main()
