import unittest

from decompiler.asm import parse_asm
from decompiler.func import fallback_cells, render, render_parts
from decompiler.service import decompile
from decompiler.toolchain import Toolchain


class FiftDisplayTests(unittest.TestCase):
    def test_nested_instruction_display_leaves_compilable_source_unchanged(self):
        program = parse_asm('''SETCP0
19 DICTPUSHCONST
DICTIGETJMPZ {
50 => <{
c4 PUSH
CTOS
IF:<{
1 GETGLOB
}>ELSE<{
WHILE:<{
DUP
}>DO<{
1 SUB
}>
}>
}>
}
11 THROWARG''')
        module = fallback_cells(program, {50: bytes.fromhex('b5ee9c72')})
        source = render(module)
        display = render_parts(module, display_program=program)['contract']
        self.assertIn('method_50() impure method_id(50) fift {', display)
        self.assertIn('  PUSH c4\n  CTOS', display)
        self.assertIn('  } else {\n    WHILE {', display)
        self.assertIn('    } do {\n      SUB 1', display)
        self.assertNotIn('B{', display)
        self.assertNotIn('asm_method', display)
        self.assertEqual(source, render(module))
        self.assertIn('B{b5ee9c72}', source)

    def test_api_display_has_separate_format_and_verified_source(self):
        tools = Toolchain()
        if not tools.configs():
            self.skipTest('Official toolchain required')
        original = tools.compile('() op() impure asm "c3 PUSH c3 POP"; '
                                 '() recv_internal() impure { op(); }')
        result = decompile(original.boc, toolchain=tools, max_search_time_ms=3000)
        self.assertTrue(result['decompilation']['exact_hash_match'])
        self.assertEqual(result['display_format'], 'func-fift-pseudocode')
        self.assertIn('recv_internal() impure fift {', result['display_contract'])
        self.assertIn('PUSH c3', result['display_contract'])
        self.assertNotIn('fift {', result['func'])
        compiler = result['compiler']
        candidate = tools.compile(result['func'], compiler['selected_version'], compiler['flags'])
        self.assertEqual(candidate.code_hash, original.code_hash)
