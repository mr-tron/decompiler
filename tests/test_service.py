"""Real oracle regression: exact lifting, lossless cell fallback and worker API."""
import base64
import http.client
import json
import threading
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from decompiler.api import Server
from decompiler.asm import parse_asm
from decompiler.boc import BocError, code_hash, method_cells
from decompiler.func import fallback_cells, reconstruct, render
from decompiler.ir import Expr
from decompiler.service import decompile, _preserve_changed_methods
from decompiler.toolchain import Toolchain


class ServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = Toolchain()
        if not cls.tools.configs():
            raise unittest.SkipTest('Run scripts/bootstrap.py for real oracle tests')

    def test_structured_roundtrip_and_ambiguous_compiler(self):
        original = self.tools.compile('() recv_internal() impure { throw(42); }')
        result = decompile(original.boc, toolchain=self.tools)
        self.assertTrue(result['success'])
        self.assertTrue(result['decompilation']['exact_hash_match'])
        self.assertEqual(result['decompilation']['reconstruction_mode'], 'structured')
        self.assertNotIn('readable', result)
        self.assertIsNone(result['compiler']['version'])
        selected = result['compiler']
        candidate = self.tools.compile(result['func'], selected['selected_version'], selected['flags'])
        self.assertEqual(original.code_hash, candidate.code_hash)

    def test_readable_cleanup_cannot_replace_an_exact_candidate(self):
        original = self.tools.compile('() recv_internal() impure { throw(42); } '
                                      'int method_100(int x) method_id(100) { return x + 1; }')

        def changed(module):
            functions = list(module.functions)
            index = next(i for i, function in enumerate(functions) if function.method_id == 100)
            functions[index] = replace(functions[index], returns=(Expr('literal', value=7),))
            return replace(module, functions=tuple(functions))

        with patch('decompiler.service.readable_module', side_effect=changed):
            result = decompile(original.boc, toolchain=self.tools)
        self.assertTrue(result['decompilation']['exact_hash_match'])
        self.assertNotIn('readable', result)

    def test_generic_binary_with_literal_does_not_specialize(self):
        original = self.tools.compile('int seven() asm "7 PUSHINT"; '
                                      '() recv_internal() impure { throw(42); } '
                                      'int method_100(int x) method_id(100) { return x == seven(); }')
        result = decompile(original.boc, toolchain=self.tools)
        chosen = result.get('readable') or result
        self.assertTrue(chosen['decompilation']['exact_hash_match'])
        self.assertIn('asm "EQUAL"', chosen['stdlib'])

    def test_lossless_method_cell_extraction_and_reassembly(self):
        source = '''
        builder begin_cell() asm "NEWC";
        builder put_uint(builder b, int x, int n) asm(x b n) "STUX";
        cell end_cell(builder b) asm "ENDC";
        cell constant_cell() asm "<b 123 32 u, b> PUSHREF";
        () recv_internal() impure { throw(42); }
        cell method_101() method_id(101) { return constant_cell(); }
        cell method_100(int arg0) method_id(100) {
          return begin_cell().put_uint(arg0, 32).end_cell();
        }
        '''
        original = self.tools.compile(source)
        cells = method_cells(original.boc)
        self.assertEqual(set(cells), {0, 100, 101})
        self.assertTrue(all(code_hash(cell) for cell in cells.values()))
        candidate_source = render(fallback_cells(parse_asm(original.asm), cells))
        candidate = self.tools.compile(candidate_source)
        self.assertEqual(original.code_hash, candidate.code_hash)
        with self.assertRaises(BocError):
            method_cells(bytes.fromhex('b5ee9c72010101010002000000'))

    def test_four_reference_method_keeps_its_cell_layout(self):
        declarations = '\n'.join(f'cell c{i}() impure asm "<b {i} 8 u, b> PUSHREF";' for i in range(4))
        original = self.tools.compile(declarations + '\n() recv_internal() impure { c0(); c1(); c2(); c3(); }')
        cells = method_cells(original.boc)
        from decompiler.boc import parse_boc
        self.assertEqual(len(parse_boc(cells[0]).cells[0].refs), 4)
        candidate = self.tools.compile(render(fallback_cells(parse_asm(original.asm), cells)))
        self.assertEqual(original.code_hash, candidate.code_hash)

    def test_partial_recovery_preserves_callee_signature_and_high_level_callers(self):
        original = self.tools.compile('''
        () recv_internal() impure { throw(42); }
        int method_100(int x) impure method_id(100) { return x + 1; }
        int method_101(int x) impure method_id(101) { return method_100(x); }
        int method_102(int x) impure method_id(102) { return x + 3; }
        ''')
        program = parse_asm(original.asm)
        module = reconstruct(program)
        changed = replace(module, functions=tuple(
            replace(f, returns=(Expr('literal', value=9),)) if f.method_id == 100 else f
            for f in module.functions))
        compiled = self.tools.compile(render(changed))
        repaired = _preserve_changed_methods(changed, program, method_cells(original.boc), compiled.boc)
        self.assertEqual({f.method_id for f in repaired.functions if f.assembly is not None}, {100})
        self.assertEqual(self.tools.compile(render(repaired)).code_hash, original.code_hash)

    def test_readable_hybrid_survives_exact_assembly_fallback(self):
        source = ('() opaque() impure asm "c0 PUSH" "DROP"; '
                  '() recv_internal() impure { opaque(); } '
                  'int example(int x) method_id(100) { do { x += 1; } until (x > 5); return x; }')
        original = self.tools.compile(source)
        result = decompile(original.boc, toolchain=self.tools)
        self.assertTrue(result['decompilation']['exact_hash_match'])
        readable = result['readable']
        self.assertEqual(readable['decompilation']['structured_method_count'], 1)
        self.assertEqual(readable['decompilation']['reconstruction_mode'], 'hybrid')
        self.assertIn('do {', readable['contract'])
        self.assertIn('asm_recv_internal', readable['contract'])
        self.assertTrue(readable['decompilation']['recompiles'])

    def test_reported_stdlib_contract_keeps_verified_high_level_methods(self):
        boc = base64.b64decode((Path(__file__).parent / 'data/stdlib_contract.b64').read_text())
        result = decompile(boc, toolchain=self.tools)
        self.assertTrue(result['success'], result)
        metrics = result['decompilation']
        self.assertTrue(metrics['exact_hash_match'])
        self.assertGreaterEqual(metrics['structured_method_count'], 14)
        self.assertFalse(set(metrics['unsupported_instructions']) &
                         {'BALANCE', 'REWRITESTDADDR', 'ISNULL', 'XCHG2', 'LDMSGADDR', 'IFJMP'})
        selected = result['compiler']
        self.assertEqual(self.tools.compile(result['func'], selected['selected_version'], selected['flags']).code_hash,
                         code_hash(boc))
        self.assertIn('recv_internal', result['contract'])
        self.assertNotIn('recv_internal', result['stdlib'])
        self.assertIn('begin_cell', result['stdlib'])
        separated = {'contract.fc': '#include "stdlib.fc";\n' + result['contract'],
                     'stdlib.fc': result['stdlib']}
        self.assertEqual(self.tools.compile(separated, selected['selected_version'], selected['flags'],
                                           entrypoints=['contract.fc']).code_hash, code_hash(boc))
        readable = result['readable']
        self.assertEqual(readable['decompilation']['structured_method_count'], 15)
        self.assertTrue(readable['decompilation']['recompiles'])
        self.assertFalse(readable['decompilation']['exact_hash_match'])
        self.assertEqual(readable['decompilation']['quality'], 'unverified')
        self.assertIn('recv_internal(int msg_value, cell in_msg_full, slice in_msg_body)', readable['contract'])
        for source in (result['contract'], readable['contract']):
            self.assertIn('load_data() impure method_id(10)', source)
            self.assertIn('store_data(', source)
            self.assertNotIn('method_10(', source)
            self.assertNotIn('method_11(', source)
        self.assertIn('send_raw_message(', readable['contract'])
        self.assertNotIn('asm_recv_internal', readable['contract'])
        self.assertRegex(readable['contract'], r'if \(tvm_equal\(v[0-9]+, 0x2fcb26a2\)\)')
        self.assertIn('~skip_bits(1);', readable['contract'])
        self.assertIn('set_data(\n      begin_cell()\n          .store_uint(arg0, 256)', readable['contract'])
        self.assertIn('.store_ref(arg3)', readable['contract'])
        self.assertIn('.store_dict(arg5)', readable['contract'])
        self.assertIn('.store_uint(arg6, 64)\n          .end_cell()', readable['contract'])
        self.assertNotIn('save_data(', readable['contract'])
        self.assertIn('~load_msg_addr();', readable['contract'])
        self.assertIn('~load_coins();', readable['contract'])
        self.assertIn('0x8b771735', readable['contract'])
        self.assertIn('if (arg0 == 7)', readable['contract'])
        self.assertNotIn('impure_touch(801842850)', readable['contract'])
        self.assertNotIn('tvm_touch', readable['func'])
        self.assertIn('impure_touch', readable['stdlib'])
        compiler = readable['compiler']
        candidate = self.tools.compile(readable['func'], compiler['selected_version'], compiler['flags'])
        self.assertEqual(candidate.code_hash, readable['decompilation']['candidate_code_hash'])
        self.assertNotEqual(candidate.code_hash, code_hash(boc))

    def test_isolated_worker(self):
        original = self.tools.compile('() recv_internal() impure { throw(42); }')
        with Server(('127.0.0.1', 0)) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                connection = http.client.HTTPConnection(*server.server_address, timeout=20)
                connection.request('POST', '/v1/decompile',
                                   json.dumps({'code': base64.b64encode(original.boc).decode()}),
                                   {'Content-Type': 'application/json'})
                response = connection.getresponse()
                result = json.loads(response.read())
                self.assertEqual(response.status, 200, result)
                self.assertTrue(result['decompilation']['exact_hash_match'])
                connection.close()
            finally:
                server.shutdown()
                thread.join(2)


if __name__ == '__main__':
    unittest.main()
