"""Official compiler and VM checks for the assisted 70-contract pass."""
import unittest
from decompiler.asm import parse_asm
from decompiler.func import reconstruct, render, resolve_references
from tests import test_patterns70 as oracle


class AssistedPatternTests(unittest.TestCase):
    setUpClass = classmethod(oracle.PatternOracleTests.setUpClass.__func__)
    vm = oracle.PatternOracleTests.vm
    assert_vm_equivalent = oracle.PatternOracleTests.assert_vm_equivalent

    def test_throw_discards_unreachable_instructions(self):
        self.assert_vm_equivalent(
            'int op(int x) impure asm "DUP IF:<{ 42 PUSHINT THROWANY SWAP }> INC"; '
            '() recv_internal() { } int example(int x) impure method_id(100) { return op(x); }',
            ['0', '1', '-3'])

    def test_empty_condition_loop_uses_body_result_as_next_flag(self):
        self.assert_vm_equivalent(
            'int op(int x) impure asm "1 PUSHINT WHILE:<{ }>DO<{ DEC DUP }>"; '
            '() recv_internal() { } int example(int x) impure method_id(100) { return op(x); }',
            ['1', '2', '10'])

    def test_loop_invariant_slice_is_not_inferred_as_integer(self):
        self.assert_vm_equivalent(
            'int bits(slice s) asm "SBITS"; () recv_internal() { } '
            'int example(slice s, int n) method_id(100) { while (n > 0) { n -= 1; } return bits(s); }',
            ['x{} 0', 'x{ab} 3'])

    def test_null_seeded_integer_list_roundtrips(self):
        source = ('forall X -> X null() asm "PUSHNULL"; '
                  'tuple cons(int head, tuple tail) asm "2 TUPLE"; '
                  '(int, tuple) uncons(tuple t) asm "2 UNTUPLE"; '
                  'int empty(tuple t) asm "ISNULL"; () recv_internal() { } '
                  'int example(int n) method_id(100) { tuple t = null(); '
                  'while (n > 0) { t = cons(n, t); n -= 1; } '
                  'int result = 0; while (~ empty(t)) { var (x, rest) = uncons(t); '
                  't = rest; result += x; } return result; }')
        self.assert_vm_equivalent(source, ['0', '1', '5'])

    def test_multiple_effectful_loop_condition_operations(self):
        self.assert_vm_equivalent(
            'int bits(slice s) impure asm "SBITS"; () recv_internal() { } '
            'int example(slice a, slice b, int n) method_id(100) { '
            'while ((bits(a) > n) & (bits(b) > n)) { n += 1; } return n; }',
            ['x{ab} x{abcd} 0', 'x{} x{ab} 0', 'x{ab} x{cd} 9'])

    def test_referenced_cell_preserves_nested_references(self):
        source = ('cell literal() asm "<b 171 8 u, <b 42 8 u, b> ref, b> PUSHREF"; '
                  '() recv_internal() { } cell example() method_id(100) { return literal(); }')
        original = self.tools.compile(source)
        candidate = self.tools.compile(render(reconstruct(resolve_references(
            parse_asm(original.asm), original.boc)), readable=True))
        self.assertEqual(original.code_hash, candidate.code_hash)
        self.assertEqual(self.vm(original.boc, ''), self.vm(candidate.boc, ''))

    def test_additional_primitive_shapes_and_rounding(self):
        from decompiler.ir import analyze
        for assembly, inputs, outputs in [
            ('INCOMINGVALUE', (), ('[int, cell]',)),
            ('GETPRECOMPILEDGAS', (), ('int',)), ('DUEPAYMENT', (), ('int',)),
            ('STORAGEFEES', (), ('int',)), ('GASCONSUMED', (), ('int',)),
            ('PLDREFVAR', ('slice', 'int'), ('cell',)),
            ('GETGASFEESIMPLE', ('int', 'int'), ('int',)),
            ('GETFORWARDFEESIMPLE', ('int', 'int', 'int'), ('int',)),
            ('STSLICE', ('slice', 'builder'), ('builder',)),
            ('BREMBITS', ('builder',), ('int',)), ('BREMREFS', ('builder',), ('int',)),
        ]:
            ir = analyze(parse_asm(assembly).instructions, arguments=len(inputs))
            self.assertEqual((ir.primitives[0].inputs, ir.primitives[0].outputs), (inputs, outputs))
        self.assert_vm_equivalent(
            'int capacity(builder b) asm "BREMBITS"; () recv_internal() { } '
            'int example(builder b) method_id(100) { return capacity(b); }',
            ['<b', '<b 1 8 u,'])
        for op in ('RSHIFTR#', 'RSHIFTC#'):
            self.assert_vm_equivalent(
                f'int shift(int x) asm "3 {op}"; () recv_internal() {{ }} '
                'int example(int x) method_id(100) { return shift(x); }',
                ['-17', '-4', '0', '3', '4', '17'])
        self.assert_vm_equivalent(
            'builder append(builder b) asm "x{ab} STSLICECONST"; cell end(builder b) asm "ENDC"; '
            '() recv_internal() { } cell example(builder b) method_id(100) { return end(append(b)); }',
            ['<b', '<b 1 8 u,'])

    def test_builder_append_order_and_slice_reference_load(self):
        for source, arguments in [
            ('builder append(builder a, builder b) asm "STB"; cell end(builder b) asm "ENDC"; '
             'cell example(builder a, builder b) method_id(100) { return end(append(a,b)); }',
             ['<b 1 8 u, <b 2 8 u,']),
            ('(slice,slice) load(slice s) asm "LDREFRTOS"; int bits(slice s) asm "SBITS"; '
             'int example(slice s) method_id(100) { var (a,b) = load(s); return bits(a) * 1000 + bits(b); }',
             ['<b 1 8 u, <b 2 16 u, b> ref, b> <s', 'x{}']),
            ('int prefix(slice a,slice b) asm "SDPPFXREV"; '
             'int example(slice a,slice b) method_id(100) { return prefix(a,b); }',
             ['x{abcd} x{ab}', 'x{ab} x{abcd}', 'x{ab} x{ab}']),
        ]:
            self.assert_vm_equivalent('() recv_internal() { } '+source, arguments)
