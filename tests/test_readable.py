import unittest

from decompiler.func import Function, Module, _builder_chains, expression, readable_module, render
from decompiler.ir import Expr, Primitive, Statement
from decompiler.toolchain import Toolchain


def local(n, kind='slice'):
    return Expr('local', value=f'v{n}', type=kind)


def load(n, source, name='tvm_ldgrams', kind='int'):
    return Statement('assign', (Expr('product', (local(n, kind), local(n + 1))),
                                Expr('call', (source,), name)))


PRIMITIVES = (Primitive('tvm_ldgrams', ('slice',), ('int', 'slice'), 'LDGRAMS'),
              Primitive('tvm_ldmsgaddr', ('slice',), ('slice', 'slice'), 'LDMSGADDR'),
              Primitive('tvm_sdskipfirst', ('slice', 'int'), ('slice',), 'SDSKIPFIRST'))
ARG = Expr('arg', value='arg0', type='slice')


def module(body, returns):
    return Module((Function('method_100', (('slice', 'arg0'),), returns, tuple(body), 100, True),
                   Function('recv_internal', (), ())), PRIMITIVES)


class ReadableTests(unittest.TestCase):
    def test_slice_chain_discards_and_renumbers_with_compiler_oracle(self):
        skip = Expr('call', (local(4), Expr('literal', value=1)), 'tvm_sdskipfirst', 'slice')
        original = module([load(1, ARG, 'tvm_ldmsgaddr', 'slice'), load(3, local(2)),
                           load(5, skip), load(7, local(6))], (local(8), local(7, 'int')))
        source = render(original, readable=True)
        self.assertIn('v0~load_msg_addr();\n  v0~load_coins();\n  v0~skip_bits(1);\n  v0~load_coins();\n  var v1 = v0~load_coins();', source)
        self.assertIn('return (v0, v1);', source)
        self.assertNotIn('_raw', source)
        tools = Toolchain()
        self.assertEqual(tools.compile(render(original)).code_hash, tools.compile(source).code_hash)

    def test_shared_slice_and_loop_keep_original_value(self):
        original = module([load(1, ARG), load(3, local(2))], (local(2), local(4)))
        source = render(original, readable=True)
        self.assertIn('var v1 = v0;', source)
        self.assertIn('return (v0, v1);', source)
        loop = module([Statement('assign', (local(0), ARG)),
                       Statement('repeat', (Expr('literal', value=2),), (load(1, local(0)),))], ())
        source = render(loop, readable=True)
        self.assertIn('repeat (2) {\n    var v0 = arg0;\n    v0~load_coins();', source)
        Toolchain().compile(source)

    def test_unused_product_results_use_placeholders_without_numbers(self):
        original = module([load(20, ARG)], (local(20, 'int'),))
        # A generic multi-result call cannot use modifying slice syntax.
        original = Module(original.functions, ())
        cleaned = readable_module(original)
        statement = cleaned.functions[0].statements[0]
        self.assertEqual(statement.values[0].args[0].value, 'v0')
        self.assertEqual(statement.values[0].args[1].value, '_')

    def test_unused_arithmetic_still_executes(self):
        division = Expr('binary', (Expr('literal', value=1), Expr('literal', value=0)), '/')
        original = module([Statement('assign', (local(99, 'int'), division))], ())
        source = render(original, readable=True)
        self.assertIn('impure_touch((1 / 0));', source)
        self.assertNotIn('var v', source)

    def test_builder_chain_compiler_oracle_and_operand_order(self):
        def call(name, *args, kind='builder'):
            return Expr('call', args, name, kind)
        arg = Expr('arg', value='arg0', type='cell')
        value = call('tvm_newc')
        value = call('tvm_stu_16', Expr('literal', value=42), value)
        value = call('tvm_stref', arg, value)
        value = call('tvm_stdict', arg, value)
        value = call('tvm_sti_5', Expr('literal', value=-1), value)
        value = call('tvm_endc', value, kind='cell')
        primitives = (Primitive('tvm_newc', (), ('builder',), 'NEWC'),
                      Primitive('tvm_stu_16', ('int', 'builder'), ('builder',), '16 STU'),
                      Primitive('tvm_sti_5', ('int', 'builder'), ('builder',), '5 STI'),
                      Primitive('tvm_stref', ('cell', 'builder'), ('builder',), 'STREF'),
                      Primitive('tvm_stdict', ('cell', 'builder'), ('builder',), 'STDICT'),
                      Primitive('tvm_endc', ('builder',), ('cell',), 'ENDC'))
        original = Module((Function('method_100', (('cell', 'arg0'),), (value,), method_id=100),
                           Function('recv_internal', (), ())), primitives)
        source = render(original, readable=True)
        self.assertIn('.store_uint(42, 16)', source)
        self.assertIn('.store_int(-1, 5)', source)
        self.assertIn('.store_ref(arg0)', source)
        self.assertIn('.store_dict(arg0)', source)
        self.assertIn('.end_cell()', source)
        self.assertNotIn('_raw', source)
        tools = Toolchain()
        self.assertEqual(tools.compile(source).code_hash, tools.compile(render(original)).code_hash)
        effectful = call('tvm_stu_16', call('tvm_now', kind='int'), call('tvm_newc'))
        self.assertEqual(_builder_chains(effectful), effectful)
        discarded = Statement('call', (call('tvm_stu_16', Expr('literal', value=65536), call('tvm_newc')),))
        self.assertEqual(_builder_chains(discarded), discarded)

    def test_hex_threshold(self):
        for value, expected in [(2**29 - 1, '536870911'), (2**29, '536870912'),
                                (2**29 + 1, '0x20000001'),
                                (1546300799, hex(1546300799)), (1546300800, '1546300800'),
                                (1700000000, '1700000000'), (1893456000, '1893456000'),
                                (1893456001, hex(1893456001)),
                                (2**31 - 1, '0x7fffffff'), (2**31, '0x80000000'),
                                (2**31 + 1, '0x80000001'), (2**256 - 1, '0x' + 'f' * 64),
                                (-2**32, '-4294967296')]:
            self.assertEqual(expression(Expr('literal', value=value)), expected)
        tools = Toolchain()
        original = module([], (Expr('literal', value=2**31 + 1),))
        source = render(original)
        self.assertEqual(tools.compile(source).code_hash,
                         tools.compile(source.replace('0x80000001', '2147483649')).code_hash)


if __name__ == '__main__':
    unittest.main()
