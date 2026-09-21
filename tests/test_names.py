from dataclasses import replace
import unittest

from decompiler.func import Function, Module, _named_module, render
from decompiler.ir import Expr, Statement


def call(name, *args):
    return Expr('call', args, name)


def storage_loader(name='method_10', method_id=10):
    value = call('tvm_ldu_32', call('tvm_ldu_16', call('tvm_ctos', call('tvm_getdata'))))
    return Function(name, (), (value,), method_id=method_id, impure=True)


class NamingTests(unittest.TestCase):
    def test_storage_helpers_and_all_call_sites(self):
        loader = storage_loader()
        saver = Function('method_11', (('int', 'arg0'),), (),
                         (Statement('call', (call('tvm_setdata', call('tvm_endc',
                          call('tvm_stu_32', Expr('arg', value='arg0'), call('tvm_newc')))),)),), 11, True)
        caller = Function('method_20', (), (call(loader.name),),
                          (Statement('if', (Expr('literal', value=1),),
                           (Statement('call', (call(saver.name, Expr('literal', value=42)),)),)),), 20, True)
        source = render(Module((loader, saver, caller)))
        self.assertIn('load_data() impure method_id(10)', source)
        self.assertIn('store_data(int arg0) impure method_id(11)', source)
        self.assertIn('store_data(42);', source)
        self.assertIn('return load_data();', source)
        self.assertNotIn('method_10', source)
        self.assertNotIn('method_11', source)

    def test_ambiguous_helpers_and_non_storage_operations(self):
        loader = storage_loader()
        duplicate = storage_loader('method_12', 12)
        unrelated = replace(loader, name='method_13', method_id=13,
                            statements=(Statement('call', (call('tvm_sendrawmsg'),)),))
        collision = Function('load_data_10', (), ())
        named = _named_module(Module((loader, duplicate, unrelated, collision)))
        self.assertEqual([f.name for f in named.functions],
                         ['load_data_10_', 'load_data_12', 'method_13', 'load_data_10'])
        # Parsing an ordinary function argument is not loading persistent data.
        parser = replace(loader, arguments=(('slice', 'arg0'),))
        self.assertEqual(_named_module(Module((parser,))).functions[0].name, 'method_10')

    def test_scalar_storage_preload_is_not_named_load_data(self):
        value = call('tvm_pldu_64', call('tvm_ctos', call('tvm_getdata')))
        getter = Function('method_14', (), (value,), method_id=14, impure=True)
        self.assertEqual(_named_module(Module((getter,))).functions[0].name, 'method_14')

    def test_receiver_names_follow_tvm_entry_stack_for_every_arity(self):
        conventional = (('int', 'balance'), ('int', 'msg_value'),
                        ('cell', 'in_msg_full'), ('slice', 'in_msg_body'))
        for count in range(5):
            expected = conventional[-count:] if count else ()
            arguments = tuple((kind, f'arg{i}') for i, (kind, _) in enumerate(expected))
            values = tuple(Expr('arg', value=name, type=kind) for kind, name in arguments)
            original = Function('recv_internal', arguments, (), (Statement('call', (call('sink', *values),)),))
            named = _named_module(Module((original,))).functions[0]
            self.assertEqual(named.arguments, expected)
            self.assertEqual([v.value for v in named.statements[0].values[0].args], [n for _, n in expected])


if __name__ == '__main__':
    unittest.main()
