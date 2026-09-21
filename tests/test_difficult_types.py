"""Type-inference regressions reproduced from frozen development BOCs."""
from pathlib import Path
import unittest

from decompiler.asm import parse_asm
from decompiler.boc import method_cells
from decompiler.func import reconstruct_partial
from decompiler.ir import UnsupportedInstruction, analyze
from decompiler.toolchain import Toolchain


class DifficultTypeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tools = Toolchain()
        if not cls.tools.configs():
            raise unittest.SkipTest('Run scripts/bootstrap.py for corpus disassembly checks')
        cls.inputs = Path(__file__).resolve().parents[1] / 'research' / 'readable-30' / 'inputs'

    @classmethod
    def method(cls, contract, method_id):
        boc = (cls.inputs / f'{contract}.boc').read_bytes()
        return parse_asm(cls.tools.disassemble(boc)).methods[method_id]

    def test_while_body_types_outer_dictionary_argument(self):
        # Lottery shuffle_dict(cell dict, int key_len, int dict_size). The
        # loop condition sees only the integer size and counter; the body
        # establishes that the other carried slot is a cell via DICTUGET.
        ir = analyze(self.method('0023', 2))
        self.assertEqual(ir.argument_types, ('cell', 'int', 'int'))

    def test_unused_and_isnull_only_arguments_stay_polymorphic(self):
        # buy(var args) receives sender_address at slot 8 but never uses it.
        buy = analyze(self.method('0058', 5))
        self.assertEqual(buy.argument_types[8], 'X8')

        # lock() only tests old_lock_manager with ISNULL; that opcode works on
        # any TVM value and cannot establish a cell type on its own.
        isnull_only = analyze(parse_asm('ISNULL\nDROP').instructions)
        self.assertEqual(isnull_only.argument_types, ('X0',))

        # NFT lock() checks old_lock_manager only via ISNULL. Its extracted
        # helper must not guess that caller-supplied cell is an int.
        boc = (self.inputs / '0034.boc').read_bytes()
        program = parse_asm(self.tools.disassemble(boc))
        module, failures = reconstruct_partial(program, method_cells(boc))
        self.assertEqual(failures, [])
        lock_helper = next(f for f in module.functions if f.name == 'method_129616')
        self.assertEqual(lock_helper.arguments[5][0], 'X5')

    def test_receiver_abi_hint_types_context_tuple(self):
        # SplitBill assigns (bounced, sender, value, raw) to a global context.
        # Its third field comes from recv_internal's msg_value argument, which
        # is typed by the entrypoint ABI rather than an opcode in this prefix.
        code = self.method('0068', 0)[:27]
        with self.assertRaisesRegex(UnsupportedInstruction, 'Tuple element types are not known'):
            analyze(code, arguments=3)
        ir = analyze(code, arguments=3,
                     argument_types_hint=('int', 'cell', 'slice'))
        self.assertEqual(ir.argument_types, ('int', 'cell', 'slice'))
        self.assertEqual(ir.returns[-1].type, '[int, slice, int, slice]')


if __name__ == '__main__':
    unittest.main()
