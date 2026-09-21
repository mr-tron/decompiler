import unittest

from decompiler.asm import parse_asm
from decompiler.func import primitive_name
from decompiler.ir import StackUnderflow, UnsupportedInstruction, analyze


class CorpusOpcodeTests(unittest.TestCase):
    def test_ends_consumes_slice_and_preserves_empty_slice_check(self):
        ir = analyze(parse_asm('ENDS').instructions, arguments=1)
        self.assertEqual(ir.argument_types, ('slice',))
        self.assertEqual(ir.returns, ())
        self.assertEqual(ir.statements[0].values[0].value, 'tvm_ends')

    def test_hashcu_takes_cell_and_returns_hash(self):
        ir = analyze(parse_asm('NEWC\nENDC\nHASHCU').instructions)
        self.assertEqual(ir.argument_types, ())
        self.assertEqual(ir.returns[0].type, 'int')
        self.assertEqual(ir.statements[-1].values[1].value, 'tvm_hashcu')
        self.assertEqual(primitive_name('tvm_hashcu'), 'cell_hash')
        self.assertEqual(primitive_name('tvm_plddict'), 'preload_dict')
        with self.assertRaises(UnsupportedInstruction):
            analyze(parse_asm('CTOS\nHASHCU').instructions)

    def test_rotrev_and_equivalent_blkswap_preserve_the_stack_order(self):
        prefix = '1 PUSHINT\n2 PUSHINT\n3 PUSHINT\n'
        rotated = analyze(parse_asm(prefix + 'ROTREV').instructions, arguments=0)
        swapped = analyze(parse_asm(prefix + '2 1 BLKSWAP').instructions, arguments=0)
        expected = [3, 1, 2]
        self.assertEqual([value.value for value in rotated.returns], expected)
        self.assertEqual([value.value for value in swapped.returns], expected)

    def test_blkswap_rejects_missing_stack_values(self):
        with self.assertRaises(StackUnderflow):
            analyze(parse_asm('1 PUSHINT\n2 1 BLKSWAP').instructions, arguments=0)

    def test_effectful_actions_keep_their_verified_stack_types(self):
        examples = {
            '1 PUSHINT\n2 PUSHINT\nRAWRESERVE': ('tvm_rawreserve', ('int', 'int'), ()),
            'NEWC\nENDC\nSETCODE': ('tvm_setcode', ('cell',), ()),
            'NEWC\nENDC\n0 PUSHINT\nSETLIBCODE': ('tvm_setlibcode', ('cell', 'int'), ()),
        }
        for source, (name, inputs, outputs) in examples.items():
            with self.subTest(opcode=name):
                ir = analyze(parse_asm(source).instructions, arguments=0)
                primitive = next(p for p in ir.primitives if p.name == name)
                self.assertEqual((primitive.inputs, primitive.outputs), (inputs, outputs))

    def test_additional_scalar_and_cell_operators_have_typed_results(self):
        examples = {
            '1 PUSHINT\n2 PUSHINT\nMIN': ('tvm_min', ('int', 'int'), ('int',)),
            '1 PUSHINT\n2 PUSHINT\nMAX': ('tvm_max', ('int', 'int'), ('int',)),
            'PUSHSLICE x{}\nSDEPTH': ('tvm_sdepth', ('slice',), ('int',)),
            'NEWC\nENDC\nCDEPTH': ('tvm_cdepth', ('cell',), ('int',)),
            '1 PUSHINT\nRAND': ('tvm_rand', ('int',), ('int',)),
            '1 PUSHINT\nADDRAND': ('tvm_addrand', ('int',), ()),
            'NEWC\nENDC\n1 PUSHINT\nCDATASIZE': ('tvm_cdatasize', ('cell', 'int'), ('int', 'int', 'int')),
        }
        for source, (name, inputs, outputs) in examples.items():
            with self.subTest(opcode=name):
                ir = analyze(parse_asm(source).instructions, arguments=0)
                primitive = next(p for p in ir.primitives if p.name == name)
                self.assertEqual((primitive.inputs, primitive.outputs), (inputs, outputs))

    def test_dynamic_slice_loads_preserve_their_output_shapes(self):
        cases = {
            'PUSHSLICE x{ff}\n8 PUSHINT\nLDUX': ('tvm_ldux', ('int', 'slice')),
            'PUSHSLICE x{ff}\n8 PUSHINT\nLDIX': ('tvm_ldix', ('int', 'slice')),
            'PUSHSLICE x{ff}\n8 PUSHINT\nPLDUX': ('tvm_pldux', ('int',)),
            'PUSHSLICE x{ff}\n8 PUSHINT\nPLDIX': ('tvm_pldix', ('int',)),
            'PUSHSLICE x{ff}\n8 PUSHINT\nPLDSLICEX': ('tvm_pldslicex', ('slice',)),
        }
        for source, (name, result_types) in cases.items():
            with self.subTest(opcode=name):
                ir = analyze(parse_asm(source).instructions, arguments=0)
                self.assertEqual(tuple(value.type for value in ir.returns), result_types)
                self.assertEqual(next(p for p in ir.primitives if p.name == name).inputs,
                                 ('slice', 'int'))

    def test_tuck_ifret_and_throw_anyif_keep_control_and_stack_order(self):
        tucked = analyze(parse_asm('1 PUSHINT\n2 PUSHINT\nTUCK').instructions, arguments=0)
        self.assertEqual([value.value for value in tucked.returns], [2, 1, 2])

        early = analyze(parse_asm('DUP\nIFRET\n0 PUSHINT\nDROP').instructions)
        self.assertEqual(early.returns[0].value, 'arg0')
        self.assertEqual(early.statements[0].then[0].kind, 'return')

        throwing = analyze(parse_asm('71 PUSHINT\nDUP\nTHROWANYIF\n0 PUSHINT').instructions,
                           arguments=0)
        self.assertEqual(next(p for p in throwing.primitives if p.name == 'tvm_throwanyif').inputs,
                         ('int', 'int'))

    def test_global_reads_require_a_previously_established_type(self):
        read = analyze(parse_asm('1 PUSHINT\n1 SETGLOB\n1 GETGLOB').instructions,
                       arguments=0)
        self.assertEqual(read.returns[0].type, 'int')
        self.assertEqual(primitive_name('tvm_getglob_1'), 'get_global_1')
        self.assertEqual(primitive_name('tvm_setglob_1'), 'set_global_1')
        for source, arguments in [('1 GETGLOB', 0), ('1 SETGLOB\n1 GETGLOB', 1)]:
            with self.subTest(source=source), self.assertRaises(UnsupportedInstruction):
                analyze(parse_asm(source).instructions, arguments=arguments)

    def test_round_two_signatures_and_typed_tuple_indexing(self):
        cases = {
            '1 PUSHINT\nNEWC\n8 PUSHINT\nSTUX':
                ('tvm_stux', ('int', 'builder', 'int'), ('builder',)),
            '1 PUSHINT\nNEWC\n8 PUSHINT\nSTIX':
                ('tvm_stix', ('int', 'builder', 'int'), ('builder',)),
            '10 PUSHINT\n3 PUSHINT\nDIVMOD':
                ('tvm_divmod', ('int', 'int'), ('int', 'int')),
            'PUSHSLICE x{}\nPUSHSLICE x{}\n1 PUSHINT\nCHKSIGNS':
                ('tvm_chksigns', ('slice', 'slice', 'int'), ('int',)),
            'NEWC\nENDC\n8 PUSHINT\nNEWC\nENDC\n8 PUSHINT\nDICTISETGETOPTREF':
                ('tvm_dictisetgetoptref', ('cell', 'int', 'cell', 'int'), ('cell', 'cell')),
        }
        for source, expected in cases.items():
            with self.subTest(source=source):
                ir = analyze(parse_asm(source).instructions, arguments=0)
                primitive = next(p for p in ir.primitives if p.name == expected[0])
                self.assertEqual((primitive.inputs, primitive.outputs), expected[1:])

        indexed = analyze(parse_asm(
            '1 PUSHINT\n2 PUSHINT\n3 PUSHINT\nTRIPLE\nSECOND').instructions,
            arguments=0)
        index = next(p for p in indexed.primitives if p.name == 'tvm_index_1')
        self.assertEqual((index.inputs, index.outputs), (('[int, int, int]',), ('int',)))
        self.assertEqual(indexed.returns[0].type, 'int')
        unpacked = analyze(parse_asm(
            '1 PUSHINT\n2 PUSHINT\n3 PUSHINT\nTRIPLE\n3 UNTUPLE').instructions,
            arguments=0)
        self.assertEqual(tuple(value.type for value in unpacked.returns), ('int', 'int', 'int'))

    def test_dictionary_iteration_requires_paired_result_padding(self):
        minimum = analyze(parse_asm('NEWC\nENDC\n16 PUSHINT\nDICTUMIN\nNULLSWAPIFNOT2').instructions,
                          arguments=0)
        primitive = next(p for p in minimum.primitives if p.name == 'tvm_dictumin')
        self.assertEqual((primitive.inputs, primitive.outputs),
                         (('cell', 'int'), ('slice', 'int', 'int')))
        self.assertEqual(primitive_name('tvm_dictumin'), 'udict_get_min_raw')

        following = analyze(parse_asm(
            '32 PUSHINT\nNEWC\nENDC\n16 PUSHINT\nDICTUGETNEXTEQ\nNULLSWAPIFNOT2').instructions,
            arguments=0)
        primitive = next(p for p in following.primitives if p.name == 'tvm_dictugetnexteq')
        self.assertEqual(primitive.inputs, ('int', 'cell', 'int'))
        with self.assertRaises(UnsupportedInstruction):
            analyze(parse_asm('NEWC\nENDC\n16 PUSHINT\nDICTUMIN').instructions,
                    arguments=0)

    def test_wallet_primitive_aliases_match_their_stack_operations(self):
        aliases = {
            'tvm_xctos': 'begin_parse_raw',
            'tvm_dictuaddb': 'udict_add_builder_raw',
            'tvm_sdcnttrail0': 'count_trailing_zeroes',
            'tvm_hashsu': 'slice_hash',
            'tvm_chksignu': 'check_signature',
            'tvm_accept': 'accept_message',
            'tvm_commit': 'commit',
            'tvm_setc5': 'set_actions',
            'tvm_sdcutlast': 'get_last_bits',
            'tvm_sdskiplast': 'remove_last_bits',
            'tvm_ldslicex': 'load_bits_raw',
            'tvm_pldslice_16': 'preload_bits_16',
            'tvm_pldrefidx_0': 'preload_ref',
            'tvm_pldrefidx_2': 'preload_ref_2',
            'tvm_sdbegins_abcd': 'remove_prefix_abcd',
            'tvm_sdbeginsq_abcd': 'remove_prefix_abcd_quiet',
            'tvm_sdbeginsq_02': 'remove_prefix_02_quiet',
            'tvm_sdbeginsq_03': 'remove_prefix_03_quiet',
            'tvm_rawreserve': 'raw_reserve',
            'tvm_setcode': 'set_code',
            'tvm_sdepth': 'slice_depth',
            'tvm_cdepth': 'cell_depth',
            'tvm_rand': 'random',
            'tvm_addrand': 'add_random_seed',
            'tvm_cdatasize': 'cell_data_size_raw',
            'tvm_dictigetoptref': 'idict_get_opt_ref_raw',
            'tvm_dictugetoptref': 'udict_get_opt_ref_raw',
            'tvm_dictisetb': 'idict_set_builder_raw',
            'tvm_dictusetb': 'udict_set_builder_raw',
            'tvm_throwanyif': 'throw_any_if_raw',
            'tvm_throwanyifnot': 'throw_any_if_not_raw',
            'tvm_ldux': 'load_uint_raw',
            'tvm_ldix': 'load_int_raw',
            'tvm_pldux': 'preload_uint_raw',
            'tvm_pldix': 'preload_int_raw',
            'tvm_pldslicex': 'preload_slice_raw',
            'tvm_pushslice_746f6e': 'push_slice_746f6e',
            'tvm_pushslice_': 'push_slice_empty',
            'tvm_mulrshift_256': 'mul_rshift_raw_256',
            'tvm_mulrshiftr_256': 'mul_rshift_round_raw_256',
            'tvm_mulrshiftc_256': 'mul_rshift_ceil_raw_256',
            'tvm_bbits': 'builder_bits',
            'tvm_brefs': 'builder_refs',
            'tvm_setlibcode': 'set_library_code',
            'tvm_dictuset': 'udict_set_raw',
            'tvm_dictiset': 'idict_set_raw',
            'tvm_getglob_2': 'get_global_2',
            'tvm_setglob_2': 'set_global_2',
            'tvm_changelib': 'change_library',
            'tvm_divmod': 'divmod_raw',
            'tvm_chksigns': 'check_data_signature',
            'tvm_stux': 'store_uint_raw',
            'tvm_stix': 'store_int_raw',
            'tvm_dictumin': 'udict_get_min_raw',
            'tvm_dictumax': 'udict_get_max_raw',
            'tvm_dictugetnext': 'udict_get_next_raw',
            'tvm_dictugetnexteq': 'udict_get_next_eq_raw',
            'tvm_dictigetprev': 'idict_get_prev_raw',
            'tvm_dictigetpreveq': 'idict_get_prev_eq_raw',
            'tvm_dicturemmin': 'udict_remove_min_raw',
            'tvm_dictiremmax': 'idict_remove_max_raw',
            'tvm_dictisetgetoptref': 'idict_set_get_opt_ref_raw',
            'tvm_dictusetgetoptref': 'udict_set_get_opt_ref_raw',
        }
        for primitive, expected in aliases.items():
            with self.subTest(primitive=primitive):
                self.assertEqual(primitive_name(primitive), expected)


if __name__ == '__main__':
    unittest.main()
