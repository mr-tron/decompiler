import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from scripts.readable_corpus import ast_coverage, select_contracts


class ReadableCorpusTests(unittest.TestCase):
    def test_method_and_receiver_coverage_are_reported_separately(self):
        result = {
            'decompilation': {'structured_method_count': 2, 'method_count': 3},
            'debug': {'ast': {'functions': [
                {'name': 'recv_internal', 'assembly': None},
                {'name': 'method_1', 'assembly': None},
                {'name': 'method_2', 'assembly': ['DROP']},
            ]}},
        }
        self.assertEqual(ast_coverage(result, b''), (1, 1, 1))

    def test_receiver_assembly_fallback_is_not_counted_as_readable(self):
        result = {
            'decompilation': {'structured_method_count': 1, 'method_count': 2},
            'debug': {'ast': {'functions': [
                {'name': 'recv_internal', 'assembly': ['DROP']},
                {'name': 'method_1', 'assembly': None},
            ]}},
        }
        self.assertEqual(ast_coverage(result, b''), (1, 1, 0))

    def test_receiver_denominator_comes_from_original_method_ids(self):
        result = {
            'decompilation': {'structured_method_count': 1, 'method_count': 2},
            'debug': {'ast': {'functions': [
                {'name': 'recv_internal', 'assembly': None},
                {'name': 'method_neg_2', 'assembly': None},
            ]}},
        }
        with patch('scripts.readable_corpus.method_cells', return_value={
                0: b'a', -2: b'c', 12: b'd'}):
            self.assertEqual(ast_coverage(result, b'original boc'), (0, 2, 1))

    def test_selection_excludes_prior_ids_and_clone_groups(self):
        contracts = [
            SimpleNamespace(name='old_id', group='old_group', split='train', error=None,
                            version='v'),
            SimpleNamespace(name='same_group', group='old_group', split='train', error=None,
                            version='v'),
            SimpleNamespace(name='new_a', group='group_a', split='train', error=None,
                            version='v'),
            SimpleNamespace(name='new_b', group='group_b', split='train', error=None,
                            version='v'),
        ]
        toolchain = SimpleNamespace(
            configs=lambda: [{'version': 'v'}],
            compile=lambda *args, **kwargs: SimpleNamespace(code_hash='hash'))
        with patch('scripts.readable_corpus.load_corpus', return_value=contracts), \
                patch('scripts.readable_corpus.compilation_bundle', return_value=([], [])):
            selected = select_contracts(Path('.'), toolchain, 2,
                                        {'old_id'}, {'old_group'})
        self.assertEqual([contract.name for contract, _ in selected], ['new_a', 'new_b'])

    def test_variants_are_opt_in_and_prior_groups_stay_excluded(self):
        contracts = [
            SimpleNamespace(name='train_a', group='group_a', split='train', error=None, version='v'),
            SimpleNamespace(name='train_b', group='group_a', split='train', error=None, version='v'),
            SimpleNamespace(name='validation_a', group='group_b', split='validation', error=None, version='v'),
            SimpleNamespace(name='old_variant', group='old_group', split='train', error=None, version='v'),
        ]
        toolchain = SimpleNamespace(
            configs=lambda: [{'version': 'v'}],
            compile=lambda *args, **kwargs: SimpleNamespace(code_hash='hash'))
        with patch('scripts.readable_corpus.load_corpus', return_value=contracts), \
                patch('scripts.readable_corpus.compilation_bundle', return_value=([], [])):
            with self.assertRaises(RuntimeError):
                select_contracts(Path('.'), toolchain, 3, {'old_variant'}, {'old_group'},
                                 ('train', 'validation'))
            selected = select_contracts(Path('.'), toolchain, 3, {'old_variant'}, {'old_group'},
                                        ('train', 'validation'), allow_variants=True)
        self.assertEqual([contract.name for contract, _ in selected],
                         ['train_a', 'validation_a', 'train_b'])


if __name__ == '__main__':
    unittest.main()
