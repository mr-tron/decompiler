"""Homogeneous tuple-vector reconstruction checks against the official VM."""
import re
import unittest

from decompiler.asm import parse_asm
from decompiler.func import reconstruct, render
from decompiler.ir import UnsupportedInstruction, analyze
from decompiler.toolchain import Toolchain
from tests import test_patterns70


class VectorOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_patterns70.PatternOracleTests.setUpClass()
        cls.oracle = test_patterns70.PatternOracleTests()
        cls.tools = Toolchain()

    def compile_pair(self, source):
        original = self.tools.compile(source, version='0.4.3')
        readable = render(reconstruct(parse_asm(original.asm)), readable=True)
        candidate = self.tools.compile(readable, version='0.4.3')
        return original, candidate, readable

    def assert_methods_match(self, source, cases):
        original, candidate, _ = self.compile_pair(source)
        for method, arguments in cases:
            with self.subTest(method=method, arguments=arguments):
                self.assertEqual(self.oracle.vm(original.boc, arguments, method),
                                 self.oracle.vm(candidate.boc, arguments, method))

    def test_empty_push_pop_length_index_and_bounds(self):
        source = '''
tuple empty_vector() asm "0 TUPLE";
forall X -> tuple vector_push(tuple t, X value) asm "TPUSH";
forall X -> (tuple, X) vector_pop(tuple t) asm "TPOP";
int vector_len(tuple t) asm "TLEN";
forall X -> X vector_at(tuple t, int index) asm "INDEXVAR";
() recv_internal() { }
int empty_len() method_id(100) { return vector_len(empty_vector()); }
int one_index() method_id(101) {
  var v = vector_push(empty_vector(), 7);
  return vector_at(v, 0);
}
(int, int) many_pop() method_id(102) {
  var a = vector_push(empty_vector(), 4);
  var b = vector_push(a, 9);
  var (tail, last) = vector_pop(b);
  return (last, vector_len(tail));
}
int many_index() method_id(103) {
  var a = vector_push(empty_vector(), 4);
  var b = vector_push(a, 9);
  var c = vector_push(b, 12);
  return vector_at(c, 1);
}
int out_of_bounds() method_id(104) {
  var v = vector_push(empty_vector(), 4);
  return vector_at(v, 1);
}
'''
        self.assert_methods_match(source, [(100, ''), (101, ''), (102, ''),
                                          (103, ''), (104, '')])

    def test_two_composite_element_shapes_keep_distinct_helpers(self):
        source = '''
tuple empty_vector() asm "0 TUPLE";
forall X -> tuple vector_push(tuple t, X value) asm "TPUSH";
int vector_len(tuple t) asm "TLEN";
builder newc() asm "NEWC";
cell endc(builder value) asm "ENDC";
slice empty_slice() asm "x{} PUSHSLICE";
() recv_internal() { }
(int, int) shapes() method_id(105) {
  var left = vector_push(empty_vector(), [0, endc(newc())]);
  var right = vector_push(empty_vector(), [empty_slice(), 0]);
  return (vector_len(left), vector_len(right));
}
'''
        original, candidate, readable = self.compile_pair(source)
        names = re.findall(r'^tuple (?:tvm_)?tpush_tuple_[a-f0-9]+\(', readable, re.M)
        names = [name.split('(')[0] for name in names]
        self.assertEqual(len(names), 2)
        self.assertEqual(len(set(names)), 2)
        self.assertNotIn('vector_[', readable)
        self.assertEqual(self.oracle.vm(original.boc, '', 105),
                         self.oracle.vm(candidate.boc, '', 105))

    def test_record_list_build_loop_and_uncons(self):
        source = '''
forall X -> X null_value() asm "PUSHNULL";
tuple cons_record([int, cell] head, tuple tail) asm "2 TUPLE";
([int, cell], tuple) uncons_record(tuple list) asm "2 UNTUPLE";
int record_key([int, cell] record) asm "0 INDEX";
forall X -> int is_null(X value) asm "ISNULL";
builder newc() asm "NEWC";
cell endc(builder value) asm "ENDC";
() recv_internal() { }
(int, int) record_loop(int count) method_id(106) {
  var tail = null_value();
  repeat (count) {
    tail = cons_record([count, endc(newc())], tail);
  }
  var (head, rest) = uncons_record(tail);
  return (record_key(head), is_null(rest));
}
'''
        original, candidate, _ = self.compile_pair(source)
        for count in ('0', '1', '3'):
            with self.subTest(count=count):
                expected = self.oracle.vm(original.boc, count, 106)
                actual = self.oracle.vm(candidate.boc, count, 106)
                self.assertEqual(expected, actual)
                if count == '0':
                    self.assertTrue(expected.endswith(' 7'), expected)

    def test_mixed_vector_elements_are_rejected(self):
        assembly = parse_asm('0 TUPLE\n1 PUSHINT\nTPUSH\nMYADDR\nTPUSH')
        with self.assertRaisesRegex(UnsupportedInstruction, 'Vector element type differs'):
            analyze(assembly.instructions, arguments=0)

    def test_loop_carried_vector_type_is_inferred_from_body(self):
        source = '''
tuple empty_vector() asm "0 TUPLE";
tuple vector_push(tuple t, int value) asm "TPUSH";
(tuple, int) vector_pop(tuple t) asm "TPOP";
int vector_len(tuple t) asm "TLEN";
() recv_internal() { }
int example(int n) method_id(107) {
  var values = empty_vector();
  while (n > 0) {
    values = vector_push(values, n);
    n -= 1;
  }
  var result = 0;
  while (vector_len(values)) {
    var (rest, value) = vector_pop(values);
    values = rest;
    result += value;
  }
  return result;
}
'''
        self.assert_methods_match(source, [(107, '0'), (107, '1'), (107, '5')])
