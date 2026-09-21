"""Readable-source temporary elimination must preserve evaluation semantics."""
import unittest

from decompiler.func import Function, Module, simplify_temporaries
from decompiler.ir import Expr, Statement


def local(name):
    return Expr("local", value=name)


def number(value):
    return Expr("literal", value=value)


def call(name, *arguments):
    return Expr("call", tuple(arguments), name)


def binary(operator, left, right):
    return Expr("binary", (left, right), operator)


def assign(name, value):
    return Statement("assign", (local(name), value))


def simplify(statements, *returns):
    module = Module((Function("method_100", (("int", "arg0"),), tuple(returns), tuple(statements), 100, True),))
    return simplify_temporaries(module).functions[0]


def contains(value, target):
    if isinstance(value, Expr):
        return value == target or any(contains(child, target) for child in value.args)
    if isinstance(value, Statement):
        return any(contains(child, target) for child in (*value.values, *value.then, *value.otherwise))
    return False


class TemporarySimplificationTests(unittest.TestCase):
    def test_literal_into_arbitrary_expression_contexts(self):
        arg = Expr("arg", value="arg0")
        uses = [local("v"), binary("==", arg, local("v")),
                call("some_operation", local("v")),
                call("some_operation", binary("+", arg, binary("*", local("v"), number(2))))]
        for use in uses:
            with self.subTest(use=use):
                result = simplify([assign("v", call("impure_touch", number(64)))], use)
                self.assertFalse(result.statements)
                self.assertFalse(contains(result.returns[0], local("v")))
                self.assertTrue(contains(result.returns[0], number(64)))

    def test_literal_can_move_into_nested_branch(self):
        arg = Expr("arg", value="arg0")
        nested = Statement("if", (arg,), (Statement("if", (arg,), (Statement("call", (call("sink", local("v")),)),)),))
        result = simplify([assign("v", call("impure_touch", number(8))), nested])
        self.assertEqual(len(result.statements), 1)
        self.assertEqual(result.statements[0].kind, "if")
        self.assertFalse(contains(result.statements[0], local("v")))
        self.assertTrue(contains(result.statements[0], number(8)))

    def test_alias_chains_are_not_limited_to_two_patterns(self):
        result = simplify([assign("a", call("impure_touch", number(17))),
                           assign("b", local("a")), assign("c", local("b")),
                           assign("d", local("c"))], call("sink", local("d")))
        self.assertFalse(result.statements)
        self.assertEqual(result.returns, (call("sink", number(17)),))

    def test_single_use_calls_can_chain_without_reordering(self):
        result = simplify([assign("a", call("first")), assign("b", call("second", local("a")))], local("b"))
        self.assertFalse(result.statements)
        self.assertEqual(result.returns, (call("second", call("first")),))

    def test_mutable_destination_and_captured_source_are_kept(self):
        arg = Expr("arg", value="arg0")
        result = simplify([assign("v", number(1)), Statement("set", (local("v"), number(2)))], local("v"))
        self.assertEqual([statement.kind for statement in result.statements], ["assign", "set"])
        captured = simplify([assign("v", arg), Statement("set", (arg, number(9)))], local("v"))
        self.assertEqual(captured.statements[0], assign("v", arg))
        self.assertEqual(captured.returns, (local("v"),))

    def test_trapping_expression_cannot_move_into_branch_or_loop(self):
        arg = Expr("arg", value="arg0")
        computation = binary("/", number(1), arg)
        for kind in ("if", "while"):
            use = Statement(kind, (arg,), (Statement("call", (call("sink", local("v")),)),))
            result = simplify([assign("v", computation), use])
            self.assertEqual(result.statements[0], assign("v", computation))
        condition = simplify([assign("v", computation), Statement("while", (local("v"),))])
        self.assertEqual(condition.statements[0], assign("v", computation))
        conditional = simplify([assign("v", computation)], Expr("select", (arg, local("v"), number(0))))
        self.assertEqual(conditional.statements[0], assign("v", computation))

    def test_call_argument_effect_order_is_preserved(self):
        for first_argument in (call("other_effect"), binary("/", number(1), Expr("arg", value="arg0"))):
            with self.subTest(first_argument=first_argument):
                original = assign("v", call("first_effect"))
                result = simplify([original], call("sink", first_argument, local("v")))
                self.assertEqual(result.statements[0], original)
        original = assign("v", call("first_effect"))
        effect = Statement("call", (call("other_effect"),))
        result = simplify([original, effect], local("v"))
        self.assertEqual(result.statements, (original, effect))
        result = simplify([original], call("other_effect"), local("v"))
        self.assertEqual(result.statements, (original,))

    def test_unused_trapping_computation_is_not_deleted(self):
        arg = Expr("arg", value="arg0")
        for value in (binary("/", number(1), arg), call("may_throw"),
                      binary("==", arg, number(0)), binary("&", arg, number(1)), Expr("unary", (arg,), "~")):
            original = assign("v", value)
            result = simplify([original])
            self.assertEqual(result.statements, (original,))

    def test_reused_expression_is_not_duplicated(self):
        original = assign("v", call("may_throw_or_have_effects"))
        result = simplify([original], binary("+", local("v"), local("v")))
        self.assertEqual(result.statements, (original,))
        self.assertEqual(result.returns, (binary("+", local("v"), local("v")),))


if __name__ == "__main__":
    unittest.main()
