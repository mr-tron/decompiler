"""Conservative symbolic execution; unsupported semantics stop reconstruction."""
from dataclasses import dataclass, field, replace
import hashlib
import re
from .asm import Instruction


class UnsupportedInstruction(ValueError):
    def __init__(self, opcode, message=None):
        self.opcode = opcode
        super().__init__(message or f"Unsupported instruction: {opcode}")


class StackUnderflow(ValueError):
    pass


@dataclass(frozen=True)
class Expr:
    op: str
    args: tuple["Expr", ...] = ()
    value: object = None
    type: str = "int"


@dataclass(frozen=True)
class Statement:
    kind: str
    values: tuple[Expr, ...] = ()
    then: tuple["Statement", ...] = ()
    otherwise: tuple["Statement", ...] = ()


@dataclass
class StackIR:
    arguments: int
    returns: tuple[Expr, ...]
    statements: tuple[Statement, ...]
    impure: bool = False
    argument_types: tuple[str, ...] = ()
    primitives: tuple["Primitive", ...] = ()
    inline_body: bool = False


@dataclass(frozen=True)
class Primitive:
    name: str
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    assembly: str
    impure: bool = True


@dataclass
class BasicBlock:
    id: int
    instructions: list[Instruction] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)
    kind: str = "fallthrough"


@dataclass
class CFG:
    blocks: list[BasicBlock]
    entry: int = 0
    unresolved: list[str] = field(default_factory=list)


def _continuations(code):
    """Expand official disassembler's structured continuation notation."""
    for instruction in code:
        if instruction.opcode == "CONT" and instruction.blocks:
            yield Instruction("PUSHCONT", blocks=instruction.blocks)
        elif instruction.blocks and instruction.opcode in {"IF", "IFNOT", "IFELSE", "IFJMP", "IFNOTJMP", "REPEAT", "UNTIL", "WHILE"}:
            for body in instruction.blocks:
                yield Instruction("PUSHCONT", blocks=(body,))
            yield Instruction(instruction.opcode, instruction.operands)
        else:
            yield instruction


def build_cfg(instructions) -> CFG:
    blocks, unresolved = [], []

    def new(kind="fallthrough"):
        block = BasicBlock(len(blocks), kind=kind)
        blocks.append(block)
        return block

    def build(code, start):
        current, pending = start, []
        for instruction in _continuations(code):
            if current is None:
                current = new("unreachable")
            current.instructions.append(instruction)
            op = instruction.opcode
            if instruction.blocks and op not in {"PUSHCONT", "DICTIGETJMP", "DICTIGETJMPZ", "DICTUGETJMP", "DICTUGETJMPZ"}:
                unresolved.append(f"block {current.id}: unstructured {op} continuation")
                for body in instruction.blocks:
                    build(body, new("unresolved_continuation"))
            if op in {"CALLDICT", "JMPDICT", "CALL", "JMP", "TRY", "TRYARGS", "EXECUTE", "CALLCC", "CALLCCARGS", "RETARGS", "SETCONT", "SETCONTCTR", "SETCONTCTRMANY"}:
                unresolved.append(f"block {current.id}: interprocedural/dynamic {op}")
            if op in {"DICTIGETJMP", "DICTIGETJMPZ", "DICTUGETJMP", "DICTUGETJMPZ"} and instruction.blocks:
                current.kind = "dispatch"
                for body in instruction.blocks:
                    entry = new("method")
                    current.successors.append(entry.id)
                    end = build(body, entry)
                    if end is not None:
                        end.kind = "terminal"
                missing = new()
                current.successors.append(missing.id)
                current = missing
            elif op == "PUSHCONT" and len(instruction.blocks) == 1:
                pending.append(instruction.blocks[0])
                continue
            if op == "WHILE" and len(pending) >= 2:
                condition, body = pending[-2:]
                del pending[-2:]
                current.kind = "while"
                condition_entry, body_entry, join = new("condition"), new("loop_body"), new()
                current.successors.append(condition_entry.id)
                condition_end = build(condition, condition_entry)
                if condition_end is not None:
                    condition_end.successors.extend([body_entry.id, join.id])
                body_end = build(body, body_entry)
                if body_end is not None:
                    body_end.successors.append(condition_entry.id)
                current = join
            elif op in {"IF", "IFNOT", "IFELSE", "IFJMP", "IFNOTJMP", "REPEAT", "UNTIL", "AGAIN"}:
                needed = 2 if op == "IFELSE" else 1
                current.kind = op.lower()
                join = new()
                if len(pending) < needed:
                    unresolved.append(f"block {current.id}: dynamic {op}")
                    current.successors.append(join.id)
                    pending.clear()
                    current = join
                    continue
                bodies = pending[-needed:]
                del pending[-needed:]
                for body in bodies:
                    entry = new("continuation")
                    current.successors.append(entry.id)
                    end = build(body, entry)
                    if end is not None:
                        if op in {"REPEAT", "UNTIL", "AGAIN"}:
                            end.successors.append(entry.id)
                        if op in {"IFJMP", "IFNOTJMP"}:
                            end.kind = "terminal"
                        elif op != "AGAIN":
                            end.successors.append(join.id)
                if op in {"IF", "IFNOT", "IFJMP", "IFNOTJMP", "REPEAT"}:
                    current.successors.append(join.id)
                current = join
            elif op in {"RET", "RETALT", "THROW", "THROWARG"}:
                current.kind = "terminal"
                current = None
                pending.clear()
            elif op in {"CALLX", "JMPX", "WHILE", "WHILEEND", "CALLREF", "JMPREF"}:
                unresolved.append(f"block {current.id}: {op}")
                pending.clear()
            elif pending:
                pending.clear()
        return current

    build(instructions, new())
    return CFG(blocks, unresolved=unresolved)


BINARY = {"ADD": "+", "SUB": "-", "MUL": "*", "DIV": "/", "MOD": "%", "AND": "&", "OR": "|", "XOR": "^", "LSHIFT": "<<", "RSHIFT": ">>", "EQUAL": "==", "NEQ": "!=", "LESS": "<", "GREATER": ">", "LEQ": "<=", "GEQ": ">="}
UNARY = {"NEGATE": "-", "NOT": "~"}


def analyze(instructions, arguments=None, methods=None, preserve_constants=False, global_types=None, argument_types_hint=None) -> StackIR:
    if arguments is None:
        for count in range(33):
            try:
                return analyze(instructions, count, methods, preserve_constants, global_types, argument_types_hint)
            except StackUnderflow:
                pass
        raise UnsupportedInstruction("stack", "More than 32 inferred arguments")
    global_types = {} if global_types is None else global_types
    initial = [Expr("arg", value=f"arg{i}", type="unknown") for i in range(arguments)]
    if argument_types_hint is not None and arguments > len(argument_types_hint):
        raise UnsupportedInstruction('entrypoint', 'Arguments exceed the entrypoint stack signature')
    argument_types = ({f'arg{i}': kind for i, kind in enumerate(argument_types_hint[-arguments:])
                       if kind not in {'unknown', 'null'}}
                      if argument_types_hint and arguments else {})
    primitives = {}
    local_count = 0

    def value_type(value):
        return argument_types.get(value.value, "unknown") if value.op == "arg" else value.type

    def require(value, kind):
        if re.fullmatch(r"X[0-9]*", kind) or value_type(value) == "null":
            return
        found = value_type(value)
        if found == 'vector_empty' and kind.startswith('vector_'):
            return
        if kind == 'tuple' and (found.startswith(('vector_', 'list_', '[')) or found == 'tuple'):
            return
        if found not in ("unknown", kind):
            raise UnsupportedInstruction("type", f"Conflicting stack types: {found} and {kind}")
        if value.op == "arg":
            argument_types[value.value] = kind

    def local(kind):
        nonlocal local_count
        result = Expr("local", value=f"v{local_count}", type=kind)
        local_count += 1
        return result

    alternate_return = (len(instructions) >= 2 and instructions[0].opcode == 'SAVECTR'
                        and instructions[0].operands == ('c2',) and instructions[1].opcode == 'SAMEALTSAVE')
    if alternate_return:
        instructions = instructions[2:]
    elif instructions and instructions[0].opcode == 'SAMEALTSAVE':
        alternate_return = True
        instructions = instructions[1:]

    def terminal(body):
        if not body:
            return False
        last = body[-1]
        return (last.kind in {'return', 'throw'} or
                last.kind == 'if' and terminal(last.then) and terminal(last.otherwise) or
                last.kind == 'while' and last.values == (Expr('literal', value=-1),))

    def execute(code, stack, preserve_result_order=False, loop_context=False):
        code = tuple(_continuations(code))
        if loop_context:
            # A jump here returns to this continuation's caller, not the function.
            # Make the skipped remainder explicit as the other branch.
            for pos in range(len(code) - 1, -1, -1):
                if code[pos].opcode in {'IFRET', 'IFNOTRET'}:
                    tail = code[pos+1:]
                    branches = ((), tail) if code[pos].opcode == 'IFRET' else (tail, ())
                    code = code[:pos] + tuple(_continuations((Instruction('IFELSE', blocks=branches),)))
                    continue
                if (pos > 0 and code[pos].opcode in {'IFJMP', 'IFNOTJMP'} and code[pos-1].opcode == 'PUSHCONT'
                        and len(code[pos-1].blocks) == 1):
                    jump, tail = code[pos-1].blocks[0], code[pos+1:]
                    branches = (jump, tail) if code[pos].opcode == 'IFJMP' else (tail, jump)
                    code = code[:pos-1] + tuple(_continuations((Instruction('IFELSE', blocks=branches),)))
        statements = []
        pending = []

        def computed(value):
            pending.append(value)
            return value

        def materialize(*extra):
            """Commit deferred expressions in TVM execution order before effects.

            Impure NOP is FunC's standard impure_touch idiom: the compiler removes
            the NOP, but must still evaluate its argument even if later discarded.
            """
            replacements = {}
            def rewritten(value):
                if id(value) in replacements:
                    return replacements[id(value)]
                return replace(value, args=tuple(rewritten(arg) for arg in value.args)) if value.args else value
            for value in pending:
                expression = rewritten(value)
                target = local(value_type(value))
                primitives["impure_touch"] = Primitive("impure_touch", ("X",), ("X",), "NOP")
                statements.append(Statement("assign", (target, Expr("call", (expression,), "impure_touch", target.type))))
                replacements[id(value)] = target
            pending.clear()
            stack[:] = [rewritten(value) for value in stack]
            return tuple(rewritten(value) for value in extra)

        def literal(value, kind="int"):
            expression = Expr("literal", value=value, type=kind)
            stack.append(computed(expression) if preserve_constants else expression)

        def pop():
            if not stack:
                raise StackUnderflow("Stack underflow")
            return stack.pop()

        def integer(instruction):
            if len(instruction.operands) != 1:
                raise UnsupportedInstruction(instruction.opcode, "Expected one integer operand")
            try:
                return int(instruction.operands[0], 0)
            except ValueError:
                raise UnsupportedInstruction(instruction.opcode, "Invalid integer operand") from None

        def discard(value):
            if value.op not in {"arg", "literal", "local"} and value not in stack:
                materialize(value)

        def slot(value):
            match = re.fullmatch(r"s([0-9]+)", value)
            if not match:
                raise UnsupportedInstruction("register", "Control or dynamic stack register")
            index = int(match[1])
            if index >= len(stack):
                raise StackUnderflow()
            return -1 - index

        def compound(op, operands):
            indices = []
            for operand in operands:
                match = re.fullmatch(r"s(?:([0-9]+)|\((-?[0-9]+)\))", operand)
                if not match:
                    raise UnsupportedInstruction(op, "Invalid stack register")
                indices.append(int(match[1] or match[2]))
            def pick(index):
                if index < 0:
                    raise UnsupportedInstruction(op, "Invalid adjusted stack index")
                if index >= len(stack):
                    raise StackUnderflow()
                return -1 - index
            def swap(x, y):
                left, right = pick(x), pick(y)
                stack[left], stack[right] = stack[right], stack[left]
            def push(x):
                stack.append(stack[pick(x)])
            # Direct translations of TON crypto/vm/stackops.cpp. PUX* printed
            # operands are adjusted by Disasm.fif (s(-1) is a valid encoding).
            if op in {"XCPU", "PUXC", "PUSH2"} and len(indices) == 2:
                x, y = indices
                if op == "XCPU":
                    swap(0, x); push(y)
                elif op == "PUXC":
                    push(x); swap(0, 1); swap(0, y + 1)
                else:
                    push(x); push(y + 1)
            elif len(indices) == 3:
                x, y, z = indices
                if op == "XCHG3":
                    swap(2, x); swap(1, y); swap(0, z)
                elif op == "XC2PU":
                    swap(1, x); swap(0, y); push(z)
                elif op == "XCPUXC":
                    swap(1, x); push(y); swap(0, 1); swap(0, z + 1)
                elif op == "XCPU2":
                    swap(0, x); push(y); push(z + 1)
                elif op == "PUXC2":
                    push(x); swap(2, 0); swap(1, y + 1); swap(0, z + 1)
                elif op == "PUXCPU":
                    push(x); swap(0, 1); swap(0, y + 1); push(z + 1)
                elif op == "PU2XC":
                    push(x); swap(1, 0); push(y + 1); swap(1, 0); swap(0, z + 2)
                elif op == "PUSH3":
                    push(x); push(y + 1); push(z + 2)
                else:
                    raise UnsupportedInstruction(op)
            else:
                raise UnsupportedInstruction(op, "Invalid stack operand count")

        def primitive(op, inputs, outputs, immediate=None, assembly=None):
            materialize()
            operands = tuple(reversed([pop() for _ in inputs]))
            for value, kind in zip(operands, inputs):
                require(value, kind)
            name = "tvm_" + op.lower() + (f"_{immediate}" if immediate is not None else "")
            assembly = assembly or (f"{immediate} {op}" if immediate is not None else op)
            primitives[name] = Primitive(name, inputs, outputs, assembly)
            results = tuple(local(kind) for kind in outputs)
            call = Expr("call", operands, name)
            if results:
                target = results[0] if len(results) == 1 else Expr("product", results)
                statements.append(Statement("assign", (target, call)))
            else:
                statements.append(Statement("call", (call,)))
            stack.extend(results)

        skip_next = False
        for index, instruction in enumerate(code):
            if skip_next:
                skip_next = False
                continue
            op = instruction.opcode
            if op in {"NOP", "RET"}:
                if op == "RET" and index != len(code) - 1:
                    raise UnsupportedInstruction(op, "Instructions after early return")
            elif op == 'RETALT':
                if not alternate_return:
                    raise UnsupportedInstruction(op, 'Alternate return target is not the function return')
                materialize()
                statements.append(Statement('return', tuple(stack)))
                break
            elif op == 'AGAINEND':
                materialize()
                probe = list(stack)
                execute(code[index + 1:], probe, True, True)
                carried = []
                for value in stack:
                    kind = value_type(value)
                    if kind == 'unknown' and value.op == 'arg':
                        carried.append(value)
                        continue
                    if kind == 'unknown':
                        raise UnsupportedInstruction(op, 'Unknown loop-carried type')
                    target = local(kind)
                    statements.append(Statement('assign', (target, value)))
                    carried.append(target)
                body_stack = list(carried)
                body = list(execute(code[index + 1:], body_stack, True, True))
                if not terminal(body):
                    if len(body_stack) != len(carried):
                        raise UnsupportedInstruction(op, 'Loop changes stack height')
                    updates = []
                    for target, value in zip(carried, body_stack):
                        if target == value:
                            continue
                        if target.op != 'local':
                            raise UnsupportedInstruction(op, 'Loop changes an inferred invariant')
                        require(value, target.type)
                        updates.append((target, value))
                    if updates:
                        targets, values = zip(*updates)
                        body.append(Statement('set', (Expr('product', targets), Expr('product', values))))
                statements.append(Statement('while', (Expr('literal', value=-1),), tuple(body)))
                # This loop exits only by a function return or exception.
                stack.clear()
                break
            elif op in {'IFRET', 'IFNOTRET', 'IFRETALT', 'IFNOTRETALT'}:
                if op.endswith('ALT') and not alternate_return:
                    raise UnsupportedInstruction(op, 'Unknown alternate return target')
                if loop_context and not op.endswith('ALT'):
                    raise UnsupportedInstruction(op, 'Conditional return targets a nested continuation')
                materialize()
                condition = pop()
                require(condition, 'int')
                if op.startswith('IFNOT'):
                    condition = Expr('binary', (condition, Expr('literal', value=0)), '==')
                statements.append(Statement('if', (condition,), (Statement('return', tuple(stack)),)))
            elif op in {'RAWRESERVE', 'SETCODE', 'MIN', 'MAX', 'ABS', 'POW2',
                        'SDEPTH', 'CDEPTH', 'SREMPTY', 'SDCNTLEAD0',
                        'RAND', 'ADDRAND', 'CDATASIZE', 'DICTIGETOPTREF', 'DICTUGETOPTREF',
                        'BBITS', 'BREFS', 'SETLIBCODE', 'CHANGELIB', 'DICTUSET', 'DICTISET',
                        'DICTUSETB', 'DICTISETB', 'DICTSETB', 'DICTADDB', 'DICTDEL',
                        'DICTISETREF', 'THROWANYIF', 'THROWANYIFNOT', 'STZEROES',
                        'STUX', 'STIX', 'DIVMOD', 'CHKSIGNS', 'DICTISETGETOPTREF', 'DICTUSETGETOPTREF'}:
                inputs, outputs = {
                    'STUX': (('int', 'builder', 'int'), ('builder',)),
                    'STIX': (('int', 'builder', 'int'), ('builder',)),
                    'DIVMOD': (('int', 'int'), ('int', 'int')),
                    'CHKSIGNS': (('slice', 'slice', 'int'), ('int',)),
                    'DICTISETGETOPTREF': (('cell', 'int', 'cell', 'int'), ('cell', 'cell')),
                    'DICTUSETGETOPTREF': (('cell', 'int', 'cell', 'int'), ('cell', 'cell')),
                    'BBITS': (('builder',), ('int',)), 'BREFS': (('builder',), ('int',)),
                    'SETLIBCODE': (('cell', 'int'), ()), 'CHANGELIB': (('int', 'int'), ()),
                    'DICTUSET': (('slice', 'int', 'cell', 'int'), ('cell',)),
                    'DICTISET': (('slice', 'int', 'cell', 'int'), ('cell',)),
                    'RAWRESERVE': (('int', 'int'), ()), 'SETCODE': (('cell',), ()),
                    'MIN': (('int', 'int'), ('int',)), 'MAX': (('int', 'int'), ('int',)),
                    'SDEPTH': (('slice',), ('int',)), 'CDEPTH': (('cell',), ('int',)),
                    'RAND': (('int',), ('int',)), 'ADDRAND': (('int',), ()),
                    'CDATASIZE': (('cell', 'int'), ('int', 'int', 'int')),
                    'DICTIGETOPTREF': (('int', 'cell', 'int'), ('cell',)),
                    'DICTUGETOPTREF': (('int', 'cell', 'int'), ('cell',)),
                    'DICTUSETB': (('builder', 'int', 'cell', 'int'), ('cell',)),
                    'DICTISETB': (('builder', 'int', 'cell', 'int'), ('cell',)),
                    'DICTSETB': (('builder', 'slice', 'cell', 'int'), ('cell',)),
                    'DICTADDB': (('builder', 'slice', 'cell', 'int'), ('cell', 'int')),
                    'DICTDEL': (('slice', 'cell', 'int'), ('cell', 'int')),
                    'DICTISETREF': (('cell', 'int', 'cell', 'int'), ('cell',)),
                    'STZEROES': (('builder', 'int'), ('builder',)),
                    'THROWANYIF': (('int', 'int'), ()), 'THROWANYIFNOT': (('int', 'int'), ()),
                    'ABS': (('int',), ('int',)), 'POW2': (('int',), ('int',)),
                    'SREMPTY': (('slice',), ('int',)), 'SDCNTLEAD0': (('slice',), ('int',)),
                }[op]
                primitive(op, inputs, outputs)
            elif op == 'GETGLOB' and index + 1 < len(code) and code[index + 1].opcode == 'ISNULL':
                # GETGLOB has no inferable type on its own. ISNULL accepts any
                # stack value, so preserve this common check without guessing.
                slot_number = integer(instruction)
                if not 1 <= slot_number <= 31:
                    raise UnsupportedInstruction(op, 'Unsupported global slot')
                materialize()
                name = f'tvm_is_global_null_{slot_number}'
                primitive_value = Primitive(name, (), ('int',), f'{slot_number} GETGLOB ISNULL')
                primitives[name] = primitive_value
                result = local('int')
                statements.append(Statement('assign', (result, Expr('call', (), name))))
                stack.append(result)
                skip_next = True
            elif op in {'LDUX', 'LDIX', 'PLDUX', 'PLDIX', 'PLDSLICEX'}:
                primitive(op, ('slice', 'int'), ('slice',) if op == 'PLDSLICEX' else
                          ('int',) if op.startswith('PL') else ('int', 'slice'))
            elif op in {'MULRSHIFT#', 'MULRSHIFTR#', 'MULRSHIFTC#'}:
                width = integer(instruction)
                if not 1 <= width <= 256:
                    raise UnsupportedInstruction(op, 'Invalid shift width')
                primitive(op[:-1], ('int', 'int'), ('int',), width, assembly=f'{width} {op}')
            elif op in {'PUSHREFSLICE', 'PUSHREF'}:
                from .boc import parse_boc, BocError
                try:
                    if len(instruction.operands) != 1:
                        raise ValueError()
                    payload = bytes.fromhex(instruction.operands[0])
                    digest = parse_boc(payload).code_hash
                except (ValueError, BocError):
                    raise UnsupportedInstruction(op, 'Referenced slice cell is unavailable') from None
                primitive(op, (), ('slice' if op == 'PUSHREFSLICE' else 'cell',), digest,
                          assembly=f'B{{{payload.hex()}}} B>boc {op}')
            elif op in {'PUSHSLICE', 'STSLICECONST'}:
                if len(instruction.operands) != 1 or not re.fullmatch(r'x\{[0-9a-fA-F]*_?\}', instruction.operands[0]):
                    raise UnsupportedInstruction(op, 'Slice literal is not inline')
                prefix = instruction.operands[0]
                primitive(op, ('builder',) if op == 'STSLICECONST' else (),
                          ('builder',) if op == 'STSLICECONST' else ('slice',),
                          prefix[2:-1].lower(), assembly=f'{prefix} {op}')
            elif op == 'DICTGET':
                if index + 1 >= len(code) or code[index + 1].opcode != 'NULLSWAPIFNOT':
                    raise UnsupportedInstruction(op, 'Dictionary lookup requires padded outputs')
                primitive(op, ('slice', 'cell', 'int'), ('slice', 'int'),
                          assembly='DICTGET NULLSWAPIFNOT')
                skip_next = True
            elif re.fullmatch(r'DICT[UI](?:(?:REM)?(?:MIN|MAX)|GET(?:NEXT|PREV)(?:EQ)?)', op) or op in {'DICTREMMIN', 'DICTUMINREF'}:
                if index + 1 >= len(code) or code[index + 1].opcode != 'NULLSWAPIFNOT2':
                    raise UnsupportedInstruction(op, 'Dictionary iteration requires padded outputs')
                inputs = ('int', 'cell', 'int') if 'GET' in op else ('cell', 'int')
                value_kind = 'cell' if op == 'DICTUMINREF' else 'slice'
                key_kind = 'slice' if op == 'DICTREMMIN' else 'int'
                outputs = (('cell',) if 'REM' in op else ()) + (value_kind, key_kind, 'int')
                primitive(op, inputs, outputs, assembly=f'{op} NULLSWAPIFNOT2')
                skip_next = True
            elif op == 'REVERSE':
                if len(instruction.operands) != 2:
                    raise UnsupportedInstruction(op, 'Expected count and offset')
                try:
                    count, offset = map(int, instruction.operands)
                except ValueError:
                    raise UnsupportedInstruction(op, 'Invalid reversal range') from None
                if not 2 <= count <= 17 or not 0 <= offset <= 15:
                    raise UnsupportedInstruction(op, 'Invalid reversal range')
                if len(stack) < count + offset:
                    raise StackUnderflow()
                start = len(stack) - count - offset
                stack[start:start + count] = reversed(stack[start:start + count])
            elif op == 'TUCK':
                right, left = pop(), pop()
                stack.extend((right, left, right))
            elif op in {'GETGLOB', 'SETGLOB'}:
                slot_number = integer(instruction)
                if not 1 <= slot_number <= 31:
                    raise UnsupportedInstruction(op, 'Unsupported global slot')
                kind = global_types.get(slot_number)
                if op == 'SETGLOB':
                    if not stack:
                        raise StackUnderflow()
                    found = value_type(stack[-1])
                    kind = kind or (found if found not in {'unknown', 'null'} else None)
                    if kind is not None:
                        require(stack[-1], kind)
                        global_types[slot_number] = kind
                    primitive(op, ('X',), (), slot_number)
                else:
                    if kind is None:
                        raise UnsupportedInstruction(op, 'Global value type is not established')
                    primitive(op, (), (kind,), slot_number)
            elif op == 'ENDS':
                primitive(op, ('slice',), ())
            elif op == 'HASHCU':
                primitive(op, ('cell',), ('int',))
            elif op == 'BLKSWAP':
                if len(instruction.operands) != 2:
                    raise UnsupportedInstruction(op, 'Expected two block lengths')
                try:
                    left, right = map(int, instruction.operands)
                except ValueError:
                    raise UnsupportedInstruction(op, 'Invalid block lengths') from None
                if not 1 <= left <= 16 or not 1 <= right <= 16:
                    raise UnsupportedInstruction(op, 'Invalid block lengths')
                if len(stack) < left + right:
                    raise StackUnderflow()
                stack[-left-right:] = stack[-right:] + stack[-left-right:-right]
            elif op == 'RANDU256':
                primitive(op, (), ('int',))
            elif op == 'RIST255_VALIDATE':
                # Non-quiet validation consumes a point and returns no value;
                # invalid encodings raise range_chk in the VM.
                primitive(op, ('int',), ())
            elif op == 'RIST255_MULBASE':
                # The scalar is reduced modulo the Ristretto order by TVM.
                primitive(op, ('int',), ('int',))
            elif op in {'ACCEPT', 'COMMIT'}:
                primitive(op, (), ())
            elif op == 'POP' and instruction.operands == ('c5',):
                primitive('SETC5', ('cell',), (), assembly='c5 POP')
            elif op in {'SDCUTLAST', 'SDSKIPLAST', 'SDCUTFIRST', 'LDSLICEX'}:
                primitive(op, ('slice', 'int'), ('slice', 'slice') if op == 'LDSLICEX' else ('slice',))
            elif op in {'PLDDICT', 'XCTOS', 'HASHSU', 'CHKSIGNU', 'SDCNTTRAIL0', 'SDCNTTRAIL1',
                        'DICTUADDB', 'SDATASIZE'}:
                inputs, outputs = {
                    'PLDDICT': (('slice',), ('cell',)), 'XCTOS': (('cell',), ('slice', 'int')),
                    'HASHSU': (('slice',), ('int',)), 'CHKSIGNU': (('int', 'slice', 'int'), ('int',)),
                    'SDCNTTRAIL0': (('slice',), ('int',)), 'SDCNTTRAIL1': (('slice',), ('int',)),
                    'DICTUADDB': (('builder', 'int', 'cell', 'int'), ('cell', 'int')),
                    'SDATASIZE': (('slice', 'int'), ('int', 'int', 'int')),
                }[op]
                primitive(op, inputs, outputs)
            elif op in {'SETGASLIMIT', 'SETRAND'}:
                primitive(op, ('int',), ())
            elif op in {'GETPRECOMPILEDGAS', 'STORAGEFEES', 'DUEPAYMENT', 'GASCONSUMED'}:
                primitive(op, (), ('int',))
            elif op == 'MYCODE':
                primitive(op, (), ('cell',))
            elif op in {'GETGASFEE', 'GETSTORAGEFEE', 'GETFORWARDFEE', 'GETORIGINALFWDFEE', 'GETGASFEESIMPLE', 'GETFORWARDFEESIMPLE'}:
                count = {'GETGASFEE': 2, 'GETSTORAGEFEE': 4,
                         'GETFORWARDFEE': 3, 'GETORIGINALFWDFEE': 2,
                         'GETGASFEESIMPLE': 2, 'GETFORWARDFEESIMPLE': 3}[op]
                primitive(op, ('int',) * count, ('int',))
            elif op in {'STB', 'STSLICE', 'LDREFRTOS', 'REWRITEVARADDR', 'SDPFXREV', 'SDPPFXREV'}:
                inputs, outputs = {
                    'STB': (('builder', 'builder'), ('builder',)),
                    'STSLICE': (('slice', 'builder'), ('builder',)),
                    'LDREFRTOS': (('slice',), ('slice', 'slice')),
                    'REWRITEVARADDR': (('slice',), ('int', 'slice')),
                    'SDPFXREV': (('slice', 'slice'), ('int',)),
                    'SDPPFXREV': (('slice', 'slice'), ('int',)),
                }[op]
                primitive(op, inputs, outputs)
            elif op in {'RSHIFTR#', 'RSHIFTC#'}:
                width = integer(instruction)
                if not 1 <= width <= 256:
                    raise UnsupportedInstruction(op, 'Invalid shift width')
                primitive(op[:-1], ('int',), ('int',), width, assembly=f'{width} {op}')
            elif op in {'BREMBITS', 'BREMREFS'}:
                primitive(op, ('builder',), ('int',))
            elif op == 'PLDREFVAR':
                primitive(op, ('slice', 'int'), ('cell',))
            elif op in {'DIVC', 'DIVR'}:
                primitive(op, ('int', 'int'), ('int',))
            elif op in {'DICTUADD', 'DICTIADD'}:
                primitive(op, ('slice', 'int', 'cell', 'int'), ('cell', 'int'))
            elif op in {'DICTUDELGET', 'DICTIDELGET'}:
                if index + 1 >= len(code) or code[index + 1].opcode != 'NULLSWAPIFNOT':
                    raise UnsupportedInstruction(op, 'Dictionary deletion requires padded outputs')
                primitive(op, ('int', 'cell', 'int'), ('cell', 'slice', 'int'),
                          assembly=f'{op} NULLSWAPIFNOT')
                skip_next = True
            elif op == 'SHA256U':
                primitive(op, ('slice',), ('int',))
            elif op == 'SBITREFS':
                primitive(op, ('slice',), ('int', 'int'))
            elif op == 'SKIPDICT':
                primitive(op, ('slice',), ('slice',))
            elif op == 'SDSUBSTR':
                primitive(op, ('slice', 'int', 'int'), ('slice',))
            elif op in {'PLDSLICE', 'LDSLICE', 'PLDREFIDX'}:
                n = integer(instruction)
                if not 0 <= n <= (3 if op == 'PLDREFIDX' else 1023):
                    raise UnsupportedInstruction(op, 'Invalid preload operand')
                outputs = ('cell',) if op == 'PLDREFIDX' else ('slice', 'slice') if op == 'LDSLICE' else ('slice',)
                primitive(op, ('slice',), outputs, n)
            elif op in {'SDBEGINS', 'SDBEGINSQ'}:
                if len(instruction.operands) != 1 or not re.fullmatch(r'x\{[0-9a-fA-F_]+\}', instruction.operands[0]):
                    raise UnsupportedInstruction(op, 'Unsupported slice prefix')
                prefix = instruction.operands[0]
                primitive(op, ('slice',), ('slice', 'int') if op.endswith('Q') else ('slice',),
                          prefix[2:-1].lower(), assembly=f'{prefix} {op}')
            elif op == "PUSHINT":
                literal(integer(instruction))
            elif op == "PUSHNULL":
                literal("null()", "null")
            elif op in {"BALANCE", "INCOMINGVALUE"}:
                primitive(op, (), ("[int, cell]",))
            elif op == "ISNULL":
                primitive(op, ("X",), ("int",))
            elif op in {"DICTUGETREF", "DICTIGETREF", "DICTUGET", "DICTIGET"}:
                if index + 1 >= len(code) or code[index + 1].opcode != "NULLSWAPIFNOT" or code[index + 1].operands:
                    raise UnsupportedInstruction(op, "Dictionary lookup needs its stdlib NULLSWAPIFNOT result padding")
                primitive(op, ("int", "cell", "int"), ("cell" if op.endswith("REF") else "slice", "int"), assembly=f"{op} NULLSWAPIFNOT")
                skip_next = True
            elif op in {'TUPLE', 'PAIR', 'TRIPLE'}:
                count = {'PAIR': 2, 'TRIPLE': 3}.get(op)
                count = integer(instruction) if count is None else count
                if not 0 <= count <= 15:
                    raise UnsupportedInstruction(op, 'Invalid tuple arity')
                if count == 0:
                    name = 'tvm_vector_empty'
                    primitives[name] = Primitive(name, (), ('tuple',), '0 TUPLE')
                    stack.append(computed(Expr('call', (), name, type='vector_empty')))
                    continue
                materialize()
                values = tuple(reversed([pop() for _ in range(count)]))
                kinds = tuple(value_type(v) for v in values)
                list_kind = (f'list_{kinds[0]}' if count == 2 and (kinds[0] in {'int', 'cell', 'slice', 'builder'}
                             or re.fullmatch(r'\[(?:int|cell|slice|builder)(?:, (?:int|cell|slice|builder))*\]', kinds[0]))
                             and (kinds[1] == f'list_{kinds[0]}' or kinds[1] == 'null' and loop_context) else None)
                if list_kind:
                    element = kinds[0]
                    tail = values[1]
                    if value_type(tail) not in {'null', list_kind}:
                        raise UnsupportedInstruction(op, 'List tail type differs from its element list')
                    element_name = 'record_' + element[1:-1].replace(', ', '_') if element.startswith('[') else element
                    name = f'tvm_cons_{element_name}'
                    primitives[name] = Primitive(name, (element, 'tuple'), ('tuple',), '2 TUPLE')
                    stack.append(computed(Expr('call', values, name, type=list_kind)))
                    continue
                if any(k in {'unknown', 'null'} for k in kinds):
                    raise UnsupportedInstruction(op, f'Tuple element types are not known: {kinds}')
                stack.append(computed(Expr('tuple', values, type='[' + ', '.join(kinds) + ']')))
            elif op == 'TPUSH':
                materialize()
                value, vector = pop(), pop()
                vector_kind, element_kind = value_type(vector), value_type(value)
                if vector_kind == 'vector_empty':
                    if element_kind in {'unknown', 'null'}:
                        raise UnsupportedInstruction(op, 'First vector element type is not known')
                    vector_kind = f'vector_{element_kind}'
                elif not vector_kind.startswith('vector_') or vector_kind == 'vector_empty':
                    raise UnsupportedInstruction(op, 'Tuple is not a homogeneous vector')
                elif vector_kind.removeprefix('vector_') != element_kind:
                    raise UnsupportedInstruction(op, 'Vector element type differs')
                element_name = (f'tuple_{hashlib.sha1(element_kind.encode()).hexdigest()[:10]}'
                                if element_kind.startswith(('[', 'list_')) else element_kind)
                name = f'tvm_tpush_{element_name}'
                primitives[name] = Primitive(name, ('tuple', element_kind), (vector_kind,), 'TPUSH')
                stack.append(computed(Expr('call', (vector, value), name, type=vector_kind)))
            elif op == 'TLEN':
                kind = value_type(stack[-1]) if stack else 'unknown'
                if kind == 'vector_empty':
                    discard(pop())
                    literal(0)
                    continue
                if kind == 'unknown':
                    primitive('TLEN', ('tuple',), ('int',))
                    continue
                if not kind.startswith('vector_'):
                    raise UnsupportedInstruction(op, 'Tuple length needs an inferred homogeneous vector')
                primitive('TLEN', (kind,), ('int',))
            elif op in {'TPOP', 'INDEXVAR'}:
                offset = pop() if op == 'INDEXVAR' else None
                if offset is not None:
                    require(offset, 'int')
                kind = value_type(stack[-1]) if stack else 'unknown'
                if not kind.startswith('vector_') or kind == 'vector_empty':
                    raise UnsupportedInstruction(op, 'Tuple pop needs an inferred homogeneous vector')
                element_kind = kind.removeprefix('vector_')
                element_name = (f'tuple_{hashlib.sha1(element_kind.encode()).hexdigest()[:10]}'
                                if element_kind.startswith(('[', 'list_')) else element_kind)
                if offset is not None:
                    stack.append(offset)
                    primitive(f'INDEXVAR_{element_name}', (kind, 'int'), (element_kind,), assembly=op)
                else:
                    primitive(f'TPOP_{element_name}', (kind,), (kind, element_kind), assembly=op)
            elif op in {"INDEX", "FIRST", "SECOND", "THIRD", "UNTUPLE", "UNPAIR"}:
                if not stack:
                    raise StackUnderflow()
                kind = value_type(stack[-1])
                if kind.startswith('list_'):
                    element = kind.removeprefix('list_')
                    element_name = 'record_' + element[1:-1].replace(', ', '_') if element.startswith('[') else element
                    if op in {'UNTUPLE', 'UNPAIR'}:
                        count = 2 if op == 'UNPAIR' else integer(instruction)
                        if count != 2:
                            raise UnsupportedInstruction(op, 'List node arity must be two')
                        primitive(f'UNCONS_{element_name}', (kind,), (element, kind), assembly='2 UNTUPLE')
                    elif op in {'INDEX', 'FIRST'} and (op == 'FIRST' or integer(instruction) == 0):
                        primitive(f'INDEX_{element_name}', (kind,), (element,), assembly='0 INDEX')
                    elif op in {'INDEX', 'SECOND'} and (op == 'SECOND' or integer(instruction) == 1):
                        primitive(f'INDEX_TAIL_{element_name}', (kind,), (kind,), assembly='1 INDEX')
                    else:
                        raise UnsupportedInstruction(op, 'Unsupported list operation')
                    continue
                if not kind.startswith("[") or not kind.endswith("]"):
                    raise UnsupportedInstruction(op, f"Tuple element types are not known: {kind}")
                parts, depth, start = [], 0, 1
                for position, char in enumerate(kind[1:-1], 1):
                    depth += (char == '[') - (char == ']')
                    if char == ',' and depth == 0:
                        parts.append(kind[start:position].strip())
                        start = position + 1
                element_types = tuple(parts + ([kind[start:-1].strip()] if kind[start:-1].strip() else []))
                if op in {"UNTUPLE", "UNPAIR"}:
                    count = 2 if op == "UNPAIR" else integer(instruction)
                    if count != len(element_types):
                        raise UnsupportedInstruction(op, "Tuple arity mismatch")
                    primitive("UNTUPLE", (kind,), element_types, count)
                else:
                    offset = {"FIRST": 0, "SECOND": 1, "THIRD": 2}.get(op)
                    offset = integer(instruction) if offset is None else offset
                    if not 0 <= offset < len(element_types):
                        raise UnsupportedInstruction(op, "Tuple index out of range")
                    primitive("INDEX", (kind,), (element_types[offset],), offset)
            elif op in {"PUSHPOW2", "PUSHPOW2DEC"}:
                power = integer(instruction)
                if not 0 <= power <= (256 if op == "PUSHPOW2DEC" else 255):
                    raise UnsupportedInstruction(op, "Invalid power of two")
                literal((1 << power) - (op == "PUSHPOW2DEC"))
            elif op == "PUSH" and instruction.operands == ("c4",):
                primitive("GETDATA", (), ("cell",), assembly="c4 PUSH")
            elif op == "POP" and instruction.operands == ("c4",):
                primitive("SETDATA", ("cell",), (), assembly="c4 POP")
            elif op in {"NOW", "LTIME", "BLOCKLT", "MYADDR"}:
                primitive(op, (), ("slice",) if op == "MYADDR" else ("int",))
            elif op == "PUSH" and len(instruction.operands) == 1:
                stack.append(stack[slot(instruction.operands[0])])
            elif op == "POP" and len(instruction.operands) == 1:
                materialize()
                destination = slot(instruction.operands[0])
                old = stack[destination]
                stack[destination] = stack[-1]
                stack.pop()
                discard(old)
            elif op == "XCHG" and len(instruction.operands) == 2:
                left, right = map(slot, instruction.operands)
                stack[left], stack[right] = stack[right], stack[left]
            elif op == "XCHG2" and len(instruction.operands) == 2:
                left, right = map(slot, instruction.operands)
                if len(stack) < 2:
                    raise StackUnderflow()
                # TON exec_xchg2 swaps s1 with sx, then s0 with sy; aliases matter.
                stack[-2], stack[left] = stack[left], stack[-2]
                stack[-1], stack[right] = stack[right], stack[-1]
            elif op in {"XCPU", "PUXC", "PUSH2", "XCHG3", "XC2PU", "XCPUXC", "XCPU2", "PUXC2", "PUXCPU", "PU2XC", "PUSH3"}:
                compound(op, instruction.operands)
            elif op == "BLKDROP2" and len(instruction.operands) == 2:
                try:
                    count, keep = map(int, instruction.operands)
                except ValueError:
                    raise UnsupportedInstruction(op, "Invalid block-drop operands") from None
                if not 0 <= count <= 15 or not 0 <= keep <= 15:
                    raise UnsupportedInstruction(op, "Invalid block-drop range")
                if len(stack) < count + keep:
                    raise StackUnderflow()
                materialize()
                start = len(stack) - count - keep
                del stack[start:start + count]
            elif op in {"2DROP", "BLKDROP"}:
                materialize()
                count = 2 if op == "2DROP" else integer(instruction)
                if not 0 <= count <= 255:
                    raise UnsupportedInstruction(op, "Invalid drop count")
                if len(stack) < count:
                    raise StackUnderflow()
                removed = [pop() for _ in range(count)]
                for value in removed:
                    discard(value)
            elif op in {"2DUP", "2SWAP"}:
                needed = 2 if op == "2DUP" else 4
                if len(stack) < needed:
                    raise StackUnderflow()
                if op == "2DUP":
                    stack.extend(stack[-2:])
                else:
                    stack[-4:] = stack[-2:] + stack[-4:-2]
            elif op in {"TRUE", "FALSE", "ZERO", "ONE", "TWO", "TEN"}:
                literal({"TRUE": -1, "FALSE": 0, "ZERO": 0, "ONE": 1, "TWO": 2, "TEN": 10}[op])
            elif op in BINARY:
                right, left = pop(), pop()
                require(left, "int")
                require(right, "int")
                if (preserve_constants
                        and any(value.op == 'literal' and value_type(value) == 'int'
                                for value in (left, right))):
                    # A generic opcode with a literal came from a source boundary;
                    # spelling it as an expression would specialize it (for example EQUAL -> EQINT).
                    name = 'tvm_' + op.lower()
                    primitives[name] = Primitive(name, ('int', 'int'), ('int',), op)
                    stack.append(computed(Expr('call', (left, right), name, 'int')))
                else:
                    stack.append(computed(Expr("binary", (left, right), BINARY[op])))
            elif op in UNARY:
                operand = pop()
                require(operand, "int")
                stack.append(computed(Expr("unary", (operand,), UNARY[op])))
            elif op == 'MODPOW2#':
                width = integer(instruction)
                if not 1 <= width <= 256:
                    raise UnsupportedInstruction(op, 'Invalid modulo width')
                primitive('MODPOW2', ('int',), ('int',), width, assembly=f'{width} MODPOW2#')
            elif op == 'PFXDICTGETQ':
                if index + 1 >= len(code) or code[index + 1].opcode != 'NULLSWAPIFNOT2':
                    raise UnsupportedInstruction(op, 'Prefix lookup requires padded outputs')
                primitive(op, ('slice', 'cell', 'int'), ('slice', 'slice', 'slice', 'int'),
                          assembly='PFXDICTGETQ NULLSWAPIFNOT2')
                skip_next = True
            elif op in {"LSHIFT#", "RSHIFT#"}:
                operand = pop()
                require(operand, "int")
                stack.append(computed(Expr("binary", (operand, Expr("literal", value=integer(instruction))), "<<" if op == "LSHIFT#" else ">>")))
            elif op in {"INC", "DEC", "ADDCONST", "ADDINT", "MULCONST", "MULINT", "EQINT", "NEQINT", "LESSINT", "GTINT"}:
                n = 1 if op in {"INC", "DEC"} else integer(instruction)
                operator = {"INC": "+", "DEC": "-", "ADDCONST": "+", "ADDINT": "+", "MULCONST": "*", "MULINT": "*", "EQINT": "==", "NEQINT": "!=", "LESSINT": "<", "GTINT": ">"}[op]
                operand = pop()
                require(operand, "int")
                stack.append(computed(Expr("binary", (operand, Expr("literal", value=n)), operator)))
            elif op in {"CTOS", "NEWC", "ENDC", "SEMPTY", "SDEMPTY", "SREFS", "SBITS", "LDREF", "STREF", "STSLICER", "REWRITESTDADDR", "LDMSGADDR", "LDGRAMS", "STGRAMS", "LDDICT", "STDICT", "SDSKIPFIRST", "SDEQ"}:
                inputs, outputs = {"CTOS": (("cell",), ("slice",)), "NEWC": ((), ("builder",)), "ENDC": (("builder",), ("cell",)), "SEMPTY": (("slice",), ("int",)), "SDEMPTY": (("slice",), ("int",)), "SREFS": (("slice",), ("int",)), "SBITS": (("slice",), ("int",)), "LDREF": (("slice",), ("cell", "slice")), "STREF": (("cell", "builder"), ("builder",)), "STSLICER": (("builder", "slice"), ("builder",)), "REWRITESTDADDR": (("slice",), ("int", "int")), "LDMSGADDR": (("slice",), ("slice", "slice")), "LDGRAMS": (("slice",), ("int", "slice")), "STGRAMS": (("builder", "int"), ("builder",)), "LDDICT": (("slice",), ("cell", "slice")), "STDICT": (("cell", "builder"), ("builder",)), "SDSKIPFIRST": (("slice", "int"), ("slice",)), "SDEQ": (("slice", "slice"), ("int",))}[op]
                primitive(op, inputs, outputs)
            elif op in {"STBR", "SENDRAWMSG", "MULDIV", "DICTUSETREF", "DICTUDEL", "DICTIDEL", "CONFIGOPTPARAM", "UBITSIZE", "BITSIZE"}:
                inputs, outputs = {
                    "STBR": (("builder", "builder"), ("builder",)),
                    "SENDRAWMSG": (("cell", "int"), ()),
                    "MULDIV": (("int", "int", "int"), ("int",)),
                    "DICTUSETREF": (("cell", "int", "cell", "int"), ("cell",)),
                    "DICTUDEL": (("int", "cell", "int"), ("cell", "int")),
                    "DICTIDEL": (("int", "cell", "int"), ("cell", "int")),
                    "UBITSIZE": (("int",), ("int",)), "BITSIZE": (("int",), ("int",)),
                    "CONFIGOPTPARAM": (("int",), ("cell",)),
                }[op]
                primitive(op, inputs, outputs)
            elif op in {"LDU", "LDI", "PLDU", "PLDI", "STU", "STI"}:
                bits = integer(instruction)
                if not 1 <= bits <= (257 if op.endswith("I") else 256):
                    raise UnsupportedInstruction(op, "Invalid integer width")
                if op.startswith("ST"):
                    primitive(op, ("int", "builder"), ("builder",), bits)
                else:
                    primitive(op, ("slice",), ("int",) if op.startswith("PL") else ("int", "slice"), bits)
            elif op == "DUP":
                value = pop()
                stack.extend([value, value])
            elif op == "OVER":
                if len(stack) < 2:
                    raise StackUnderflow()
                stack.append(stack[-2])
            elif op == "2OVER":
                if len(stack) < 4:
                    raise StackUnderflow()
                stack.extend(stack[-4:-2])
            elif op == "SWAP":
                a, b = pop(), pop()
                stack.extend([a, b])
            elif op == "DROP":
                discard(pop())
            elif op == "NIP":
                a = pop()
                discarded = pop()
                if discarded.op not in {"arg", "literal", "local"} and discarded not in stack and discarded != a:
                    a, = materialize(a)
                stack.append(a)
            elif op in {"ROT", "-ROT", "ROTREV"}:
                c, b, a = pop(), pop(), pop()
                stack.extend([b, c, a] if op == "ROT" else [c, a, b])
            elif op == "PUSHCONT" and len(instruction.blocks) == 1:
                stack.append(Expr("continuation", value=instruction.blocks[0]))
            elif op in {"CALLDICT", "CALL"} and methods is not None and not instruction.blocks:
                materialize()
                method_id = integer(instruction)
                if method_id <= 0:
                    raise UnsupportedInstruction(op, "Calling reserved entrypoint")
                callee = methods(method_id)
                operands = tuple(reversed([pop() for _ in range(callee.arguments)]))
                for value, kind in zip(operands, callee.argument_types):
                    require(value, kind)
                if callee.inline_body:
                    bindings = {f'arg{i}': value for i, value in enumerate(operands)}
                    locals_map = {}
                    def substitute(value):
                        if isinstance(value, Expr):
                            if value.op == 'arg':
                                return bindings[value.value]
                            if value.op == 'local':
                                if value.value not in locals_map:
                                    locals_map[value.value] = local(value.type)
                                return locals_map[value.value]
                            return replace(value, args=tuple(substitute(a) for a in value.args))
                        return replace(value, values=tuple(substitute(v) for v in value.values),
                                       then=tuple(substitute(s) for s in value.then),
                                       otherwise=tuple(substitute(s) for s in value.otherwise))
                    statements.extend(substitute(s) for s in callee.statements)
                    primitives.update((p.name, p) for p in callee.primitives)
                    for value in callee.returns:
                        value = substitute(value)
                        stack.append(value if value.op in {'arg', 'literal', 'local'} else computed(value))
                    materialize()
                    continue
                arg_types = dict(zip((f"arg{i}" for i in range(callee.arguments)), callee.argument_types))
                result_types = [arg_types[value.value] if value.op == "arg" else value.type for value in callee.returns]
                results = tuple(local(kind) for kind in result_types)
                call = Expr("call", operands, f"method_{method_id}")
                if results:
                    target = results[0] if len(results) == 1 else Expr("product", results)
                    statements.append(Statement("assign", (target, call)))
                else:
                    statements.append(Statement("call", (call,)))
                stack.extend(results)
            elif op in {"REPEAT", "WHILE", "UNTIL"}:
                materialize()
                body = pop()
                condition = None if op == 'UNTIL' else pop()
                if body.op != "continuation" or op == "WHILE" and condition.op != "continuation":
                    raise UnsupportedInstruction(op, "Dynamic loop continuation")
                # A true initial flag with an empty condition is a do/while loop:
                # the body consumes the old stack and leaves its next flag on top.
                if (op == 'WHILE' and not condition.value and stack
                        and stack[-1].op == 'literal' and isinstance(stack[-1].value, int)
                        and stack[-1].value != 0):
                    stack.pop()
                    body = replace(body, value=body.value + (Instruction('EQINT', ('0',)),))
                    op, condition = 'UNTIL', None
                if op == "REPEAT":
                    require(condition, "int")
                elif op == 'WHILE':
                    # Infer carried argument types from the condition before
                    # introducing loop variables (e.g. DUP SEMPTY requires slice).
                    probe = list(stack)
                    execute(condition.value, probe)
                # Infer types used only by the body before fixing loop-carried locals.
                probe = list(stack)
                execute(body.value, probe, True, True)
                carried = []
                for position, value in enumerate(stack):
                    kind = value_type(value)
                    if kind == 'unknown' and position < len(probe) and probe[position] == value:
                        # Keep invariant arguments unbound until a later consumer establishes their type.
                        carried.append(value)
                        continue
                    if kind in {'null', 'vector_empty'} and position < len(probe):
                        inferred = value_type(probe[position])
                        if inferred not in {'unknown', 'null'}:
                            kind = inferred
                    if kind == "unknown":
                        require(value, "int")
                        kind = "int"
                    target = local(kind)
                    statements.append(Statement("assign", (target, value)))
                    carried.append(target)
                if op == "WHILE":
                    condition_stack = list(carried)
                    condition_statements = execute(condition.value, condition_stack)
                    if len(condition_stack) != len(carried) + 1 or condition_stack[:-1] != carried:
                        raise UnsupportedInstruction(op, "Loop condition modifies carried stack or has side effects")
                    condition = condition_stack[-1]
                    if (len(condition_statements) == 1 and condition_statements[0].kind == 'assign'
                            and condition_statements[0].values[0].op == 'local'):
                        target, call = condition_statements[0].values
                        occurrences = 0
                        def inline(value):
                            nonlocal occurrences
                            if value == target:
                                occurrences += 1
                                return call
                            return Expr(value.op, tuple(inline(arg) for arg in value.args), value.value, value.type)
                        inlined = inline(condition)
                        if occurrences == 1:
                            condition, condition_statements = inlined, ()
                    require(condition, "int")
                body_stack = list(carried)
                body_statements = list(execute(body.value, body_stack, True, True))
                if op == 'UNTIL':
                    if not body_stack:
                        raise UnsupportedInstruction(op, 'Missing until condition')
                    condition_value = body_stack.pop()
                    require(condition_value, 'int')
                    condition = local('int')
                    statements.append(Statement('assign', (condition, Expr('literal', value=0))))
                    body_statements.append(Statement('set', (condition, condition_value)))
                if len(body_stack) != len(carried):
                    raise UnsupportedInstruction(op, "Loop changes stack height")
                updates = []
                for target, value in zip(carried, body_stack):
                    if target == value:
                        continue
                    if target.op != 'local':
                        raise UnsupportedInstruction(op, 'Loop changes an inferred invariant')
                    require(value, target.type)
                    updates.append((target, value))
                if updates:
                    targets, values = zip(*updates)
                    body_statements.append(Statement("set", (Expr("product", targets), Expr("product", values))))
                if op == 'WHILE' and condition_statements:
                    # Re-evaluate all condition effects exactly once per iteration, including the final check.
                    flag = local('int')
                    statements.append(Statement('assign', (flag, Expr('literal', value=-1))))
                    body_statements = [*condition_statements, Statement('set', (flag, condition)),
                                       Statement('if', (flag,), tuple(body_statements))]
                    condition = flag
                statements.append(Statement(op.lower(), (condition,), tuple(body_statements)))
                stack[:] = carried
            elif op in {"IFJMP", "IFNOTJMP"}:
                materialize()
                continuation, condition = pop(), pop()
                if continuation.op != "continuation":
                    raise UnsupportedInstruction(op, "Dynamic early-return continuation")
                require(condition, "int")
                if op == "IFNOTJMP":
                    condition = Expr("binary", (condition, Expr("literal", value=0)), "==")
                branch_stack = list(stack)
                body = execute(continuation.value, branch_stack, True, loop_context)
                if loop_context and not terminal(body):
                    raise UnsupportedInstruction(op, 'Continuation jump is not a function return')
                statements.append(Statement("if", (condition,), body if terminal(body) else body + (Statement("return", tuple(branch_stack)),)))
            elif op in {"IF", "IFNOT", "IFELSE"}:
                materialize()
                otherwise = pop() if op == "IFELSE" else Expr("continuation", value=())
                then, condition = pop(), pop()
                if then.op != "continuation" or otherwise.op != "continuation":
                    raise UnsupportedInstruction(op, "Dynamic continuation")
                if op == "IFNOT":
                    then, otherwise = otherwise, then
                require(condition, "int")
                left, right = list(stack), list(stack)
                left_statements = execute(then.value, left, True, loop_context or index != len(code) - 1)
                right_statements = execute(otherwise.value, right, True, loop_context or index != len(code) - 1)
                left_terminal, right_terminal = terminal(left_statements), terminal(right_statements)
                if left_terminal or right_terminal:
                    if left_terminal and right_terminal:
                        statements.append(Statement('if', (condition,), left_statements, right_statements))
                        stack.clear()
                        break
                    # Keep surviving branch locals in the surrounding scope.
                    if left_terminal:
                        statements.append(Statement('if', (condition,), left_statements))
                        statements.extend(right_statements)
                        stack[:] = right
                    else:
                        negated = Expr('binary', (condition, Expr('literal', value=0)), '==')
                        statements.append(Statement('if', (negated,), right_statements))
                        statements.extend(left_statements)
                        stack[:] = left
                    continue
                if len(left) != len(right):
                    raise UnsupportedInstruction(op, "Branch stack heights differ")
                if left_statements or right_statements:
                    merged, left_assign, right_assign = [], [], []
                    for a, b in zip(left, right):
                        if a == b:
                            merged.append(a)
                            continue
                        kind = value_type(a)
                        if kind in {"unknown", "null", "vector_empty"}:
                            kind = value_type(b)
                        if kind in {"unknown", "null"}:
                            kind = "cell" if "null" in {value_type(a), value_type(b)} else "int"
                        require(a, kind)
                        require(b, kind)
                        target = local(kind)
                        default = Expr("literal", value=0)
                        if kind != "int":
                            default = Expr("literal", value="null()", type=kind)
                        statements.append(Statement("assign", (target, default)))
                        merged.append(target)
                        left_assign.append(Statement("set", (target, a)))
                        right_assign.append(Statement("set", (target, b)))
                    statements.append(Statement("if", (condition,), left_statements + tuple(left_assign), right_statements + tuple(right_assign)))
                    stack[:] = merged
                    continue
                merged = []
                for a, b in zip(left, right):
                    if a == b:
                        merged.append(a)
                        continue
                    kinds = {value_type(a), value_type(b)} - {"unknown", "null", "vector_empty"}
                    if len(kinds) > 1:
                        raise UnsupportedInstruction(op, "Conditional value types differ")
                    kind = next(iter(kinds), "cell" if "null" in {value_type(a), value_type(b)} else "int")
                    require(a, kind)
                    require(b, kind)
                    merged.append(computed(Expr("select", (condition, a, b), type=kind)))
                stack[:] = merged
            elif op in {"THROW", "THROWIF", "THROWIFNOT", "THROWANY"}:
                materialize()
                number = pop() if op == "THROWANY" else Expr("literal", value=integer(instruction))
                require(number, "int")
                values = (number,) if op in {"THROW", "THROWANY"} else (number, pop())
                if len(values) == 2:
                    require(values[1], 'int')
                statements.append(Statement("throw" if op == "THROWANY" else op.lower(), values))
                if op in {"THROW", "THROWANY"}:
                    break
            else:
                raise UnsupportedInstruction(op)
        if preserve_result_order and pending:
            # Constants have no effects and terminal return scheduling is the
            # compiler's job. Only potentially trapping expressions require
            # ordered materialization when the result stack was permuted.
            expected = [id(value) for value in pending if value.op != "literal"]
            pending_ids = set(expected)
            observed = []
            def evaluation_order(value):
                for argument in value.args:
                    evaluation_order(argument)
                if id(value) in pending_ids:
                    observed.append(id(value))
            for value in stack:
                evaluation_order(value)
            if observed != expected:
                materialize()
        return tuple(statements)

    statements = execute(instructions, initial, True)
    if any(value.op == "continuation" for value in initial):
        raise UnsupportedInstruction("PUSHCONT", "Continuation escapes function")
    exits = [tuple(initial)]
    def find_returns(body):
        for statement in body:
            if statement.kind == "return":
                exits.append(statement.values)
            find_returns(statement.then)
            find_returns(statement.otherwise)
    find_returns(statements)
    if any(len(values) != len(initial) for values in exits):
        raise UnsupportedInstruction("return", "Early and final return stack heights differ")
    return_types = []
    for position in range(len(initial)):
        kinds = {value_type(values[position]) for values in exits} - {"null", "unknown"}
        if len(kinds) > 1:
            raise UnsupportedInstruction("return", "Early and final return types differ")
        kind = next(iter(kinds), "cell" if any(value_type(values[position]) == "null" for values in exits) else "int")
        for values in exits:
            require(values[position], kind)
        return_types.append(kind)
    def typed_returns(values):
        return tuple(replace(value, type=kind) for value, kind in zip(values, return_types))
    def type_statements(body):
        return tuple(replace(statement, values=typed_returns(statement.values) if statement.kind == "return" else statement.values,
                             then=type_statements(statement.then), otherwise=type_statements(statement.otherwise)) for statement in body)
    initial[:] = typed_returns(initial)
    statements = type_statements(statements)
    return StackIR(arguments, tuple(initial), statements, bool(statements), tuple(argument_types.get(f"arg{i}", f"X{i}") for i in range(arguments)), tuple(primitives.values()))
