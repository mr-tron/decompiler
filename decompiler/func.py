"""Small FunC AST and its independent printer and equivalent rewrites."""
from dataclasses import asdict, dataclass, replace
from collections import Counter
import json
import re
from .asm import Instruction, Program, walk
from .ir import Expr, Statement, Primitive, analyze, UnsupportedInstruction


@dataclass(frozen=True)
class Function:
    name: str
    arguments: tuple[tuple[str, str], ...]
    returns: tuple[Expr, ...]
    statements: tuple[Statement, ...] = ()
    method_id: int | None = None
    impure: bool = False
    assembly: tuple[str, ...] | None = None
    diagnostic: str | None = None
    inline_ref: bool = False


@dataclass(frozen=True)
class Module:
    functions: tuple[Function, ...]
    primitives: tuple[Primitive, ...] = ()


def primitive_name(name):
    """Use familiar stdlib names; raw helpers retain TVM stack order."""
    names = {
        'getdata': 'get_data', 'setdata': 'set_data', 'ctos': 'begin_parse',
        'getprecompiledgas': 'get_precompiled_gas_consumption', 'storagefees': 'get_storage_fees',
        'incomingvalue': 'get_incoming_value', 'pldrefvar': 'preload_ref_raw',
        'newc': 'begin_cell', 'endc': 'end_cell', 'balance': 'get_balance',
        'now': 'now', 'ltime': 'cur_lt', 'blocklt': 'block_lt', 'myaddr': 'my_address',
        'rewritestdaddr': 'parse_std_addr', 'sbits': 'slice_bits', 'srefs': 'slice_refs',
        'sempty': 'slice_empty?', 'sdempty': 'slice_data_empty?', 'sdeq': 'equal_slice_bits',
        'hashcu': 'cell_hash', 'hashsu': 'slice_hash', 'plddict': 'preload_dict',
        'xctos': 'begin_parse_raw', 'dictuaddb': 'udict_add_builder_raw',
        'sdcnttrail0': 'count_trailing_zeroes', 'chksignu': 'check_signature',
        'accept': 'accept_message', 'commit': 'commit', 'setc5': 'set_actions',
        'sdcutlast': 'get_last_bits', 'sdskiplast': 'remove_last_bits',
        'ldslicex': 'load_bits_raw', 'sha256u': 'string_hash',
        'sbitrefs': 'slice_bits_refs', 'skipdict': 'skip_dict', 'sdsubstr': 'slice_substring',
        'setgaslimit': 'set_gas_limit', 'setrand': 'set_seed', 'mycode': 'my_code',
        'getgasfee': 'get_gas_fee', 'getstoragefee': 'get_storage_fee_raw',
        'getforwardfee': 'get_forward_fee_raw', 'getoriginalfwdfee': 'get_original_fwd_fee',
        'getgasfeesimple': 'get_gas_fee_simple', 'getforwardfeesimple': 'get_forward_fee_simple_raw',
        'duepayment': 'get_due_payment', 'gasconsumed': 'gas_consumed',
        'brembits': 'builder_remaining_bits', 'bremrefs': 'builder_remaining_refs',
        'stslice': 'store_slice_raw', 'stb': 'store_builder_raw', 'ldrefrtos': 'load_ref_slice_raw',
        'rewritevaraddr': 'parse_var_addr', 'sdppfxrev': 'has_proper_prefix_raw',
        'divc': 'div_ceil', 'divr': 'div_round',
        'dictuadd': 'udict_add_raw', 'dictiadd': 'idict_add_raw',
        'dictudelget': 'udict_delete_get_raw', 'dictidelget': 'idict_delete_get_raw',
        'rawreserve': 'raw_reserve', 'setcode': 'set_code', 'min': 'min', 'max': 'max',
        'sdepth': 'slice_depth', 'cdepth': 'cell_depth', 'rand': 'random',
        'addrand': 'add_random_seed', 'cdatasize': 'cell_data_size_raw',
        'dictigetoptref': 'idict_get_opt_ref_raw', 'dictugetoptref': 'udict_get_opt_ref_raw',
        'dictisetb': 'idict_set_builder_raw', 'dictusetb': 'udict_set_builder_raw',
        'throwanyif': 'throw_any_if_raw', 'throwanyifnot': 'throw_any_if_not_raw',
        'ldux': 'load_uint_raw', 'ldix': 'load_int_raw',
        'pldux': 'preload_uint_raw', 'pldix': 'preload_int_raw',
        'pldslicex': 'preload_slice_raw',
        'changelib': 'change_library', 'divmod': 'divmod_raw',
        'chksigns': 'check_data_signature', 'randu256': 'random_uint256', 'ubitsize': 'unsigned_bitsize', 'bitsize': 'signed_bitsize',
        'dictidel': 'idict_delete_raw', 'pfxdictgetq': 'pfxdict_get_raw', 'stux': 'store_uint_raw', 'stix': 'store_int_raw',
        'brefs': 'builder_refs', 'bbits': 'builder_bits', 'setlibcode': 'set_library_code',
        'dictuset': 'udict_set_raw', 'dictiset': 'idict_set_raw',
        'isnull': 'is_null', 'sendrawmsg': 'send_raw_message', 'configoptparam': 'config_param',
        'stslicer': 'store_slice', 'stgrams': 'store_coins', 'stbr': 'store_builder',
        'sdskipfirst': 'skip_bits', 'ldmsgaddr': 'load_msg_addr_raw',
        'ldref': 'load_ref_raw', 'lddict': 'load_dict_raw', 'ldgrams': 'load_coins_raw',
        'stref': 'store_ref_raw', 'stdict': 'store_dict_raw',
        'dictugetref': 'udict_get_ref_raw', 'dictigetref': 'idict_get_ref_raw',
        'dictuget': 'udict_get_raw', 'dictiget': 'idict_get_raw',
        'dictusetref': 'udict_set_ref_raw', 'dictisetref': 'idict_set_ref_raw',
        'dictudel': 'udict_delete_raw', 'dictidel': 'idict_delete_raw',
        'muldiv': 'muldiv_raw',
    }
    if not name.startswith('tvm_'):
        return name
    suffix = name[4:]
    if suffix in names:
        return names[suffix]
    if suffix.startswith('pushref_'):
        return 'referenced_cell_' + suffix.removeprefix('pushref_')
    if suffix.startswith('pushrefslice_'):
        return 'referenced_slice_' + suffix.removeprefix('pushrefslice_')
    if suffix.startswith('modpow2_'):
        return 'mod_power_of_two_' + suffix.removeprefix('modpow2_')
    match = re.fullmatch(r'(index|untuple)_([0-9]+)', suffix)
    if match:
        return ('tuple_at_' if match[1] == 'index' else 'unpack_tuple_') + match[2]
    match = re.fullmatch(r'(pldslice|pldrefidx)_([0-9]+)', suffix)
    if match:
        operation, index = match.groups()
        return ('preload_bits_' + index if operation == 'pldslice' else
                'preload_ref' if index == '0' else 'preload_ref_' + index)
    match = re.fullmatch(r'(getglob|setglob)_([0-9]+)', suffix)
    if match:
        return ('get_global_' if match[1] == 'getglob' else 'set_global_') + match[2]
    match = re.fullmatch(r'pushslice_([0-9a-f_]+)', suffix)
    if match:
        return 'push_slice_' + match[1]
    if suffix == 'pushslice_':
        return 'push_slice_empty'
    match = re.fullmatch(r'mulrshift(r|c)?_([0-9]+)', suffix)
    if match:
        rounding, width = match.groups()
        name = {'': 'mul_rshift_raw', 'r': 'mul_rshift_round_raw', 'c': 'mul_rshift_ceil_raw'}[rounding or '']
        return f'{name}_{width}'
    match = re.fullmatch(r'dict([ui])(min|max|getnext(?:eq)?|getprev(?:eq)?)', suffix)
    if match:
        sign, operation = match.groups()
        operation = {'min': 'get_min', 'max': 'get_max', 'getnext': 'get_next',
                     'getnexteq': 'get_next_eq', 'getprev': 'get_prev',
                     'getpreveq': 'get_prev_eq'}[operation]
        return f'{sign}dict_{operation}_raw'
    match = re.fullmatch(r'dict([ui])rem(min|max)', suffix)
    if match:
        return f'{match[1]}dict_remove_{match[2]}_raw'
    match = re.fullmatch(r'dict([ui])setgetoptref', suffix)
    if match:
        return f'{match[1]}dict_set_get_opt_ref_raw'
    match = re.fullmatch(r'(sdbeginsq?)_([0-9a-f]+)', suffix)
    if match:
        operation, prefix = match.groups()
        return f'remove_prefix_{prefix}' + ('_quiet' if operation == 'sdbeginsq' else '')
    match = re.fullmatch(r'(ldu|ldi|pldu|pldi|stu|sti)_([0-9]+)', suffix)
    if match:
        operation, width = match.groups()
        operation = {'ldu': 'load_uint', 'ldi': 'load_int', 'pldu': 'preload_uint',
                     'pldi': 'preload_int', 'stu': 'store_uint', 'sti': 'store_int'}[operation]
        return f'{operation}_{width}_raw'
    return name


def _check_dispatcher(program):
    opcodes = tuple(i.opcode for i in program.instructions)
    if opcodes not in (("SETCP0", "DICTPUSHCONST", "DICTIGETJMPZ", "THROWARG"), ("SETCP", "DICTPUSHCONST", "DICTIGETJMPZ", "THROWARG")):
        raise UnsupportedInstruction("dispatcher", "Method dictionary has nonstandard entry dispatch")
    if program.instructions[0].opcode == "SETCP" and program.instructions[0].operands != ("0",):
        raise UnsupportedInstruction("dispatcher", "Nonzero TVM code page")
    if not program.instructions[1].operands or program.instructions[1].operands[0] != "19":
        raise UnsupportedInstruction("dispatcher", "Nonstandard method dictionary key length")
    if program.instructions[-1].operands != ("11",):
        raise UnsupportedInstruction("dispatcher", "Nonstandard missing-method exception")


def fallback(program: Program) -> Module:
    """Preserve method bodies in FunC asm when structured lifting is unsupported.

    This is a fidelity candidate, not a claim of high-level reconstruction.
    Only literal operands and structured continuations are reassemblable here;
    missing reference-cell contents explicitly fail.
    """
    _check_dispatcher(program)

    def assembly(code):
        lines = []
        for instruction in code:
            op = instruction.opcode
            if not re.fullmatch(r"(?:-?[0-9]*[A-Z][A-Z0-9_#?+-]*|DUMPs[0-9]+)", op):
                raise UnsupportedInstruction(op, "Invalid assembly opcode")
            if instruction.blocks:
                if op in {"IFELSE", "WHILE"} and len(instruction.blocks) == 2:
                    lines.append(("IF" if op == "IFELSE" else "WHILE") + ":<{")
                    lines.extend(assembly(instruction.blocks[0]))
                    lines.append("}>ELSE<{" if op == "IFELSE" else "}>DO<{")
                    lines.extend(assembly(instruction.blocks[1]))
                    lines.append("}>")
                elif len(instruction.blocks) == 1 and op in {"CONT", "PUSHCONT", "IF", "IFNOT", "IFJMP", "IFNOTJMP", "REPEAT", "UNTIL", "CALL", "JMP"}:
                    lines.append(("CONT" if op == "PUSHCONT" else op) + ":<{")
                    lines.extend(assembly(instruction.blocks[0]))
                    lines.append("}>")
                else:
                    raise UnsupportedInstruction(op, "Nested dictionary/reference layout is not reassemblable")
            else:
                for value in instruction.operands:
                    if not re.fullmatch(r"(?:-?(?:[0-9]+|0x[0-9a-fA-F]+)|[sc](?:[0-9]+|\(-?[0-9]+\))|x\{[0-9a-fA-F_]*\})", value):
                        raise UnsupportedInstruction(op, "Reference or operand cannot be reproduced from disassembly")
                lines.append(" ".join((*instruction.operands, op)))
        return tuple(lines)

    functions = []
    for method_id, code in sorted(program.methods.items()):
        name = {0: "recv_internal", -1: "recv_external", -2: "run_ticktock"}.get(method_id, f"method_{method_id}" if method_id >= 0 else f"method_neg_{-method_id}")
        functions.append(Function(name, (), (), method_id=method_id if method_id not in (0, -1, -2) else None, impure=True, assembly=assembly(code)))
    return Module(tuple(functions))


def fallback_cells(program: Program, method_cells: dict[int, bytes]) -> Module:
    """Opaque, lossless method candidate from toolchain-extracted BOC cells."""
    _check_dispatcher(program)
    if set(method_cells) != set(program.methods):
        raise UnsupportedInstruction("dictionary", "Extracted method set differs from disassembly")
    functions = []
    for method_id, boc in sorted(method_cells.items()):
        if not isinstance(boc, bytes) or not boc:
            raise UnsupportedInstruction("cell", "Missing serialized method cell")
        name = {0: "recv_internal", -1: "recv_external", -2: "run_ticktock"}.get(method_id, f"method_{method_id}" if method_id >= 0 else f"method_neg_{-method_id}")
        opcodes = [instruction.opcode for instruction in walk(program.methods[method_id])]
        diagnostic = "Opaque TVM method; preserved instructions: " + " ".join(opcodes[:40])
        if len(opcodes) > 40:
            diagnostic += " ..."
        # @addop reserves a reference and would split a four-reference method.
        functions.append(Function(name, (), (), method_id=method_id if method_id not in (0, -1, -2) else None, impure=True, assembly=(f"B{{{boc.hex()}}} B>boc <s s,",), diagnostic=diagnostic))
    return Module(tuple(functions))


def _function(method_id, ir):
    if method_id in (0, -1):
        if ir.arguments > (1 if method_id == -1 else 4):
            raise UnsupportedInstruction("entrypoint", "Inferred arguments exceed the entrypoint stack signature")
        types = ('slice',) if method_id == -1 else ("int", "int", "cell", "slice")
        arguments = tuple((kind, f"arg{i}") for i, kind in enumerate(types[len(types) - ir.arguments:]))
        name = 'recv_external' if method_id == -1 else "recv_internal"
    else:
        arguments = tuple((kind, f"arg{i}") for i, kind in enumerate(ir.argument_types))
        name = "run_ticktock" if method_id == -2 else f"method_{method_id}" if method_id >= 0 else f"method_neg_{-method_id}"
    if method_id in (0, -1) and any(value.op not in {"arg", "literal", "local"} for value in ir.returns):
        raise UnsupportedInstruction("return", "Unused entrypoint computation could raise a TVM exception")
    returns = () if method_id in (0, -1) else ir.returns
    # TVM arithmetic can trap even when a caller drops its result.
    return Function(name, arguments, returns, ir.statements, method_id if method_id not in (0, -1) else None, True)


def _reconstruct(program, cell_fallback=None, debug_ir=None, preserve_constants=()):
    if program.methods:
        _check_dispatcher(program)
    methods = program.methods if cell_fallback is not None else program.methods or {0: program.instructions}
    original_ids = set(methods)
    methods = dict(methods)
    auxiliaries, bodies = set(), {}
    stable_dispatcher = not any(
        i.opcode != 'PUSH' and 'c3' in i.operands
        or i.opcode.startswith(('SETCONT', 'POPCTR', 'CALLCC', 'BLESS', 'TRY'))
        or i.opcode == 'POP' and any(r in {'c0', 'c1', 'c2'} for r in i.operands)
        for body in methods.values() for i in walk(body))
    def extract(code):
        result = []
        index = 0
        while index < len(code):
            instruction = code[index]
            if (stable_dispatcher and instruction.opcode == 'PUSHINT' and index + 2 < len(code)
                    and code[index + 1].opcode == 'PUSH' and code[index + 1].operands == ('c3',)
                    and code[index + 2].opcode == 'EXECUTE'):
                result.append(Instruction('CALLDICT', instruction.operands))
                index += 3
                continue
            static_call = instruction.opcode == 'CALL' and len(instruction.blocks) == 1
            execute_call = (instruction.opcode in {'CONT', 'PUSHCONT'} and len(instruction.blocks) == 1
                            and index + 1 < len(code) and code[index + 1].opcode == 'EXECUTE')
            if static_call or execute_call:
                body = tuple(extract(instruction.blocks[0]))
                key = tuple(i.normalized() for i in body)
                if key not in bodies:
                    method_id = max((*methods, 0)) + 1
                    bodies[key] = method_id
                    methods[method_id] = body
                    auxiliaries.add(method_id)
                result.append(Instruction('CALLDICT', (str(bodies[key]),)))
                index += int(execute_call)
            else:
                result.append(replace(instruction, blocks=tuple(tuple(extract(b)) for b in instruction.blocks)))
            index += 1
        return result
    for method_id in sorted(original_ids):
        methods[method_id] = tuple(extract(methods[method_id]))
    analyzed, functions, failures, active = {}, {}, {}, set()
    global_types = {}

    def method_ir(method_id):
        if method_id in failures:
            raise failures[method_id]
        if method_id in active or method_id not in methods:
            raise UnsupportedInstruction("CALLDICT", "Recursive or missing method requires an explicit signature")
        if method_id not in analyzed:
            active.add(method_id)
            try:
                ir = analyze(methods[method_id], methods=method_ir,
                             preserve_constants=method_id in preserve_constants, global_types=global_types,
                             argument_types_hint={0: ('int', 'int', 'cell', 'slice'), -1: ('slice',)}.get(method_id))
                if method_id in auxiliaries and any(0 < key <= len(auxiliaries) for key in original_ids):
                    def has_return(statements):
                        return any(s.kind == 'return' or has_return(s.then) or has_return(s.otherwise)
                                   for s in statements)
                    def loop_return(statements):
                        return any(s.kind in {'while', 'until', 'repeat'} and has_return(s.then)
                                   or loop_return(s.then) or loop_return(s.otherwise) for s in statements)
                    if has_return(ir.statements) and not loop_return(ir.statements):
                        first = 1 + max((int(e.value[1:]) for v in (*ir.statements, *ir.returns)
                                         for e in _expressions(v) if e.op == 'local'), default=-1)
                        targets = tuple(Expr('local', value=f'v{first+i}', type=v.type)
                                        for i, v in enumerate(ir.returns))
                        rewritten_count = 0
                        def lower(statements):
                            nonlocal rewritten_count
                            result = []
                            for pos, statement in enumerate(statements):
                                rewritten_count += 1
                                # simple: bound branch-tail duplication; larger helpers retain their call.
                                if rewritten_count > 256:
                                    raise UnsupportedInstruction('CALL', 'Early-return inlining exceeds 256 statements')
                                if statement.kind == 'return':
                                    values = tuple(v if v.op in {'arg', 'local', 'literal'} else
                                                   Expr('call', (v,), 'impure_touch', v.type)
                                                   for v in statement.values)
                                    if targets:
                                        result.append(Statement('set', (Expr('product', targets), Expr('product', values))))
                                    break
                                if statement.kind == 'if' and has_return((statement,)):
                                    tail = statements[pos+1:]
                                    result.append(replace(statement, then=lower(statement.then + tail),
                                                          otherwise=lower(statement.otherwise + tail)))
                                    break
                                result.append(statement)
                            return tuple(result)
                        defaults = tuple(Statement('assign', (v, Expr('literal', value=0 if v.type == 'int' else 'null()', type=v.type)))
                                         for v in targets)
                        ir.statements = defaults + lower(ir.statements + (Statement('return', ir.returns),))
                        ir.returns = targets
                        ir.primitives += (Primitive('impure_touch', ('X',), ('X',), 'NOP'),)
                    # Automatic helper IDs collide with explicit low method IDs.
                    ir.inline_body = not has_return(ir.statements)
                if debug_ir is not None:
                    debug_ir[str(method_id)] = asdict(ir)
                function = _function(method_id, ir)
                if method_id in auxiliaries:
                    function = replace(function, method_id=None, inline_ref=True)
                analyzed[method_id] = ir
                functions[method_id] = function
            except UnsupportedInstruction as exc:
                failures[method_id] = exc
                if debug_ir is not None:
                    debug_ir[str(method_id)] = {"error": str(exc), "opcode": exc.opcode}
                raise
            finally:
                active.remove(method_id)
        return analyzed[method_id]

    for method_id in sorted(original_ids):
        try:
            method_ir(method_id)
        except UnsupportedInstruction:
            if cell_fallback is None:
                raise
    primitives = {primitive.name: primitive for ir in analyzed.values() for primitive in ir.primitives}
    if cell_fallback is not None:
        for method_id in sorted(original_ids & failures.keys()):
            functions[method_id] = cell_fallback[method_id]
    unsupported = [f"method {method_id}: {exc.opcode}: {exc}" for method_id, exc in sorted(failures.items())]
    return Module(tuple(functions.values()), tuple(primitives.values())), unsupported


def resolve_references(program: Program, boc: bytes) -> Program:
    """Recover referenced literals from the supplied BOC, never from source examples."""
    from .boc import parse_boc, _slice_boc
    parsed = parse_boc(boc)
    cells = {cell.digest.hex().lower(): index for index, cell in enumerate(parsed.cells)}
    def resolve(code):
        result = []
        for instruction in code:
            if instruction.opcode in {'PUSHREFSLICE', 'PUSHREF'} and len(instruction.operands) == 1:
                digest = instruction.operands[0].strip('()').lower()
                if digest in cells:
                    instruction = replace(instruction, operands=(_slice_boc(parsed, cells[digest], 0).hex(),))
            result.append(replace(instruction, blocks=tuple(resolve(block) for block in instruction.blocks)))
        return tuple(result)
    return Program(resolve(program.instructions), {key: resolve(body) for key, body in program.methods.items()})


def reconstruct(program: Program, debug_ir=None, preserve_constants=()) -> Module:
    return _reconstruct(program, debug_ir=debug_ir, preserve_constants=preserve_constants)[0]


def reconstruct_partial(program: Program, method_cells: dict[int, bytes], debug_ir=None, preserve_constants=()):
    """Lift independent methods; preserve unsupported methods and their callers.

    A high-level caller is never linked to an opaque method with an unknown
    signature. Failed callees propagate failure before source is generated.
    """
    fallback_module = fallback_cells(program, method_cells)
    cell_fallback = dict(zip(sorted(method_cells), fallback_module.functions))
    return _reconstruct(program, cell_fallback, debug_ir, preserve_constants)


def _builder_method(name):
    match = re.fullmatch(r'tvm_st([ui])_([0-9]+)', name)
    if match:
        return 'store_uint' if match[1] == 'u' else 'store_int'
    return primitive_name(name).removesuffix('_raw')


def _builder_chains(value):
    if isinstance(value, Statement):
        # A discarded store must retain its impure helper so overflow still throws.
        values = tuple(_builder_chains(v) for v in value.values)
        if value.kind == 'call' and values and values[0].op == 'chain':
            values = (replace(value.values[0], args=tuple(_builder_chains(a) for a in value.values[0].args)),)
        return replace(value, values=values, then=tuple(_builder_chains(s) for s in value.then),
                       otherwise=tuple(_builder_chains(s) for s in value.otherwise))
    value = replace(value, args=tuple(_builder_chains(a) for a in value.args))
    if value.op != 'call':
        return value
    width = re.fullmatch(r'tvm_st[ui]_([0-9]+)', value.value)
    if width or value.value in {'tvm_stref', 'tvm_stdict'}:
        # Moving an effectful value behind the builder would change evaluation order.
        if len(value.args) != 2 or value.args[0].op not in {'literal', 'arg', 'local'}:
            return value
        args = (value.args[1], value.args[0])
        if width:
            args += (Expr('literal', value=int(width[1])),)
        return replace(value, op='chain', args=args)
    if value.value in {'tvm_stslicer', 'tvm_stgrams', 'tvm_stbr', 'tvm_endc'}:
        return replace(value, op='chain')
    return value


def expression(expr: Expr) -> str:
    if expr.op in {"arg", "local", "literal"}:
        if (expr.op == "literal" and type(expr.value) is int and expr.value > 2**29
                and not 1546300800 <= expr.value <= 1893456000):  # UTC 2019-01-01 through 2030-01-01
            return hex(expr.value)
        return str(expr.value)
    if expr.op == 'chain':
        return f"{expression(expr.args[0])}.{_builder_method(expr.value)}({', '.join(map(expression, expr.args[1:]))})"
    if expr.op == "modify":
        return f"{expression(expr.args[0])}~{primitive_name(expr.value).removesuffix("_raw")}({", ".join(map(expression, expr.args[1:]))})"
    if expr.op == "binary":
        return f"({expression(expr.args[0])} {expr.value} {expression(expr.args[1])})"
    if expr.op == "unary":
        return f"({expr.value} {expression(expr.args[0])})"
    if expr.op == "select":
        return f"({expression(expr.args[0])} ? {expression(expr.args[1])} : {expression(expr.args[2])})"
    if expr.op == "call":
        return f"{primitive_name(expr.value)}({', '.join(map(expression, expr.args))})"
    if expr.op == "tuple":
        return "[" + ", ".join(map(expression, expr.args)) + "]"
    if expr.op == "product":
        return "(" + ", ".join(map(expression, expr.args)) + ")"
    raise UnsupportedInstruction(expr.op, "Expression cannot be printed")


def _formatted_expression(value, indent):
    if value.op == 'chain':
        receiver = _formatted_expression(value.args[0], indent)
        return receiver + '\n' + ' ' * (indent + 4) + '.' + _builder_method(value.value) + '(' + ', '.join(map(expression, value.args[1:])) + ')'
    if value.op == 'call' and any(a.op == 'chain' for a in value.args):
        return primitive_name(value.value) + '(\n' + ',\n'.join(
            ' ' * (indent + 4) + _formatted_expression(a, indent + 4) for a in value.args) + '\n' + ' ' * indent + ')'
    return expression(value)


def _statement(statement, indent=2):
    pad = " " * indent
    values = [_formatted_expression(value, indent) for value in statement.values]
    if statement.kind in {"throw", "throwif", "throwifnot"}:
        name = {"throw": "throw", "throwif": "throw_if", "throwifnot": "throw_unless"}[statement.kind]
        return [f"{pad}{name}({', '.join(values)});"]
    if statement.kind == "assign":
        return [f"{pad}var {values[0]} = {values[1]};"]
    if statement.kind == "call":
        return [f"{pad}{values[0]};"]
    if statement.kind == "set":
        return [f"{pad}{values[0]} = {values[1]};"]
    if statement.kind == "return":
        return [f"{pad}return ({', '.join(values)});"]
    if statement.kind == 'until':
        lines = [pad + 'do {']
        for child in statement.then:
            lines.extend(_statement(child, indent + 2))
        lines.append(pad + '} until (' + values[0] + ');')
        return lines
    if statement.kind in {"if", "while", "repeat"}:
        condition = values[0][1:-1] if statement.values[0].op == 'binary' else values[0]
        lines = [f"{pad}{statement.kind} ({condition}) {{"]
        for child in statement.then:
            lines.extend(_statement(child, indent + 2))
        lines.append(pad + "}")
        if statement.otherwise:
            lines[-1] += " else {"
            for child in statement.otherwise:
                lines.extend(_statement(child, indent + 2))
            lines.append(pad + "}")
        return lines
    raise UnsupportedInstruction(statement.kind, "Statement cannot be printed")


def _expressions(value):
    if isinstance(value, Expr):
        yield value
        for arg in value.args:
            yield from _expressions(arg)
    elif isinstance(value, Statement):
        for item in (*value.values, *value.then, *value.otherwise):
            yield from _expressions(item)


def _variable_uses(body):
    reads, writes = Counter(), Counter()
    def count(body):
        for statement in body:
            values = statement.values
            if statement.kind in {'assign', 'set'}:
                writes.update(e.value for e in _expressions(values[0]) if e.op in {'local', 'arg'})
                values = values[1:]
            reads.update(e.value for value in values for e in _expressions(value) if e.op in {'local', 'arg'})
            count((*statement.then, *statement.otherwise))
    count(body)
    return reads, writes


def simplify_temporaries(module: Module) -> Module:
    """Inline single-use values without changing whether/when effects execute."""
    functions = []
    for function in module.functions:
        if function.assembly is not None:
            functions.append(function)
            continue
        body = (*function.statements, Statement('return', function.returns))
        reads, writes = _variable_uses(body)

        def pure(value):
            if value.op == 'literal':
                return True
            if value.op in {'arg', 'local'}:
                return writes[value.value] == (1 if value.op == 'local' else 0)
            # Even comparisons can throw on TVM NaN; only values may move freely.
            return False

        def substitute(value, name, expression):
            if isinstance(value, Expr):
                if value.op == 'local' and value.value == name:
                    return expression
                return replace(value, args=tuple(substitute(a, name, expression) for a in value.args))
            return replace(value, values=tuple(substitute(v, name, expression) for v in value.values),
                           then=tuple(substitute(s, name, expression) for s in value.then),
                           otherwise=tuple(substitute(s, name, expression) for s in value.otherwise))

        def mentions(value, name):
            return any(e.op == 'local' and e.value == name for e in _expressions(value))

        def first_effect(value, name):
            # Ternary arms are conditional; the condition alone always executes.
            if value.op == 'select':
                return first_effect(value.args[0], name)
            if value.op == 'local' and value.value == name:
                return True
            for arg in value.args:
                if mentions(arg, name):
                    return first_effect(arg, name)
                if not pure(arg):
                    return False
            return False

        def simplify(body):
            body = list(body)
            result = []
            for index, statement in enumerate(body):
                if statement.kind == 'assign' and statement.values[0].op == 'local':
                    target, value = statement.values
                    name = target.value
                    if value.op == 'call' and value.value == 'impure_touch' and len(value.args) == 1:
                        value = value.args[0]
                    value = replace(value, type=target.type)
                    if writes[name] == 1:
                        if reads[name] == 0 and pure(value):
                            continue
                        # simple: quadratic tail scans; use def-use chains if large methods need it.
                        tail = body[index + 1:]
                        if reads[name] == 1 and any(mentions(s, name) for s in tail):
                            if pure(value):
                                body[index + 1:] = [substitute(s, name, value) for s in tail]
                                continue
                            consumer = tail[0]
                            values = consumer.values[1:] if consumer.kind in {'assign', 'set'} else consumer.values
                            # Do not move a one-time computation into a loop condition/body.
                            if consumer.kind in {'assign', 'set', 'call', 'return', 'if', 'repeat', 'throw', 'throwif', 'throwifnot'}:
                                for position, operand in enumerate(values):
                                    if mentions(operand, name):
                                        if all(pure(v) for v in values[:position]) and first_effect(operand, name):
                                            body[index + 1] = substitute(consumer, name, value)
                                            break
                                        break
                                if body[index + 1] != consumer:
                                    continue
                result.append(replace(statement, then=simplify(statement.then), otherwise=simplify(statement.otherwise)))
            return tuple(result)
        cleaned = simplify(body)
        functions.append(replace(function, statements=cleaned[:-1], returns=cleaned[-1].values))
    return replace(module, functions=tuple(functions))


def readable_module(module: Module) -> Module:
    """Recover slice mutation only when the previous slice version is dead."""
    module = simplify_temporaries(module)
    primitives = {p.name: p for p in module.primitives}
    loaders = {p.name for p in module.primitives if p.name in {
        'tvm_ldmsgaddr', 'tvm_ldgrams', 'tvm_ldref', 'tvm_lddict'
    } or re.fullmatch(r'tvm_ld[ui]_[0-9]+', p.name)}
    functions = []
    for function in module.functions:
        if function.assembly is not None:
            functions.append(function)
            continue
        body = (*function.statements, Statement('return', function.returns))
        reads, writes = _variable_uses(body)

        def rewrite(body, aliases, in_loop=False):
            aliases = dict(aliases)
            def resolve(value):
                if value.op in {'local', 'arg'} and value.value in aliases:
                    return aliases[value.value]
                return replace(value, args=tuple(resolve(a) for a in value.args))
            result = []
            for statement in body:
                if statement.kind == 'assign':
                    target, value = statement.values
                    is_load = value.op == 'call' and value.value in loaders and target.op == 'product'
                    is_skip = value.op == 'call' and value.value == 'tvm_sdskipfirst' and target.op == 'local'
                    if (is_load and len(target.args) == 2 or is_skip) and all(
                            writes[e.value] == 1 for e in _expressions(target) if e.op == 'local'):
                        remainder = target.args[1] if is_load else target
                        source = value.args[0]
                        skips = []
                        while source.op == 'call' and source.value == 'tvm_sdskipfirst':
                            skips.append(source)
                            source = source.args[0]
                        if source.op == 'local' and reads[source.value] == 1 and writes[source.value] == 1 and not in_loop:
                            cursor = resolve(source)
                        else:
                            cursor = remainder
                            result.append(Statement('assign', (cursor, resolve(source))))
                        for skip in reversed(skips):
                            result.append(Statement('call', (Expr('modify', (cursor, *map(resolve, skip.args[1:])), skip.value, '()'),)))
                        call = Expr('modify', (cursor, *map(resolve, value.args[1:])), value.value,
                                    target.args[0].type if is_load else '()')
                        if is_load and reads[target.args[0].value]:
                            result.append(Statement('assign', (target.args[0], call)))
                        else:
                            result.append(Statement('call', (call,)))
                        aliases[remainder.value] = cursor
                        continue
                    def discard(target):
                        if target.op == 'local' and not reads[target.value] and writes[target.value] == 1:
                            return Expr('literal', value='_', type=target.type)
                        return replace(target, args=tuple(discard(a) for a in target.args))
                    target = discard(target)
                    value = resolve(value)
                    if all(e.value == '_' for e in _expressions(target) if e.op != 'product'):
                        if value.op in {'literal', 'local', 'arg'}:
                            continue
                        if value.op != 'call':
                            primitives['impure_touch'] = Primitive('impure_touch', ('X',), ('X',), 'NOP')
                            value = Expr('call', (value,), 'impure_touch', value.type)
                        result.append(Statement('call', (value,)))
                    else:
                        result.append(replace(statement, values=(target, value)))
                    continue
                result.append(replace(statement, values=tuple(resolve(v) for v in statement.values),
                                      then=rewrite(statement.then, aliases, in_loop or statement.kind in {'while', 'repeat', 'until'}),
                                      otherwise=rewrite(statement.otherwise, aliases, in_loop)))
            return tuple(result)
        body = rewrite(body, {})
        names = {}
        def renumber(value):
            if isinstance(value, Expr):
                if value.op == 'local':
                    return replace(value, value=names.setdefault(value.value, f'v{len(names)}'))
                return replace(value, args=tuple(renumber(a) for a in value.args))
            return replace(value, values=tuple(renumber(v) for v in value.values),
                           then=tuple(renumber(s) for s in value.then), otherwise=tuple(renumber(s) for s in value.otherwise))
        body = tuple(_builder_chains(renumber(s)) for s in body)
        functions.append(replace(function, statements=body[:-1], returns=body[-1].values))
    return replace(module, functions=tuple(functions), primitives=tuple(primitives.values()))


def _named_module(module):
    """Infer conventional helper names; explicit method IDs remain unchanged."""
    load_calls = {'tvm_getdata', 'tvm_ctos', 'tvm_ldmsgaddr', 'tvm_ldgrams',
                  'tvm_ldref', 'tvm_lddict', 'tvm_sdskipfirst', 'tvm_sbits',
                  'tvm_srefs', 'tvm_sempty', 'tvm_sdempty', 'tvm_ends',
                  'impure_touch', 'null'}
    store_calls = {'tvm_setdata', 'tvm_newc', 'tvm_endc', 'tvm_stslicer',
                  'tvm_stgrams', 'tvm_stref', 'tvm_stdict', 'tvm_stbr',
                  'impure_touch', 'null'}
    matches = {'load_data': [], 'store_data': []}
    for function in module.functions:
        if function.assembly is not None or not re.fullmatch(r'method_(?:neg_)?[0-9]+', function.name):
            continue
        calls = Counter(e.value for v in (*function.statements, *function.returns)
                        for e in _expressions(v) if e.op in {'call', 'modify', 'chain'})
        # simple: recognize only direct storage helpers, not indirect wrappers.
        loads = {name for name in calls if re.fullmatch(r'tvm_(?:ld|pld)[ui]_[0-9]+', name)}
        loaded_fields = {'tvm_ldmsgaddr', 'tvm_ldgrams', 'tvm_ldref', 'tvm_lddict'}
        load_count = sum(count for name, count in calls.items()
                         if name in loads or name in loaded_fields)
        stores = {name for name in calls if re.fullmatch(r'tvm_st[ui]_[0-9]+', name)}
        if (not function.arguments and function.returns and calls['tvm_getdata'] == 1
                and calls['tvm_ctos'] and set(calls) <= load_calls | loads
                and load_count >= 2):
            matches['load_data'].append(function)
        if (not function.returns and calls['tvm_setdata'] == 1 and calls['tvm_newc']
                and calls['tvm_endc'] and set(calls) <= store_calls | stores
                and (stores or set(calls) & {'tvm_stslicer', 'tvm_stgrams', 'tvm_stref', 'tvm_stdict', 'tvm_stbr'})):
            matches['store_data'].append(function)
    occupied = {f.name for f in module.functions} | {primitive_name(p.name) for p in module.primitives}
    names = {}
    for base, functions in matches.items():
        for function in functions:
            name = base if len(functions) == 1 and base not in occupied else base + '_' + function.name.removeprefix('method_')
            while name in occupied:
                name += '_'
            occupied.add(name)
            names[function.name] = name
    functions = []
    for function in module.functions:
        arguments = function.arguments
        argument_names = {}
        if function.name == 'recv_internal' and arguments:
            conventional = (('int', 'balance'), ('int', 'msg_value'), ('cell', 'in_msg_full'), ('slice', 'in_msg_body'))
            expected = conventional[-len(arguments):]
            if tuple(t for t, _ in arguments) == tuple(t for t, _ in expected):
                argument_names = {old: new for (_, old), (_, new) in zip(arguments, expected)}
                arguments = expected
        def rename(value):
            if isinstance(value, Expr):
                mapping = argument_names if value.op == 'arg' else names if value.op == 'call' else {}
                name = mapping.get(value.value, value.value)
                return replace(value, value=name, args=tuple(rename(a) for a in value.args))
            return replace(value, values=tuple(rename(v) for v in value.values),
                           then=tuple(rename(s) for s in value.then), otherwise=tuple(rename(s) for s in value.otherwise))
        functions.append(replace(function, name=names.get(function.name, function.name), arguments=arguments,
                                 statements=tuple(rename(s) for s in function.statements),
                                 returns=tuple(rename(v) for v in function.returns)))
    return replace(module, functions=tuple(functions))


def render_parts(module: Module, *, readable=False, display_program: Program | None = None) -> dict[str, str]:
    if readable:
        module = readable_module(module)
    reachable = {f.name for f in module.functions if not f.inline_ref}
    while True:
        called = {e.value for f in module.functions if f.name in reachable and f.assembly is None
                  for v in (*f.statements, *f.returns) for e in _expressions(v) if e.op == 'call'}
        expanded = reachable | called
        if expanded == reachable:
            break
        reachable = expanded
    module = _named_module(replace(module, functions=tuple(f for f in module.functions if f.name in reachable)))
    lines = []
    values = [expr for function in module.functions if function.assembly is None
              for value in (*function.returns, *function.statements) for expr in _expressions(value)]
    called = {value.value for value in values if value.op == 'call'}
    modifying = {value.value for value in values if value.op == 'modify'}
    chained = {value.value for value in values if value.op == 'chain'}
    if any(value.value == "null()" for value in values):
        lines.append('forall X -> X null() asm "PUSHNULL";')
    def source_type(kind):
        if kind.startswith(('list_', 'vector_')):
            return 'tuple'
        kind = re.sub(r'(?:list|vector)_\[[^\[\]]*\]', 'tuple', kind)
        return re.sub(r'(?:list|vector)_(?:int|cell|slice|builder|empty)', 'tuple', kind)

    def signature(types):
        types = tuple(source_type(kind) for kind in types)
        return types[0] if len(types) == 1 else "(" + ", ".join(types) + ")"
    for primitive in module.primitives:
        if primitive.name not in called | modifying | chained:
            continue
        arguments = ", ".join(f"{source_type(kind)} arg{i}" for i, kind in enumerate(primitive.inputs))
        effect = " impure" if primitive.impure else ""
        generic = "forall X -> " if "X" in (*primitive.inputs, *primitive.outputs) else ""
        if primitive.name == 'impure_touch':
            lines.append(";; Value-returning form of stdlib's ~impure_touch: preserves evaluation order.")
        if primitive.name in called or primitive.name in chained and primitive.name not in {'tvm_stref', 'tvm_stdict'} and not re.fullmatch(r'tvm_st[ui]_[0-9]+', primitive.name):
            lines.append(f"{generic}{signature(primitive.outputs)} {primitive_name(primitive.name)}({arguments}){effect} asm {json.dumps(primitive.assembly)};")
        if primitive.name in chained and primitive.name in {'tvm_stref', 'tvm_stdict'}:
            lines.append(f'builder {_builder_method(primitive.name)}(builder arg0, cell arg1){effect} asm(arg1 arg0) {json.dumps(primitive.assembly)};')
        if primitive.name in modifying:
            skip = primitive.name == 'tvm_sdskipfirst'
            outputs = ('slice', '()') if skip else tuple(reversed(primitive.outputs))
            name = ('~' if skip else '') + primitive_name(primitive.name).removesuffix('_raw')
            order = '' if skip else '( -> 1 0)'
            lines.append(f"{signature(outputs)} {name}({arguments}){effect} asm{order} {json.dumps(primitive.assembly)};")
    if lines:
        lines.append("")
    stdlib = "\n".join(lines)
    lines = []
    for function in module.functions:
        if function.diagnostic and display_program is None:
            lines.append(";; " + function.diagnostic)
        count = len(function.returns)
        argument_types = {name: kind for kind, name in function.arguments}
        result_type = signature([argument_types[value.value] if value.op == "arg" else value.type for value in function.returns])
        args = ", ".join(f"{source_type(type_)} {name}" for type_, name in function.arguments)
        variables = sorted({kind for kind, _ in function.arguments if re.fullmatch(r'X[0-9]*', kind)})
        generic = 'forall ' + ', '.join(variables) + ' -> ' if variables else ''
        attributes = " impure" if function.impure else ""
        if function.inline_ref:
            attributes += " inline_ref"
        if function.method_id is not None:
            attributes += f" method_id({function.method_id})"
        if function.assembly is not None and display_program is not None:
            method_id = function.method_id
            if method_id is None:
                method_id = {'recv_internal': 0, 'recv_external': -1, 'run_ticktock': -2}.get(function.name)
            if method_id in display_program.methods:
                lines.append(f"{function.name}({args}){attributes} fift {{")
                def instructions(code, indent=2):
                    for instruction in code:
                        line = ' ' * indent + ' '.join((instruction.opcode, *instruction.operands))
                        if not instruction.blocks:
                            lines.append(line)
                            continue
                        lines.append(line + ' {')
                        for index, block in enumerate(instruction.blocks):
                            if index:
                                label = {'IFELSE': 'else', 'WHILE': 'do'}.get(instruction.opcode, '')
                                lines.append(' ' * indent + '} ' + (label + ' ' if label else '') + '{')
                            instructions(block, indent + 2)
                        lines.append(' ' * indent + '}')
                instructions(display_program.methods[method_id])
                lines.extend(['}', ''])
                continue
        if function.assembly is not None:
            helper = "asm_" + function.name
            literals = " ".join(json.dumps(line) for line in function.assembly)
            lines.append(f"{result_type} {helper}({args}) impure asm {literals or chr(34) + chr(34)};")
            call = f"{helper}({', '.join(name for _, name in function.arguments)})"
            lines.extend([f"{result_type} {function.name}({args}){attributes} {{", f"  return {call};", "}", ""])
            continue
        lines.append(f"{generic}{result_type} {function.name}({args}){attributes} {{")
        for statement in function.statements:
            lines.extend(_statement(statement))
        lines.append("  return " + (_formatted_expression(function.returns[0], 2) if count == 1 else "(" + ", ".join(map(expression, function.returns)) + ")") + ";")
        lines.extend(["}", ""])
    return {'stdlib': stdlib, 'contract': "\n".join(lines)}


def render(module: Module, *, readable=False) -> str:
    parts = render_parts(module, readable=readable)
    return parts['stdlib'] + ('\n' if parts['stdlib'] else '') + parts['contract']


def candidates(module: Module, method_ids=None):
    """Bounded AST alternatives; only integer commutative pure operations swap."""
    yield module
    method_ids = None if method_ids is None else {int(value) for value in method_ids}
    for index, function in enumerate(module.functions):
        method_id = function.method_id if function.method_id is not None else {"recv_internal": 0, "recv_external": -1, "run_ticktock": -2}.get(function.name)
        if method_ids is not None and method_id not in method_ids:
            continue
        for slot, value in enumerate(function.returns):
            if value.op == "binary" and value.value in {"+", "*", "&", "|", "^", "==", "!="} and all(operand.op in {"arg", "local", "literal"} for operand in value.args):
                returns = list(function.returns)
                returns[slot] = replace(value, args=tuple(reversed(value.args)))
                functions = list(module.functions)
                functions[index] = replace(function, returns=tuple(returns))
                yield replace(module, functions=tuple(functions))
