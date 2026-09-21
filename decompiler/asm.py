"""Tokenized representation of TON's textual TVM disassembly.

Normalization removes layout and comments only: constants, cells and ordering
remain significant. Unknown opcodes are retained, never silently discarded.
"""
from dataclasses import dataclass, field
import re


class AsmError(ValueError):
    pass


@dataclass(frozen=True)
class Instruction:
    opcode: str
    operands: tuple[str, ...] = ()
    blocks: tuple[tuple["Instruction", ...], ...] = ()
    source: str = ""

    @property
    def stack_effect(self):
        if self.opcode in {"PUSHINT", "PUSHCONT", "CONT", "TRUE", "FALSE", "ZERO", "ONE", "TWO", "TEN"}:
            return (0, 1)
        if self.opcode in {"ADD", "SUB", "MUL", "DIV", "MOD", "AND", "OR", "XOR", "LSHIFT", "RSHIFT", "EQUAL", "NEQ", "LESS", "GREATER", "LEQ", "GEQ"}:
            return (2, 1)
        return {"DROP": (1, 0), "DUP": (1, 2), "SWAP": (2, 2), "OVER": (2, 3), "NIP": (2, 1), "ROT": (3, 3), "-ROT": (3, 3), "NOP": (0, 0), "NEGATE": (1, 1), "NOT": (1, 1)}.get(self.opcode)

    @property
    def control_flow(self):
        if self.opcode in {"RET", "RETALT", "THROW", "THROWARG", "JMP", "JMPX", "JMPREF"}:
            return "terminal"
        if self.opcode.startswith("IF") or self.opcode.startswith("DICT") and "JMP" in self.opcode:
            return "branch"
        if self.opcode in {"REPEAT", "UNTIL", "WHILE", "AGAIN"}:
            return "loop"
        return "fallthrough"

    def normalized(self):
        return (self.opcode, self.operands, tuple(tuple(i.normalized() for i in b) for b in self.blocks))


@dataclass
class Program:
    instructions: tuple[Instruction, ...]
    methods: dict[int, tuple[Instruction, ...]] = field(default_factory=dict)


def _lines(text):
    """Lex strings, comments and continuation delimiters without regex parsing."""
    if len(text) > 8_000_000:
        raise AsmError("ASM exceeds size limit")
    lines, tokens, token, quoted, escaped = [], [], [], False, False
    i = 0
    while i < len(text):
        c = text[i]
        if quoted:
            token.append(c)
            if c == '"' and not escaped:
                quoted = False
            escaped = c == "\\" and not escaped
            i += 1
            continue
        if c == '"':
            quoted = True
            token.append(c)
        elif text[i:i + 2] in ("//", ";;") or c == ";":
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        elif c.isspace():
            if token:
                tokens.append("".join(token))
                token = []
            if c == "\n" and tokens:
                lines.append(tokens)
                tokens = []
        else:
            token.append(c)
        i += 1
    if quoted:
        raise AsmError("Unterminated string")
    if token:
        tokens.append("".join(token))
    if tokens:
        lines.append(tokens)
    return lines


def parse_asm(text: str) -> Program:
    lines = _lines(text)
    position = 0
    methods = {}

    def block(depth=0, closing=False):
        nonlocal position
        if depth > 128:
            raise AsmError("Continuation nesting exceeds limit")
        result = []
        while position < len(lines):
            words = lines[position]
            position += 1
            if words[0] in ("}>", "}", "]", "}>ELSE<{", "}>DO<{"):
                if not closing:
                    raise AsmError("Unexpected continuation closing delimiter")
                if len(words) > 1:
                    raise AsmError("Unexpected tokens after continuation closing delimiter")
                return tuple(result), words[0]
            source = " ".join(words)
            if words[0] == "Cannot":
                raise AsmError("TON could not disassemble the entire code cell")
            if len(words) == 2 and words[1] == "{" and words[0].startswith("DICT"):
                ids, bodies = [], []
                while position < len(lines) and lines[position] != ["}"]:
                    entry = lines[position]
                    position += 1
                    if len(entry) != 3 or entry[1:] != ["=>", "<{"]:
                        raise AsmError("Malformed method dictionary entry")
                    try:
                        method_id = int(entry[0], 0)
                    except ValueError:
                        raise AsmError("Malformed method id") from None
                    if str(method_id) in ids:
                        raise AsmError("Duplicate method id")
                    body, end = block(depth + 1, True)
                    if end != "}>":
                        raise AsmError("Invalid method continuation")
                    if depth == 0:
                        methods[method_id] = body
                    ids.append(str(method_id))
                    bodies.append(body)
                if position == len(lines):
                    raise AsmError("Unclosed method dictionary")
                position += 1
                result.append(Instruction(words[0], tuple(ids), tuple(bodies), source))
                continue
            attached = words[-1].endswith(":<{")
            if attached or words[-1] in ("<{", "{", "["):
                head = words[:-1] + ([words[-1][:-3]] if attached else [])
                opcode = head[-1] if head else "CONT"
                first, end = block(depth + 1, True)
                bodies = [first]
                if end in ("}>ELSE<{", "}>DO<{"):
                    second, last = block(depth + 1, True)
                    if last != "}>":
                        raise AsmError("Invalid second continuation")
                    if end == "}>ELSE<{" and opcode == "IF":
                        opcode = "IFELSE"
                    elif end != "}>DO<{" or opcode != "WHILE":
                        raise AsmError("Unexpected continuation alternative")
                    bodies.append(second)
                elif end not in ("}>", "}", "]"):
                    raise AsmError("Invalid continuation ending")
                result.append(Instruction(opcode, tuple(head[:-1]), tuple(bodies), source))
                continue
            # Fift uses postfix operands; std-disasm uses prefix and commas.
            if re.fullmatch(r"(?:-?[0-9]*[A-Z][A-Z0-9_#?+-]*|DUMPs[0-9]+)", words[-1]):
                opcode, operands = words[-1], words[:-1]
            elif re.fullmatch(r"(?:-?[0-9]*[A-Z][A-Z0-9_#?+-]*|DUMPs[0-9]+)", words[0]):
                opcode, operands = words[0], words[1:]
            else:
                raise AsmError(f"Malformed instruction: {source[:160]}")
            operands = [word.rstrip(",") for word in operands]
            result.append(Instruction(opcode, tuple(operands), source=source))
        if closing:
            raise AsmError("Unclosed continuation")
        return tuple(result), None

    instructions, _ = block()
    return Program(instructions, methods)


def normalize_asm(text: str) -> str:
    import json
    return json.dumps([i.normalized() for i in parse_asm(text).instructions], separators=(",", ":"))


def walk(instructions):
    for instruction in instructions:
        yield instruction
        for child in instruction.blocks:
            yield from walk(child)
