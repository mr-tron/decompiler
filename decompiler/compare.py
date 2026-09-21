"""Measured, bounded comparisons; structural similarity is not equivalence."""
from collections import Counter
from functools import lru_cache
from .asm import normalize_asm, parse_asm, walk
from .ir import build_cfg


def _overlap(left, right):
    total = sum(left.values()) + sum(right.values())
    return 2 * sum((left & right).values()) / total if total else 1.0


@lru_cache(maxsize=16)
def compare(original: str, candidate: str) -> dict:
    left, right = parse_asm(original), parse_asm(candidate)
    a = [i.normalized() for i in walk(left.instructions)]
    b = [i.normalized() for i in walk(right.instructions)]
    exact = normalize_asm(original) == normalize_asm(candidate)
    # simple: linear multiset unigrams/bigrams bound comparison time; no edit-distance search.
    tokens = _overlap(Counter(a), Counter(b))
    ordering = _overlap(Counter(zip(a, a[1:])), Counter(zip(b, b[1:])))

    def graph(program):
        cfg = build_cfg(program.instructions)
        blocks = Counter((block.kind, tuple(i.opcode for i in block.instructions), len(block.successors))
                         for block in cfg.blocks)
        edges = Counter((cfg.blocks[block.id].kind, cfg.blocks[target].kind)
                        for block in cfg.blocks for target in block.successors)
        return blocks, edges

    ab, ae = graph(left)
    bb, be = graph(right)
    mismatching_methods = [key for key in sorted(set(left.methods) | set(right.methods))
                           if tuple(i.normalized() for i in left.methods.get(key, ())) !=
                              tuple(i.normalized() for i in right.methods.get(key, ()))]
    return {'normalized_asm_match': exact, 'mismatching_methods': mismatching_methods,
            'instruction_match': 1.0 if exact else (tokens + ordering) / 2,
            'cfg_match': 1.0 if exact else (_overlap(ab, bb) + _overlap(ae, be)) / 2}


def compare_cells(original: bytes, candidate: bytes) -> float:
    """Compare cell payloads and reference topology independently of ASM layout."""
    from .boc import parse_boc
    left, right = parse_boc(original), parse_boc(candidate)
    if left.code_hash == right.code_hash:
        return 1.0

    def features(boc):
        payloads = Counter((cell.bits, cell.data, len(cell.refs)) for cell in boc.cells)
        topology = Counter((cell.bits, cell.depth,
                            tuple((boc.cells[ref].bits, boc.cells[ref].depth) for ref in cell.refs))
                           for cell in boc.cells)
        return payloads, topology

    ap, at = features(left)
    bp, bt = features(right)
    return (_overlap(ap, bp) + _overlap(at, bt)) / 2
