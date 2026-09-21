"""Bounded ordinary-cell BOC validation and TON representation hashes.

Exotic/levelled cells are rejected explicitly: hashing them as ordinary cells
would produce misleading exact-match results. See TON crypto/vm/boc.cpp.
"""
from dataclasses import dataclass
from hashlib import sha256

MAX_BYTES = 1_048_576
MAX_CELLS = 16_384
MAX_DEPTH = 512


class BocError(ValueError):
    pass


@dataclass(frozen=True)
class Cell:
    descriptors: bytes
    data: bytes
    refs: tuple[int, ...]
    bits: int
    digest: bytes
    depth: int


@dataclass(frozen=True)
class Boc:
    cells: tuple[Cell, ...]
    root: int

    @property
    def code_hash(self):
        return self.cells[self.root].digest.hex()


def crc32c(data: bytes) -> bytes:
    crc = 0xffffffff
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82f63b78 if crc & 1 else 0)
    return (crc ^ 0xffffffff).to_bytes(4, 'little')


def parse_boc(data: bytes) -> Boc:
    if not isinstance(data, bytes) or not 11 <= len(data) <= MAX_BYTES:
        raise BocError('BOC size must be between 11 bytes and 1 MiB')
    pos = 0

    def take(size):
        nonlocal pos
        if size < 0 or pos + size > len(data):
            raise BocError('Truncated BOC')
        result = data[pos:pos + size]
        pos += size
        return result

    def integer(size):
        return int.from_bytes(take(size), 'big')

    magic = take(4)
    if magic == bytes.fromhex('b5ee9c72'):
        flags = integer(1)
        indexed, checksum = bool(flags & 128), bool(flags & 64)
        if flags & 0x38:
            raise BocError('Cache bits and reserved BOC flags are unsupported')
        size = flags & 7
        explicit_roots = True
    elif magic in (bytes.fromhex('68ff65f3'), bytes.fromhex('acc3a728')):
        size = integer(1)
        indexed, checksum, explicit_roots = True, magic == bytes.fromhex('acc3a728'), False
    else:
        raise BocError('Invalid BOC magic')
    offset_size = integer(1)
    if not 1 <= size <= 4 or not 1 <= offset_size <= 8:
        raise BocError('Invalid BOC integer widths')
    count, roots, absent = integer(size), integer(size), integer(size)
    total = integer(offset_size)
    if not 1 <= count <= MAX_CELLS or roots != 1 or absent:
        raise BocError('Expected one root, no absent cells, and at most 16384 cells')
    root = integer(size) if explicit_roots else 0
    if root >= count:
        raise BocError('Invalid root index')
    offsets = [integer(offset_size) for _ in range(count)] if indexed else []
    start = pos
    if start + total + (4 if checksum else 0) != len(data):
        raise BocError('BOC length does not match header')
    if checksum and crc32c(data[:-4]) != data[-4:]:
        raise BocError('Invalid BOC CRC32C')
    raw = []
    for index in range(count):
        d1, d2 = integer(1), integer(1)
        refs = d1 & 7
        if refs > 4:
            raise BocError('A cell cannot have more than four references')
        if d1 & 0xe8:
            raise BocError('Exotic and levelled cells are unsupported')
        stored_hash = take(32) if d1 & 16 else None
        stored_depth = integer(2) if d1 & 16 else None
        payload = take((d2 + 1) // 2)
        bits = len(payload) * 8
        if d2 & 1:
            if not payload or not payload[-1] & 0x7f:
                raise BocError('Invalid cell top-up bits')
            bits -= (payload[-1] & -payload[-1]).bit_length()
        references = tuple(integer(size) for _ in range(refs))
        if any(ref <= index or ref >= count for ref in references):
            raise BocError('Invalid or cyclic cell reference ordering')
        if pos > start + total:
            raise BocError('Cells exceed declared BOC length')
        if indexed and offsets[index] != pos - start:
            raise BocError('BOC index does not match cell boundaries')
        raw.append((bytes((d1 & ~16, d2)), payload, references, bits, stored_hash, stored_depth))
    if pos != start + total:
        raise BocError('Unused bytes in cell data')
    cells = [None] * count
    for index in range(count - 1, -1, -1):
        desc, payload, refs, bits, stored_hash, stored_depth = raw[index]
        depth = 1 + max((cells[ref].depth for ref in refs), default=-1)
        if depth > MAX_DEPTH:
            raise BocError('Cell depth exceeds 512')
        representation = desc + payload
        representation += b''.join(cells[ref].depth.to_bytes(2, 'big') for ref in refs)
        representation += b''.join(cells[ref].digest for ref in refs)
        digest = sha256(representation).digest()
        if stored_hash is not None and (stored_hash != digest or stored_depth != depth):
            raise BocError('Stored cell hash/depth is incorrect')
        cells[index] = Cell(desc, payload, refs, bits, digest, depth)
    reached, pending = set(), [root]
    while pending:
        index = pending.pop()
        if index not in reached:
            reached.add(index)
            pending.extend(cells[index].refs)
    if len(reached) != count:
        raise BocError('BOC contains unreachable cells')
    return Boc(tuple(cells), root)


def code_hash(data: bytes) -> str:
    return parse_boc(data).code_hash


def method_cells(data: bytes) -> dict[int, bytes]:
    """Extract signed 19-bit dictionary leaves from the standard FunC dispatcher.

    This is a lossless fallback, not semantic reconstruction. Nonstandard entry
    code is rejected rather than replaced by a superficially similar dispatcher.
    """
    boc = parse_boc(data)
    root = boc.cells[boc.root]
    if root.data != bytes.fromhex('ff00f4a413f4bcf2c80b') or root.bits != 80 or len(root.refs) != 1:
        raise BocError('Nonstandard dispatcher: cannot preserve method cells')
    leaves = {}
    work = [(root.refs[0], 19, 0)]
    visited = 0
    while work:
        index, width, prefix = work.pop()
        visited += 1
        if visited > MAX_CELLS:
            raise BocError('Method dictionary exceeds node limit')
        cell = boc.cells[index]
        offset = 0
        value = int.from_bytes(cell.data, 'big')
        storage_bits = len(cell.data) * 8

        def read(count):
            nonlocal offset
            if count < 0 or offset + count > cell.bits:
                raise BocError('Truncated method dictionary label')
            result = (value >> (storage_bits - offset - count)) & ((1 << count) - 1)
            offset += count
            return result

        if read(1) == 0:
            length = 0
            while read(1):
                length += 1
                if length > width:
                    raise BocError('Method dictionary label exceeds key width')
            label = read(length)
        elif read(1) == 0:
            length = read(width.bit_length())
            if length > width:
                raise BocError('Method dictionary label exceeds key width')
            label = read(length)
        else:
            repeated = read(1)
            length = read(width.bit_length())
            if length > width:
                raise BocError('Method dictionary label exceeds key width')
            label = ((1 << length) - 1) if repeated else 0
        prefix = (prefix << length) | label
        remaining = width - length
        if remaining:
            if offset != cell.bits or len(cell.refs) != 2:
                raise BocError('Invalid method dictionary fork')
            work.extend([(cell.refs[0], remaining - 1, prefix << 1),
                         (cell.refs[1], remaining - 1, (prefix << 1) | 1)])
        else:
            method = prefix - (1 << 19) if prefix & (1 << 18) else prefix
            if method in leaves:
                raise BocError('Duplicate method ID')
            leaves[method] = _slice_boc(boc, index, offset)
    return leaves


def _slice_boc(boc: Boc, index: int, offset: int) -> bytes:
    """Serialize one ordinary-cell slice and its DAG in topological order."""
    cell = boc.cells[index]
    bits = cell.bits - offset
    value = (int.from_bytes(cell.data, 'big') >> (len(cell.data) * 8 - cell.bits)) & ((1 << bits) - 1)
    size = (bits + 7) // 8
    payload_value = value << (size * 8 - bits)
    if bits % 8:
        payload_value |= 1 << (size * 8 - bits - 1)
    payload = payload_value.to_bytes(size, 'big')
    desc = bytes((len(cell.refs), bits // 8 + (bits + 7) // 8))
    synthetic = len(boc.cells)
    cells = boc.cells + (Cell(desc, payload, cell.refs, bits, b'', 0),)
    # Existing cell indices are topological; the synthetic root precedes all.
    reached, work = set(), list(cell.refs)
    while work:
        ref = work.pop()
        if ref not in reached:
            reached.add(ref)
            work.extend(cells[ref].refs)
    order = [synthetic] + sorted(reached)
    ids = {old: new for new, old in enumerate(order)}
    width = max(1, (len(order).bit_length() + 7) // 8)
    serialized = b''.join(cells[old].descriptors + cells[old].data +
                          b''.join(ids[ref].to_bytes(width, 'big') for ref in cells[old].refs)
                          for old in order)
    offset_width = max(1, (len(serialized).bit_length() + 7) // 8)
    return (bytes.fromhex('b5ee9c72') + bytes((width, offset_width)) +
            len(order).to_bytes(width, 'big') + (1).to_bytes(width, 'big') + bytes(width) +
            len(serialized).to_bytes(offset_width, 'big') + bytes(width) + serialized)
