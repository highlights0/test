#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate an Il2CppDumper-style metadata listing from a *managed* .NET DLL.

Supported: ECMA-335 metadata (#~ / #-), signatures, TypeDef/TypeRef/TypeSpec,
nested types, generic parameters, fields, properties, method signatures and
real managed-PE IL RVAs. No native IL2CPP addresses or guessed field offsets.

Python 3.9+, standard library only.

Examples:
  python managed_dll_to_dumpcs.py UpdateScript_500.dll
  python managed_dll_to_dumpcs.py UpdateScript_500.dll -o dump.cs
  python managed_dll_to_dumpcs.py UpdateScript_500.dll -o dump.cs --stats

This is a searchable declaration/metadata listing, not compilable C# source.
It cannot recover names lost to obfuscation, native offsets, or missing bodies.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from pathlib import Path
import struct
import sys
from dataclasses import dataclass


class MetadataError(ValueError):
    pass


def u16(b, off):
    return struct.unpack_from('<H', b, off)[0]


def u32(b, off):
    return struct.unpack_from('<I', b, off)[0]


def u64(b, off):
    return struct.unpack_from('<Q', b, off)[0]


@dataclass(frozen=True)
class Col:
    kind: str
    arg: object = None


def t(n): return Col('table', n)
def c(n): return Col('coded', n)
S = Col('string')
G = Col('guid')
B = Col('blob')
H = Col('u2')
W = Col('u4')

CODED = {
    'TypeDefOrRef': (2, [2, 1, 27]),
    'HasConstant': (2, [4, 8, 23]),
    'HasCustomAttribute': (5, [6, 4, 1, 2, 8, 9, 10, 0, 14, 23, 20, 17, 26, 27, 32, 35, 38, 39, 40, 42, 44, 43]),
    'HasFieldMarshal': (1, [4, 8]),
    'HasDeclSecurity': (2, [2, 6, 32]),
    'MemberRefParent': (3, [2, 1, 26, 6, 27]),
    'HasSemantics': (1, [20, 23]),
    'MethodDefOrRef': (1, [6, 10]),
    'MemberForwarded': (1, [4, 6]),
    'Implementation': (2, [38, 35, 39]),
    'CustomAttributeType': (3, [None, None, 6, 10, None]),
    'ResolutionScope': (2, [0, 26, 35, 1]),
    'TypeOrMethodDef': (1, [2, 6]),
}

# Complete standard metadata table layouts 0..44. Needed to locate the rows
# correctly, including tables not used directly in the rendered dump.
SCHEMA = {
    0: [H, S, G, G, G],
    1: [c('ResolutionScope'), S, S],
    2: [W, S, S, c('TypeDefOrRef'), t(4), t(6)],
    3: [t(4)],
    4: [H, S, B],
    5: [t(6)],
    6: [W, H, H, S, B, t(8)],
    7: [t(8)],
    8: [H, H, S],
    9: [t(2), c('TypeDefOrRef')],
    10: [c('MemberRefParent'), S, B],
    11: [H, c('HasConstant'), B],
    12: [c('HasCustomAttribute'), c('CustomAttributeType'), B],
    13: [c('HasFieldMarshal'), B],
    14: [H, c('HasDeclSecurity'), B],
    15: [H, W, t(2)],
    16: [W, t(4)],
    17: [B],
    18: [t(2), t(20)],
    19: [t(20)],
    20: [H, S, c('TypeDefOrRef')],
    21: [t(2), t(23)],
    22: [t(23)],
    23: [H, S, B],
    24: [H, t(6), c('HasSemantics')],
    25: [t(2), c('MethodDefOrRef'), c('MethodDefOrRef')],
    26: [S],
    27: [B],
    28: [H, c('MemberForwarded'), S, t(26)],
    29: [W, t(4)],
    30: [W, W],
    31: [W],
    32: [W, H, H, H, H, W, B, S, S],
    33: [W],
    34: [W, W, W],
    35: [H, H, H, H, W, B, S, S, B],
    36: [W, t(35)],
    37: [W, W, W, t(35)],
    38: [W, S, B],
    39: [W, W, S, S, c('Implementation')],
    40: [W, W, S, c('Implementation')],
    41: [t(2), t(2)],
    42: [H, H, c('TypeOrMethodDef'), S],
    43: [c('MethodDefOrRef'), B],
    44: [t(42), c('TypeDefOrRef')],
}


class Meta:
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.sections = []
        self._parse_pe()
        self._parse_metadata()
        self._parse_table_headers()
        self._build_indices()
        self._type_cache = {}
        self._type_active = set()
        self._sig_cache = {}

    def _parse_pe(self):
        b = self.data
        if len(b) < 256 or b[:2] != b'MZ':
            raise MetadataError('Not a PE DLL (no MZ header). Unpack the UnityFS AssetBundle first.')
        pe = u32(b, 0x3c)
        if pe + 24 >= len(b) or b[pe:pe + 4] != b'PE\x00\x00':
            raise MetadataError('Invalid PE header')
        nsec = u16(b, pe + 6)
        opt_size = u16(b, pe + 20)
        opt = pe + 24
        magic = u16(b, opt)
        if magic == 0x10b:
            directories = opt + 96
        elif magic == 0x20b:
            directories = opt + 112
        else:
            raise MetadataError(f'Unknown PE optional header: {magic:#x}')
        sec = opt + opt_size
        for i in range(nsec):
            p = sec + i * 40
            if p + 40 > len(b):
                raise MetadataError('Truncated PE section header')
            name = b[p:p + 8].rstrip(b'\0').decode('ascii', 'replace')
            vsize, vrva, rsize, rawptr = struct.unpack_from('<IIII', b, p + 8)
            self.sections.append((name, vrva, max(vsize, rsize), rawptr, rsize))
        cli_rva, cli_size = struct.unpack_from('<II', b, directories + 14 * 8)
        if not cli_rva or not cli_size:
            raise MetadataError('No CLR header: this is not a managed DLL. IL2CPP native binaries need a different tool.')
        cli = self.rva_to_offset(cli_rva)
        if cli + 16 > len(b):
            raise MetadataError('Truncated CLR header')
        meta_rva, meta_size = struct.unpack_from('<II', b, cli + 8)
        self.meta_offset = self.rva_to_offset(meta_rva)
        self.meta_size = meta_size
        if self.meta_offset + self.meta_size > len(b):
            raise MetadataError('CLR metadata extends beyond file')

    def rva_to_offset(self, rva):
        if not rva:
            return None
        for name, start, vsize, rawptr, rsize in self.sections:
            if start <= rva < start + vsize:
                delta = rva - start
                if delta >= rsize or rawptr + delta >= len(self.data):
                    raise MetadataError(f'RVA {rva:#x} refers to a non-file-backed portion of {name}')
                return rawptr + delta
        raise MetadataError(f'RVA {rva:#x} outside PE sections')

    def _parse_metadata(self):
        b, off = self.data, self.meta_offset
        if b[off:off + 4] != b'BSJB':
            raise MetadataError('Invalid CLI metadata signature (BSJB not found at metadata RVA)')
        vlen = u32(b, off + 12)
        pos = (off + 16 + vlen + 3) & ~3
        nstreams = u16(b, pos + 2)
        pos += 4
        self.streams = {}
        for _ in range(nstreams):
            so, sz = struct.unpack_from('<II', b, pos)
            name_start = pos + 8
            end = b.find(b'\x00', name_start, name_start + 64)
            if end < 0:
                raise MetadataError('Malformed CLR stream name')
            name = b[name_start:end].decode('ascii', 'replace')
            pos = (end + 4) & ~3
            absolute = off + so
            if absolute + sz > off + self.meta_size:
                raise MetadataError(f'CLR metadata stream {name} out of bounds')
            self.streams[name] = (absolute, sz)
        self.strings = self.get_stream('#Strings')
        self.blobs = self.get_stream('#Blob')
        self._string_cache = {}

    def get_stream(self, name):
        if name not in self.streams:
            raise MetadataError(f'Missing CLR metadata stream {name}')
        off, size = self.streams[name]
        return memoryview(self.data)[off:off + size]

    def _parse_table_headers(self):
        b = self.data
        off, size = self.streams.get('#~', self.streams.get('#-', (None, None)))
        if off is None:
            raise MetadataError('Missing #~ / #- metadata table stream')
        self.table_stream_end = off + size
        self.heap_sizes = b[off + 6]
        valid = u64(b, off + 8)
        pos = off + 24
        self.counts = {}
        for table in range(64):
            if valid & (1 << table):
                self.counts[table] = u32(b, pos)
                pos += 4
        self.widths = {}
        self.locations = {}
        for table in range(64):
            count = self.counts.get(table, 0)
            if count == 0:
                continue
            if table not in SCHEMA:
                raise MetadataError(f'Unsupported metadata table {table}; cannot calculate row layout')
            layout = []
            width = 0
            for col in SCHEMA[table]:
                sz = self.col_width(col)
                layout.append((width, sz))
                width += sz
            self.widths[table] = (width, layout)
            self.locations[table] = pos
            pos += width * count
            if pos > self.table_stream_end:
                raise MetadataError(f'Metadata table {table} extends beyond table stream')

    def col_width(self, col):
        if col.kind == 'u2': return 2
        if col.kind == 'u4': return 4
        if col.kind == 'string': return 4 if self.heap_sizes & 1 else 2
        if col.kind == 'guid': return 4 if self.heap_sizes & 2 else 2
        if col.kind == 'blob': return 4 if self.heap_sizes & 4 else 2
        if col.kind == 'table': return 4 if self.counts.get(col.arg, 0) >= 65536 else 2
        if col.kind == 'coded':
            bits, tables = CODED[col.arg]
            return 4 if max(self.counts.get(t, 0) for t in tables if t is not None) >= (1 << (16 - bits)) else 2
        raise MetadataError(f'Unknown metadata column: {col}')

    def row(self, table, rid):
        if rid < 1 or rid > self.counts.get(table, 0):
            raise MetadataError(f'Invalid RID {rid} for metadata table {table}')
        start = self.locations[table] + (rid - 1) * self.widths[table][0]
        result = []
        for p, width in self.widths[table][1]:
            result.append(int.from_bytes(self.data[start + p:start + p + width], 'little'))
        return result

    def decode_coded(self, coded_name, value):
        bits, tables = CODED[coded_name]
        tag = value & ((1 << bits) - 1)
        rid = value >> bits
        table = tables[tag] if tag < len(tables) else None
        return table, rid

    def str_at(self, index):
        if index == 0:
            return ''
        if index >= len(self.strings):
            raise MetadataError(f'Bad string heap index {index}')
        if index in self._string_cache:
            return self._string_cache[index]
        start = self.streams['#Strings'][0] + index
        heap_end = self.streams['#Strings'][0] + len(self.strings)
        end = self.data.find(b'\x00', start, heap_end)
        if end < 0:
            raise MetadataError('Unterminated metadata string')
        value = self.data[start:end].decode('utf-8', 'replace')
        self._string_cache[index] = value
        return value

    def blob_at(self, index):
        if index == 0:
            return b''
        if index >= len(self.blobs):
            raise MetadataError(f'Bad blob heap index {index}')
        r = SigReader(self.blobs[index:])
        length = r.compressed()
        if r.pos + length > len(r.b):
            raise MetadataError('Truncated blob')
        return r.b[r.pos:r.pos + length].tobytes()

    def _build_indices(self):
        self.nested_parent = {}
        for rid in range(1, self.counts.get(41, 0) + 1):
            child, parent = self.row(41, rid)
            self.nested_parent[child] = parent

        self.generic_names = defaultdict(dict)
        self.generic_flags = defaultdict(dict)
        for rid in range(1, self.counts.get(42, 0) + 1):
            number, flags, owner, name_idx = self.row(42, rid)
            key = self.decode_coded('TypeOrMethodDef', owner)
            self.generic_names[key][number] = self.str_at(name_idx)
            self.generic_flags[key][number] = flags

        self.property_range = {}
        for rid in range(1, self.counts.get(21, 0) + 1):
            parent, start = self.row(21, rid)
            nxt = self.row(21, rid + 1)[1] if rid < self.counts.get(21, 0) else self.counts.get(23, 0) + 1
            self.property_range[parent] = (start, nxt)

        self.event_range = {}
        for rid in range(1, self.counts.get(18, 0) + 1):
            parent, start = self.row(18, rid)
            nxt = self.row(18, rid + 1)[1] if rid < self.counts.get(18, 0) else self.counts.get(20, 0) + 1
            self.event_range[parent] = (start, nxt)

        self.accessors = defaultdict(dict)
        for rid in range(1, self.counts.get(24, 0) + 1):
            semantics, method, association = self.row(24, rid)
            table, target = self.decode_coded('HasSemantics', association)
            self.accessors[(table, target)][semantics] = method

        self.interfaces = defaultdict(list)
        for rid in range(1, self.counts.get(9, 0) + 1):
            owner, interface = self.row(9, rid)
            self.interfaces[owner].append(interface)

    def type_name(self, table, rid, omit_ns=False):
        if rid == 0 or table is None:
            return 'object'
        key = (table, rid)
        if key in self._type_cache:
            return self._type_cache[key]
        if key in self._type_active:
            return f'<recursive-type-{table}:{rid}>'
        self._type_active.add(key)
        try:
            if table == 2:
                fields = self.row(2, rid)
                name, namespace = self.str_at(fields[1]), self.str_at(fields[2])
                name = name.replace('+', '.')
                parent = self.nested_parent.get(rid)
                if parent:
                    result = f'{self.type_name(2, parent)}.{name}'
                else:
                    result = f'{namespace}.{name}' if namespace else name
            elif table == 1:
                scope, name_idx, namespace_idx = self.row(1, rid)
                name, namespace = self.str_at(name_idx), self.str_at(namespace_idx)
                scope_table, scope_rid = self.decode_coded('ResolutionScope', scope)
                if scope_table == 1 and scope_rid:
                    result = f'{self.type_name(1, scope_rid)}.{name}'
                else:
                    result = f'{namespace}.{name}' if namespace else name
            elif table == 27:
                raw = self.blob_at(self.row(27, rid)[0])
                result = SigReader(raw, self).type_name()
            else:
                result = f'/* unknown type {table}:{rid} */object'
            self._type_cache[key] = result
            return result
        finally:
            self._type_active.discard(key)

    def generic_context(self, table, rid):
        params = self.generic_names.get((table, rid), {})
        return [params[i] for i in sorted(params)]

    def type_context(self, rid):
        # ECMA nested types may include their parent's generic parameters in
        # the nested type's own GenericParam rows.
        return self.generic_context(2, rid)

    def method_context(self, rid):
        return self.generic_context(6, rid)

    def get_method_sig(self, rid, owner_type):
        blob_idx = self.row(6, rid)[4]
        return SigReader(self.blob_at(blob_idx), self,
                         self.type_context(owner_type), self.method_context(rid)).method_sig()


class SigReader:
    PRIMITIVES = {
        0x01: 'void', 0x02: 'bool', 0x03: 'char', 0x04: 'sbyte',
        0x05: 'byte', 0x06: 'short', 0x07: 'ushort', 0x08: 'int',
        0x09: 'uint', 0x0a: 'long', 0x0b: 'ulong', 0x0c: 'float',
        0x0d: 'double', 0x0e: 'string', 0x16: 'TypedReference',
        0x18: 'nint', 0x19: 'nuint', 0x1c: 'object',
    }

    def __init__(self, b, meta=None, type_params=(), method_params=()):
        self.b = memoryview(b)
        self.pos = 0
        self.meta = meta
        self.type_params = type_params
        self.method_params = method_params

    def byte(self):
        if self.pos >= len(self.b):
            raise MetadataError('Truncated metadata signature')
        x = self.b[self.pos]
        self.pos += 1
        return x

    def peek(self):
        if self.pos >= len(self.b):
            raise MetadataError('Truncated metadata signature')
        return self.b[self.pos]

    def compressed(self):
        a = self.byte()
        if a & 0x80 == 0:
            return a
        if a & 0xc0 == 0x80:
            return ((a & 0x3f) << 8) | self.byte()
        if a & 0xe0 == 0xc0:
            return ((a & 0x1f) << 24) | (self.byte() << 16) | (self.byte() << 8) | self.byte()
        raise MetadataError('Invalid compressed unsigned integer in signature')

    def compressed_signed(self):
        # ECMA-335 compressed signed: low bit is sign, which is extended
        # from 7, 14 or 29 bit signed payload widths.
        first = self.peek()
        bits = 7 if first < 0x80 else (14 if first < 0xc0 else 29)
        val = self.compressed()
        n = val >> 1
        return n - (1 << (bits - 1)) if val & 1 else n

    def coded_type(self):
        v = self.compressed()
        table, rid = [2, 1, 27][v & 3] if (v & 3) < 3 else None, v >> 2
        if table is None or rid == 0:
            return 'object'
        return self.meta.type_name(table, rid) if self.meta else f'Type_{table}_{rid}'

    def type_name(self, depth=0):
        if depth > 64:
            raise MetadataError('Excessive signature nesting')
        e = self.byte()
        if e in self.PRIMITIVES:
            return self.PRIMITIVES[e]
        if e == 0x0f:
            return self.type_name(depth + 1) + '*'
        if e == 0x10:
            return self.type_name(depth + 1) + '&'
        if e in (0x11, 0x12):
            return self.coded_type()
        if e == 0x13:
            n = self.compressed()
            return self.type_params[n] if n < len(self.type_params) else f'!{n}'
        if e == 0x1e:
            n = self.compressed()
            return self.method_params[n] if n < len(self.method_params) else f'!!{n}'
        if e == 0x1d:
            return self.type_name(depth + 1) + '[]'
        if e == 0x14:
            element = self.type_name(depth + 1)
            rank = self.compressed()
            sizes = [self.compressed() for _ in range(self.compressed())]
            lows = [self.compressed_signed() for _ in range(self.compressed())]
            if rank == 0:
                return element + '[?]'
            # Ordinary multidimensional arrays: show rank; constraints in a comment.
            return element + '[' + ',' * (rank - 1) + ']'
        if e == 0x15:
            kind = self.byte()
            if kind not in (0x11, 0x12):
                raise MetadataError('Invalid generic instance element kind')
            name = self.coded_type()
            params = [self.type_name(depth + 1) for _ in range(self.compressed())]
            if '`' in name:
                # Keep nested names but remove ECMA generic arity suffixes.
                import re
                name = re.sub(r'`\d+', '', name)
            return name + '<' + ', '.join(params) + '>'
        if e in (0x1f, 0x20):  # modreq, modopt
            mod = self.coded_type()
            base = self.type_name(depth + 1)
            # Preserve modifier in a comment; must not change its signature.
            return f'{base} /* {"modreq" if e == 0x1f else "modopt"}({mod}) */'
        if e == 0x1b:
            sig = self.method_sig()
            return 'delegate*<' + ', '.join(sig['params'] + [sig['return']]) + '>'
        if e == 0x45:
            return self.type_name(depth + 1) + ' /* pinned */'
        if e == 0x41:
            return '__arglist'
        if e == 0x21:
            # ELEMENT_TYPE_INTERNAL carries runtime address and cannot be
            # interpreted safely in a persisted PE signature.
            raise MetadataError('Runtime-only ELEMENT_TYPE_INTERNAL signature')
        raise MetadataError(f'Unknown ELEMENT_TYPE 0x{e:02X} at sig+{self.pos - 1}')

    def method_sig(self):
        cc = self.byte()
        generic_count = self.compressed() if cc & 0x10 else 0
        count = self.compressed()
        ret = self.type_name()
        params = []
        while len(params) < count:
            if self.peek() == 0x41:
                self.byte()
                params.append('...')
                # ellipsis marker is not counted among parameter count
                continue
            params.append(self.type_name())
        return dict(return_type=ret, **{'return': ret}, params=params,
                    has_this=bool(cc & 0x20), cc=cc, generic_count=generic_count)

    def field_sig(self):
        flag = self.byte()
        if flag & 0x0f != 0x06:
            raise MetadataError(f'Not a field signature: 0x{flag:02X}')
        return self.type_name()

    def property_sig(self):
        cc = self.byte()
        if cc & 0x0f != 0x08:
            raise MetadataError(f'Not a property signature: 0x{cc:02X}')
        count = self.compressed()
        result = self.type_name()
        args = [self.type_name() for _ in range(count)]
        return result, args


ACCESS = {
    0: 'private', 1: 'private', 2: 'private protected',
    3: 'internal', 4: 'protected', 5: 'protected internal', 6: 'public',
}


def type_kind(meta, rid):
    row = meta.row(2, rid)
    flags, _, _, extends = row[:4]
    if flags & 0x20:
        return 'interface'
    tab, base_rid = meta.decode_coded('TypeDefOrRef', extends)
    base = meta.type_name(tab, base_rid) if base_rid else ''
    if base == 'System.Enum': return 'enum'
    if base == 'System.ValueType': return 'struct'
    if base in ('System.MulticastDelegate', 'System.Delegate'): return 'delegate'
    return 'class'


def type_access(flags):
    v = flags & 7
    return {
        0: 'internal', 1: 'public', 2: 'public',
        3: 'private', 4: 'protected', 5: 'internal',
        6: 'private protected', 7: 'protected internal',
    }[v]


def generic_decl(meta, table, rid):
    names = meta.generic_context(table, rid)
    return '<' + ', '.join(names) + '>' if names else ''


def clean_decl_type_name(name):
    # CLR stores arity in TypeDef.Name. It is a representation detail, not a
    # literal part of the C# source identifier. Nested generic parameters are
    # handled by generic_decl(), not guessed from the name.
    return name.split('`', 1)[0]


def method_modifiers(flags):
    mods = [ACCESS[flags & 7]]
    if flags & 0x10: mods.append('static')
    if flags & 0x40 and flags & 0x100: mods.append('virtual')
    elif flags & 0x40: mods.append('override')
    if flags & 0x400: mods.append('abstract')
    if flags & 0x20 and flags & 0x40: mods.append('sealed')
    if flags & 0x2000: mods.append('extern')
    return ' '.join(mods)


def field_modifiers(flags):
    mods = [ACCESS[flags & 7]]
    if flags & 0x10: mods.append('static')
    if flags & 0x40: mods.append('const')
    elif flags & 0x20: mods.append('readonly')
    return ' '.join(mods)


def format_parameter(type_name, pname, flags):
    if type_name.endswith('&'):
        kind = 'out' if flags & 2 else 'in' if flags & 1 else 'ref'
        return f'{kind} {type_name[:-1]} {pname}'
    return f'{type_name} {pname}'


def resolve_params(meta, mid, next_param_start, sig):
    method = meta.row(6, mid)
    begin = method[5]
    prm = {}
    for pid in range(begin, next_param_start):
        flags, seq, nameidx = meta.row(8, pid)
        if seq:
            prm[seq] = (meta.str_at(nameidx), flags)
    args = []
    n = 0
    for stype in sig['params']:
        if stype == '...':
            args.append('...')
            continue
        n += 1
        name, flags = prm.get(n, ('', 0))
        args.append(format_parameter(stype, name or f'arg{n - 1}', flags))
    return ', '.join(args)


def literal_name(name):
    # Retain exact metadata names so the output is searchable even when names
    # are obfuscated or contain unusual characters (not necessarily compilable).
    return name.replace('\r', r'\r').replace('\n', r'\n')


def render(meta, outf, show_stats=False):
    counts = Counter()
    f = outf.write
    assembly = meta.str_at(meta.row(32, 1)[7]) if meta.counts.get(32, 0) else meta.path.stem
    f('// Managed assembly metadata dump (Il2CppDumper-style)\n')
    f('// Source: ' + meta.path.name + '\n')
    f('// Assembly: ' + assembly + '\n')
    f('// Addresses below are RVA in the MANAGED PE, NOT IL2CPP / native addresses.\n')
    f('// MetadataToken: 0xTTrrrrrr (table and row ID).\n')
    f('// TypeDefIndex is zero-based in this listing; tokens use one-based RIDs.\n')
    f('// Field offsets intentionally omitted: no native instance layout is inferred.\n')
    f('// NOT compilable C#; declarations and comments only, no IL bodies.\n\n')
    type_count = meta.counts.get(2, 0)
    field_count = meta.counts.get(4, 0)
    method_count = meta.counts.get(6, 0)
    property_count = meta.counts.get(23, 0)
    for tid in range(1, type_count + 1):
        td = meta.row(2, tid)
        flags, nameidx, nsidx, extends, field_start, method_start = td
        rawname = meta.str_at(nameidx)
        namespace = meta.str_at(nsidx)
        if tid == 1 and rawname == '<Module>':
            # Module pseudo-type is real TypeDef row. Show it too; do not omit
            # any metadata types.
            pass
        kind = type_kind(meta, tid)
        name = clean_decl_type_name(rawname)
        mods = [type_access(flags)]
        if flags & 0x80 and kind == 'class': mods.append('abstract')
        if flags & 0x100 and kind == 'class': mods.append('sealed')
        mods.append(kind)
        mods.append(name + generic_decl(meta, 2, tid))
        bases = []
        table, rid = meta.decode_coded('TypeDefOrRef', extends)
        if table is not None and rid:
            base = meta.type_name(table, rid)
            if base not in ('System.Object', 'System.ValueType', 'System.Enum', 'System.MulticastDelegate', 'System.Delegate'):
                bases.append(base)
        for interface in meta.interfaces.get(tid, []):
            table, rid = meta.decode_coded('TypeDefOrRef', interface)
            if table is not None and rid:
                bases.append(meta.type_name(table, rid))
        decl = ' '.join(mods) + (' : ' + ', '.join(bases) if bases else '')
        f(f'// Namespace: {namespace or "(global)"}\n')
        if tid in meta.nested_parent:
            f('// DeclaringType: ' + meta.type_name(2, meta.nested_parent[tid]) + '\n')
        f(f'// TypeDefIndex: {tid-1}; Token: 0x{(0x02000000 | tid):08X}\n')
        f(decl + '\n{\n')
        counts['types'] += 1
        end_field = meta.row(2, tid + 1)[4] if tid < type_count else field_count + 1
        if field_start < end_field:
            f('    // Fields\n')
        for fid in range(field_start, end_field):
            field_flags, fname_idx, sig_idx = meta.row(4, fid)
            fname = literal_name(meta.str_at(fname_idx))
            try:
                ft = SigReader(meta.blob_at(sig_idx), meta, meta.type_context(tid)).field_sig()
            except (MetadataError, ValueError, IndexError) as exc:
                ft = 'object /* bad field signature: ' + str(exc).replace('*/', '* /') + ' */'
                counts['signature_errors'] += 1
            f(f'    {field_modifiers(field_flags)} {ft} {fname}; // Token: 0x{0x04000000 | fid:08X}\n')
            counts['fields'] += 1
        if field_start < end_field:
            f('\n')

        prop_range = meta.property_range.get(tid)
        if prop_range and prop_range[0] < prop_range[1]:
            f('    // Properties\n')
            for pid in range(*prop_range):
                pflags, pnameidx, sigidx = meta.row(23, pid)
                pname = literal_name(meta.str_at(pnameidx))
                try:
                    rettype, argtypes = SigReader(meta.blob_at(sigidx), meta, meta.type_context(tid)).property_sig()
                except (MetadataError, ValueError, IndexError) as exc:
                    rettype, argtypes = 'object /* bad property signature */', []
                    counts['signature_errors'] += 1
                accessor = meta.accessors.get((23, pid), {})
                getm, setm = accessor.get(2), accessor.get(1)
                mods = ''
                for method_id in (getm, setm):
                    if method_id:
                        mods = ACCESS[meta.row(6, method_id)[2] & 7] + ' '
                        break
                index = '[' + ', '.join(f'{typ} index{i}' for i, typ in enumerate(argtypes)) + ']' if argtypes else ''
                acc = ('get; ' if getm else '') + ('set; ' if setm else '')
                f(f'    {mods}{rettype} {pname}{index} {{ {acc}}} // Token: 0x{0x17000000 | pid:08X}\n')
                counts['properties'] += 1
            f('\n')

        event_range = meta.event_range.get(tid)
        if event_range and event_range[0] < event_range[1]:
            f('    // Events\n')
            for eid in range(*event_range):
                _, nameidx, typetok = meta.row(20, eid)
                table, rid = meta.decode_coded('TypeDefOrRef', typetok)
                etype = meta.type_name(table, rid) if rid else 'object'
                f(f'    event {etype} {literal_name(meta.str_at(nameidx))}; // Token: 0x{0x14000000 | eid:08X}\n')
                counts['events'] += 1
            f('\n')

        end_method = meta.row(2, tid + 1)[5] if tid < type_count else method_count + 1
        if method_start < end_method:
            f('    // Methods\n')
        for mid in range(method_start, end_method):
            rva, impl, mflags, mnidx, sigidx, paramstart = meta.row(6, mid)
            mname = literal_name(meta.str_at(mnidx))
            try:
                sig = meta.get_method_sig(mid, tid)
                next_param = meta.row(6, mid + 1)[5] if mid < method_count else meta.counts.get(8, 0) + 1
                args = resolve_params(meta, mid, next_param, sig)
                generic = generic_decl(meta, 6, mid)
                retval = sig['return']
            except (MetadataError, ValueError, IndexError) as exc:
                retval, args, generic = 'void /* signature error */', '', ''
                counts['signature_errors'] += 1
            method_decl = f'{method_modifiers(mflags)} {retval} {mname}{generic}({args});'
            if rva:
                try:
                    offset = meta.rva_to_offset(rva)
                    offset_note = f' ; PE FileOffset: 0x{offset:X}'
                    # Check body header exists and at least reaches declared IL.
                    first = meta.data[offset]
                    if (first & 3) == 2:
                        code_len, iloffset = first >> 2, offset + 1
                    elif (first & 3) == 3:
                        header_bytes = (u16(meta.data, offset) >> 12) * 4
                        code_len, iloffset = u32(meta.data, offset + 4), offset + header_bytes
                    else:
                        raise MetadataError('invalid IL method header')
                    if iloffset + code_len > len(meta.data):
                        raise MetadataError('truncated IL body')
                    counts['valid_il_headers'] += 1
                except (MetadataError, ValueError, struct.error, IndexError) as exc:
                    offset_note = ' ; IL body WARNING: ' + str(exc).replace('\n', ' ')
                    counts['invalid_il_headers'] += 1
                addr = f'IL RVA (managed PE): 0x{rva:08X}{offset_note}'
            else:
                addr = 'IL RVA (managed PE): none (no managed method body RVA)'
                counts['no_rva'] += 1
            f(f'    // {addr} ; Token: 0x{0x06000000 | mid:08X}\n')
            f('    ' + method_decl + '\n')
            counts['methods'] += 1
        f('}\n\n')
        if show_stats and (tid % 2000 == 0 or tid == type_count):
            print(f'  types {tid:,}/{type_count:,}; methods {counts["methods"]:,}/{method_count:,}', file=sys.stderr)
    return counts


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument('dll', type=Path, help='Unpacked managed .NET DLL (MZ/PE with CLR metadata)')
    p.add_argument('-o', '--output', type=Path, default=Path('dump.cs'), help='Output path (default: dump.cs)')
    p.add_argument('--stats', action='store_true', help='Print progress every 2000 types')
    p.add_argument('--encoding', choices=['utf-8', 'utf-8-sig'], default='utf-8-sig', help='Text encoding (default: UTF-8 BOM, Windows friendly)')
    args = p.parse_args(argv)
    if args.dll.resolve() == args.output.resolve():
        p.error('Output path must differ from DLL')
    try:
        print('[*] Reading managed PE/CLR metadata:', args.dll)
        meta = Meta(args.dll)
        print('[+] Metadata tables: ' + ', '.join(f'{name}={meta.counts.get(t, 0):,}' for name, t in [('TypeDef', 2), ('Field', 4), ('MethodDef', 6), ('Property', 23), ('Event', 20)]))
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with args.output.open('w', encoding=args.encoding, newline='\n') as out:
            counts = render(meta, out, args.stats)
        print('[+] Saved:', args.output.resolve())
        print('[+] ' + '; '.join(f'{k}={v:,}' for k, v in counts.items()))
        if counts['signature_errors'] or counts['invalid_il_headers']:
            print('[!] Warnings detected; search dump.cs for "signature error" and "IL body WARNING".', file=sys.stderr)
        return 0
    except (MetadataError, OSError, struct.error, MemoryError) as exc:
        print('[ERROR] ' + str(exc), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())