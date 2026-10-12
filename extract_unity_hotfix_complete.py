#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Extract intact managed .NET DLL bytes from UnityFS AssetBundle TextAssets.

Tested with Unity 2022.3.62f2 (SerializedFile v22, UnityFS v8).
Unlike a naive MZ search, this parses UnityFS directory entries, the Unity
SerializedFile type/object tables, and TextAsset.m_Script's exact byte length.
It checks PE/CLR metadata and reports TypeDef / MethodDef counts before saving.

Install (Python 3.8+):
    pip install lz4

Single asset:
    python extract_unity_hotfix_complete.py input_bundle.dll -o extracted_dlls
Batch directory:
    python extract_unity_hotfix_complete.py /path/to/bundles -o extracted_dlls

Limitations: If TextAsset contains encrypted/obfuscated bytes rather than a
standard CLR PE, this tool reports that; it does not decrypt them. Modern
Unity object formats outside supported versions may need a general reader
(e.g., UnityPy). No network access or game runtime is needed for plain DLLs.
"""

from __future__ import annotations

import argparse
import hashlib
import lzma
import re
import struct
import sys
from pathlib import Path
from typing import Dict, Iterator, List, NamedTuple, Optional, Tuple


class FormatError(ValueError):
    pass


class Reader:
    def __init__(self, data: bytes, endian: str = ">", at: int = 0):
        self.data, self.endian, self.at = data, endian, at

    def take(self, count: int) -> bytes:
        if count < 0 or self.at + count > len(self.data):
            raise FormatError(f"Truncated input at offset 0x{self.at:x} (+{count})")
        result = self.data[self.at:self.at + count]
        self.at += count
        return result

    def num(self, fmt: str) -> int:
        size = struct.calcsize(fmt)
        return struct.unpack(self.endian + fmt, self.take(size))[0]

    def u8(self) -> int: return self.num("B")
    def u16(self) -> int: return self.num("H")
    def i16(self) -> int: return self.num("h")
    def u32(self) -> int: return self.num("I")
    def i32(self) -> int: return self.num("i")
    def u64(self) -> int: return self.num("Q")
    def i64(self) -> int: return self.num("q")

    def cstr(self) -> str:
        end = self.data.find(b"\x00", self.at)
        if end < 0:
            raise FormatError("Unterminated C-string")
        value = self.data[self.at:end].decode("utf-8", "replace")
        self.at = end + 1
        return value

    def align(self, n: int = 4) -> None:
        self.at = (self.at + n - 1) & ~(n - 1)


class BundleEntry(NamedTuple):
    name: str
    data: bytes


class AssetEntry(NamedTuple):
    name: str
    data: bytes
    location: str


def bounded_count(name: str, num: int, maximum: int) -> int:
    if not 0 <= num <= maximum:
        raise FormatError(f"Invalid {name}: {num}")
    return num


def decompress_block(packed: bytes, plain_size: int, method: int) -> bytes:
    if method == 0:
        result = packed
    elif method in (2, 3):
        try:
            import lz4.block
        except ImportError as exc:
            raise FormatError("LZ4 required: python -m pip install lz4") from exc
        try:
            result = lz4.block.decompress(packed, uncompressed_size=plain_size)
        except Exception as exc:
            raise FormatError(f"LZ4 decompression failed: {exc}") from exc
    elif method == 1:
        try:
            result = lzma.decompress(packed)
        except lzma.LZMAError as exc:
            raise FormatError(f"Unsupported Unity LZMA envelope: {exc}") from exc
    else:
        raise FormatError(f"Unsupported Unity compression {method}")
    if len(result) != plain_size:
        raise FormatError(f"Decompressed size mismatch ({len(result)} != {plain_size})")
    return result


def read_unityfs(blob: bytes) -> List[BundleEntry]:
    rd = Reader(blob)
    if rd.cstr() != "UnityFS":
        raise FormatError("Not a UnityFS file")
    version = rd.u32()
    engine = rd.cstr()
    revision = rd.cstr()
    if version < 6:
        raise FormatError(f"UnityFS format version {version} is not supported")
    total_size = rd.u64()
    packed_info = rd.u32()
    raw_info = rd.u32()
    flags = rd.u32()
    if total_size != len(blob):
        raise FormatError(f"UnityFS advertised {total_size:,} bytes but file has {len(blob):,}")
    if version >= 7:
        rd.align(16)
    if flags & 0x80:  # BlocksInfoAtTheEnd
        if packed_info > len(blob):
            raise FormatError("Invalid blocks-info length")
        block_info = blob[-packed_info:]
        data_start = rd.at
        data_limit = len(blob) - packed_info
    else:
        block_info = rd.take(packed_info)
        data_start = rd.at
        data_limit = len(blob)
    info = Reader(decompress_block(block_info, raw_info, flags & 0x3F))
    info.take(16)  # uncompressed-data hash
    count = bounded_count("UnityFS block count", info.u32(), 500000)
    blocks = [(info.u32(), info.u32(), info.u16()) for _ in range(count)]
    directory_count = bounded_count("UnityFS directory count", info.u32(), 500000)
    files = []
    for _ in range(directory_count):
        offset, size, file_flags = info.u64(), info.u64(), info.u32()
        filename = info.cstr()
        files.append((offset, size, file_flags, filename))
    if flags & 0x200:  # BlockInfoNeedPaddingAtStart
        data_start = (data_start + 15) & ~15
    cursor = data_start
    result = bytearray()
    for index, (plain_size, comp_size, block_flags) in enumerate(blocks):
        if cursor + comp_size > data_limit:
            raise FormatError(f"Block {index} runs past compressed data")
        result.extend(decompress_block(blob[cursor:cursor + comp_size], plain_size, block_flags & 0x3F))
        cursor += comp_size
    data = bytes(result)
    print(f"[UnityFS] version={version}, Unity={revision}, blocks={len(blocks)}, "
          f"directories={len(files)}, decoded={len(data):,} bytes")
    entries = []
    for offset, size, unused_flags, filename in files:
        if offset > len(data) or size > len(data) - offset:
            raise FormatError(f"Bad directory extent: {filename!r}")
        entries.append(BundleEntry(filename, data[offset:offset + size]))
    return entries


def read_typetree(rd: Reader, ver: int) -> None:
    # Blob-style TypeTrees in SerializedFile >= 12. v19+ nodes are 32 bytes.
    if ver < 12:
        raise FormatError(f"Old recursive TypeTree not supported: v{ver}")
    n_nodes = bounded_count("type-tree node count", rd.i32(), 200000)
    string_len = bounded_count("type-tree string buffer length", rd.i32(), 64 * 1024 * 1024)
    node_len = 32 if ver >= 19 else 24
    rd.take(n_nodes * node_len + string_len)


def read_serialized_type(rd: Reader, ver: int, has_tree: bool, is_ref_type: bool = False) -> int:
    cls = rd.i32()
    if ver >= 16:
        rd.u8()  # m_IsStrippedType
    if ver >= 17:
        rd.i16()  # m_ScriptTypeIndex
    # Script-id exists for MonoBehaviour or negative class id in regular types.
    if (cls == 114 or cls < 0) and not is_ref_type:
        rd.take(16)
    if ver >= 13:
        rd.take(16)  # m_OldTypeHash
    if has_tree:
        read_typetree(rd, ver)
    if ver >= 21:
        if is_ref_type:
            # regular reference type's class/name/namespace strings
            rd.cstr(); rd.cstr(); rd.cstr()
        else:
            dep_cnt = bounded_count("type dependency count", rd.i32(), 100000)
            rd.take(dep_cnt * 4)
    return cls


def parse_textasset_object(data: bytes, endian: str) -> Tuple[str, bytes]:
    # Unity TextAsset object payload (modern serialization):
    #   string m_Name [int32 length; UTF8; alignment to 4]
    #   vector<uint8> m_Script [int32 length; bytes]
    rd = Reader(data, endian)
    n_name = rd.i32()
    if not 0 <= n_name <= 16 * 1024 or n_name > len(data) - rd.at:
        raise FormatError("Invalid TextAsset m_Name length")
    name = rd.take(n_name).decode("utf-8", "replace")
    rd.align(4)
    n_payload = rd.i32()
    if not 0 <= n_payload <= len(data) - rd.at:
        raise FormatError("Invalid TextAsset m_Script length")
    raw_payload = rd.take(n_payload)
    if any(byte != 0 for byte in data[rd.at:]):
        # TextAssets can have aligned padding; malformed payload should be reported.
        raise FormatError("Unexpected nonzero bytes after TextAsset m_Script")
    return name, raw_payload


def parse_serializedfile(blob: bytes, name: str) -> List[AssetEntry]:
    if len(blob) < 48:
        raise FormatError("File is too small to contain SerializedFile header")
    rd = Reader(blob)
    meta_size = rd.u32()
    file_size = rd.u32()
    ver = rd.u32()
    data_offset = rd.u32()
    rd.take(4)  # endianness + reserved bytes (in the legacy 20-byte header)
    if not 9 <= ver <= 40:
        raise FormatError(f"Unrecognized SerializedFile version {ver}")
    if ver >= 22:
        meta_size = rd.u32()
        file_size = rd.u64()
        data_offset = rd.u64()
        rd.u64()  # unknown/reserved
    endianness = blob[0x2c] if ver >= 22 else blob[0x10]
    if endianness not in (0, 1):
        raise FormatError(f"Unknown serialized-file endianness {endianness}")
    if file_size != len(blob):
        raise FormatError(f"SerializedFile length mismatch: header={file_size}, actual={len(blob)}")
    if data_offset > len(blob) or not (rd.at < data_offset):
        raise FormatError("SerializedFile data offset is outside the file")
    if meta_size > len(blob):
        raise FormatError("SerializedFile metadata size exceeds file size")
    rd.endian = "<" if endianness == 0 else ">"
    unity = rd.cstr()
    rd.i32()  # target platform
    has_tree = bool(rd.u8()) if ver >= 13 else True
    type_count = bounded_count("SerializedFile type count", rd.i32(), 100000)
    types = [read_serialized_type(rd, ver, has_tree) for _ in range(type_count)]
    count = bounded_count("SerializedFile object count", rd.i32(), 3000000)
    result: List[AssetEntry] = []
    for index in range(count):
        if ver >= 14:
            rd.align(4)
            path_id = rd.i64()
        else:
            path_id = rd.i32()
        start = rd.i64() if ver >= 22 else rd.u32()
        size = rd.u32()
        type_id = rd.i32()
        if not 0 <= type_id < len(types):
            raise FormatError(f"Object {index} has invalid type index {type_id}")
        if ver < 16:
            rd.i16()  # class id
        if ver < 11:
            rd.i16()  # isDestroyed
        if 11 <= ver < 17:
            rd.i16()  # scriptTypeIndex
        if ver in (15, 16):
            rd.u8()  # stripped
        if types[type_id] != 49:  # TextAsset class ID = 49
            continue
        object_offset = data_offset + start
        if object_offset < data_offset or size > len(blob) - object_offset:
            raise FormatError(f"TextAsset object {path_id} is out of bounds")
        obj_data = blob[object_offset:object_offset + size]
        asset_name, asset_data = parse_textasset_object(obj_data, rd.endian)
        result.append(AssetEntry(asset_name, asset_data, f"{name} / pathId={path_id}"))
    print(f"[Assets] {name}: Unity={unity}, serialized_v={ver}, "
          f"objects={count}, TextAssets={len(result)}")
    return result


def cli_metadata_counts(pe: bytes) -> Dict[str, int]:
    """Reject fake/partial PEs and return CLR metadata table row counts.

    Does not disassemble methods; dnSpy / ILSpy are responsible for that.
    """
    def u16(off: int) -> int:
        if off < 0 or off + 2 > len(pe): raise FormatError("Truncated PE header")
        return struct.unpack_from("<H", pe, off)[0]

    def u32(off: int) -> int:
        if off < 0 or off + 4 > len(pe): raise FormatError("Truncated PE header")
        return struct.unpack_from("<I", pe, off)[0]

    if len(pe) < 512 or pe[:2] != b"MZ":
        raise FormatError("No DOS MZ header")
    pe_head = u32(0x3c)
    if pe_head + 24 > len(pe) or pe[pe_head:pe_head + 4] != b"PE\0\0":
        raise FormatError("No valid PE signature")
    sections_num = u16(pe_head + 6)
    optional_size = u16(pe_head + 20)
    if not 1 <= sections_num <= 96:
        raise FormatError("Unreasonable PE section count")
    opt = pe_head + 24
    magic = u16(opt)
    if magic not in (0x10b, 0x20b):
        raise FormatError("Unsupported PE optional header")
    directories = opt + (96 if magic == 0x10b else 112)
    if optional_size < directories + 15 * 8 - opt:
        raise FormatError("PE optional header omits CLR directory")
    section_table = opt + optional_size
    if section_table + 40 * sections_num > len(pe):
        raise FormatError("Truncated PE section table")
    headers_size = u32(opt + 60)
    sections = []
    for i in range(sections_num):
        at = section_table + i * 40
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", pe, at + 8)
        if raw_size and raw_ptr + raw_size > len(pe):
            raise FormatError("Truncated PE section contents")
        sections.append((vaddr, max(vsize, raw_size), raw_ptr, raw_size))

    def rva_to_offset(rva: int, length: int = 1) -> int:
        if 0 <= rva < headers_size and rva + length <= len(pe):
            return rva
        for va, virt_len, raw_ptr, raw_len in sections:
            if va <= rva and rva + length <= va + raw_len:
                result = raw_ptr + rva - va
                if result + length <= len(pe): return result
        raise FormatError(f"PE RVA 0x{rva:x} not backed by file data")

    cli_rva, cli_len = u32(directories + 14 * 8), u32(directories + 14 * 8 + 4)
    if not cli_rva or cli_len < 72:
        raise FormatError("No CLR runtime directory (not a managed .NET DLL)")
    cli = rva_to_offset(cli_rva, 0x10)
    metadata_rva = u32(cli + 8)
    metadata_size = u32(cli + 12)
    md = rva_to_offset(metadata_rva, metadata_size)
    if pe[md:md + 4] != b"BSJB":
        raise FormatError("CLR metadata signature BSJB not found")
    vlen = u32(md + 12)
    pos = md + 16 + vlen
    pos = (pos + 3) & ~3
    if pos + 4 > md + metadata_size:
        raise FormatError("Incomplete CLR version metadata")
    streams = u16(pos + 2)
    pos += 4
    if not 1 <= streams <= 64:
        raise FormatError("Invalid CLR stream count")
    table_stream = None
    for _ in range(streams):
        offset, size = u32(pos), u32(pos + 4)
        pos += 8
        end = pe.find(b"\0", pos, min(pos + 64, md + metadata_size))
        if end < 0: raise FormatError("Invalid CLR stream name")
        stream_name = pe[pos:end].decode("ascii", "replace")
        pos = (end + 4) & ~3
        if offset + size > metadata_size:
            raise FormatError("CLR stream extends beyond metadata")
        if stream_name in ("#~", "#-"):
            table_stream = (md + offset, size)
    if table_stream is None:
        raise FormatError("Missing CLR metadata table stream")
    t, n = table_stream
    if n < 24:
        raise FormatError("Truncated CLR metadata tables")
    valid = struct.unpack_from("<Q", pe, t + 8)[0]
    pos = t + 24
    table_names = {0:"Module", 1:"TypeRef", 2:"TypeDef", 4:"Field", 6:"MethodDef", 35:"AssemblyRef"}
    counts = {}
    for i in range(64):
        if (valid >> i) & 1:
            if pos + 4 > t + n: raise FormatError("Truncated CLR metadata table counts")
            count = u32(pos)
            pos += 4
            if i in table_names: counts[table_names[i]] = count
    if counts.get("Module", 0) != 1:
        raise FormatError("Unreasonable .NET Module table row count")
    if counts.get("TypeDef", 0) <= 0:
        raise FormatError("Empty or invalid TypeDef metadata table")
    return counts


def safe_filename(s: str) -> str:
    s = s.replace("\\", "/").split("/")[-1]
    s = re.sub(r"[<>:\"|?*\x00-\x1f]", "_", s).strip(" .")
    if not s: s = "unnamed"
    if not s.lower().endswith(".dll"): s += ".dll"
    return s


def save_candidate(asset: AssetEntry, dest: Path, seen_hashes: set) -> int:
    if not asset.data.startswith(b"MZ"):
        # May be non-assembly TextAsset, compressed bytes, or encrypted data.
        print(f"[SKIP] {asset.location} / {asset.name}: not a plaintext .NET PE "
              f"({len(asset.data):,} bytes)")
        return 0
    try:
        metadata = cli_metadata_counts(asset.data)
    except FormatError as exc:
        print(f"[SKIP] {asset.location} / {asset.name}: invalid managed PE: {exc}")
        return 0
    digest = hashlib.sha256(asset.data).hexdigest()
    if digest in seen_hashes:
        print(f"[SKIP] Duplicate DLL: {asset.name} SHA256={digest[:16]}...")
        return 0
    seen_hashes.add(digest)
    dest.mkdir(parents=True, exist_ok=True)
    base = dest / safe_filename(asset.name)
    if base.exists():
        if hashlib.sha256(base.read_bytes()).hexdigest() == digest:
            print(f"[OK] Already extracted: {base}")
            return 1
        base = dest / f"{base.stem}_{digest[:12]}{base.suffix}"
    base.write_bytes(asset.data)
    if hashlib.sha256(base.read_bytes()).hexdigest() != digest:
        raise IOError(f"Output write verification failed: {base}")
    print(f"[OK] {base} ({len(asset.data):,} bytes)")
    print(f"     TypeDef={metadata.get('TypeDef', 0):,}, "
          f"MethodDef={metadata.get('MethodDef', 0):,}, "
          f"Field={metadata.get('Field', 0):,}, "
          f"AssemblyRef={metadata.get('AssemblyRef', 0):,}")
    print(f"     SHA256 {digest}")
    return 1


def process_one(src: Path, dest: Path, seen_hashes: set) -> Tuple[int, int]:
    print(f"\n[INPUT] {src} ({src.stat().st_size:,} bytes)")
    blob = src.read_bytes()
    n = 0
    try:
        if blob.startswith(b"UnityFS\0"):
            entries = read_unityfs(blob)
        elif blob.startswith(b"MZ"):
            entries = [BundleEntry(src.name, blob)]
        else:
            entries = [BundleEntry(src.name, blob)]  # maybe SerializedFile
        for entry in entries:
            if entry.data.startswith(b"MZ"):
                n += save_candidate(AssetEntry(entry.name, entry.data, str(src)), dest, seen_hashes)
                continue
            try:
                assets = parse_serializedfile(entry.data, entry.name)
            except FormatError as exc:
                print(f"[SKIP] {entry.name}: unsupported/non-serialized entry ({exc})")
                continue
            for asset in assets:
                n += save_candidate(asset, dest, seen_hashes)
        if n == 0:
            print("[NOTICE] No plaintext managed DLL found. Check asset type, encryption, or Unity format.")
        return n, 0
    except (FormatError, OSError, struct.error) as exc:
        print(f"[ERROR] {src}: {exc}", file=sys.stderr)
        return n, 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", type=Path, help="UnityFS AssetBundle / serialized file / directory")
    ap.add_argument("-o", "--output", type=Path, default=Path("extracted_dlls"))
    ap.add_argument("-r", "--recursive", action="store_true", help="Recurse into subfolders in directory mode")
    args = ap.parse_args()
    if not args.input.exists():
        ap.error(f"Input does not exist: {args.input}")
    if args.input.is_file():
        files = [args.input]
    else:
        files = sorted(p for p in (args.input.rglob("*") if args.recursive else args.input.iterdir()) if p.is_file())
    seen: set = set()
    success = errors = 0
    for filename in files:
        n, e = process_one(filename, args.output, seen)
        success += n
        errors += e
    print(f"\n[RESULT] Extracted/verified: {success}; file-level errors: {errors}; output: {args.output}")
    return 0 if success > 0 and not errors else 1


if __name__ == "__main__":
    sys.exit(main())