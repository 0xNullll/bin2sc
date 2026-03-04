#!/usr/bin/env python3

# MIT License — Copyright (c) 2026 0xNullll — Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software to deal in the Software without restriction. Full license: opensource.org/licenses/MIT

"""
bin2sc.py — Convert any binary file to shellcode-usable output formats.
"""

import sys
import os
import re
import math
import base64
import hashlib
import argparse
from collections import Counter

SEP_WIDTH = 80
SEP       = "=" * SEP_WIDTH

def _section(title: str) -> str:
    """Return a full-width centered section title bar."""
    label = f"  {title}  "
    fill  = SEP_WIDTH - len(label)
    left  = fill // 2
    right = fill - left
    return "=" * left + label + "=" * right

# ============================================================
#  ENCODERS
# ============================================================

def encode_xor(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)

def encode_xor_rolling(data: bytes, keys: list) -> bytes:
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ keys[i % len(keys)]
    return bytes(out)

def encode_not(data: bytes) -> bytes:
    return bytes(~b & 0xFF for b in data)

def encode_add(data: bytes, val: int) -> bytes:
    return bytes((b + val) & 0xFF for b in data)

def encode_sub(data: bytes, val: int) -> bytes:
    return bytes((b - val) & 0xFF for b in data)

def apply_encoding_chain(data: bytes, args) -> tuple:
    steps = []
    if args.xor is not None:
        key  = parse_single_byte(args.xor, "--xor")
        data = encode_xor(data, key)
        steps.append(f"XOR(0x{key:02x})")
    if args.xor_rolling is not None:
        keys = parse_rolling_keys(args.xor_rolling)
        data = encode_xor_rolling(data, keys)
        key_str = ",".join(f"0x{k:02x}" for k in keys)
        steps.append(f"XOR-ROLLING({key_str})")
    if args.not_enc:
        data = encode_not(data)
        steps.append("NOT")
    if args.add is not None:
        val  = parse_single_byte(args.add, "--add")
        data = encode_add(data, val)
        steps.append(f"ADD(0x{val:02x})")
    if args.sub is not None:
        val  = parse_single_byte(args.sub, "--sub")
        data = encode_sub(data, val)
        steps.append(f"SUB(0x{val:02x})")
    desc = " -> ".join(steps) if steps else None
    return data, desc

def any_encoding(args) -> bool:
    return any([
        args.xor is not None, args.xor_rolling is not None,
        args.not_enc, args.add is not None, args.sub is not None,
    ])

# ============================================================
#  DECODER STUB GENERATORS
# ============================================================

def build_decoder_c(var_name: str, args, arch) -> str:
    arch_comment = f" [{arch}]" if arch else ""
    lines = [
        f"/* Decoder stub{arch_comment} */",
        f"void decode_{var_name}() {{",
        f"    unsigned int i;",
    ]
    ops = []
    if args.sub is not None:
        val = parse_single_byte(args.sub, "--sub")
        ops.append(f"    for (i=0;i<{var_name}_len;i++) {var_name}[i] = ({var_name}[i] + 0x{val:02x}) & 0xFF;  /* undo SUB */")
    if args.add is not None:
        val = parse_single_byte(args.add, "--add")
        ops.append(f"    for (i=0;i<{var_name}_len;i++) {var_name}[i] = ({var_name}[i] - 0x{val:02x}) & 0xFF;  /* undo ADD */")
    if args.not_enc:
        ops.append(f"    for (i=0;i<{var_name}_len;i++) {var_name}[i] = ~{var_name}[i] & 0xFF;  /* undo NOT */")
    if args.xor_rolling is not None:
        keys    = parse_rolling_keys(args.xor_rolling)
        key_arr = ", ".join(f"0x{k:02x}" for k in keys)
        ops.append(f"    {{ unsigned char rk[] = {{{key_arr}}};")
        ops.append(f"      for (i=0;i<{var_name}_len;i++) {var_name}[i] ^= rk[i % {len(keys)}]; }}  /* undo XOR-ROLLING */")
    if args.xor is not None:
        key = parse_single_byte(args.xor, "--xor")
        ops.append(f"    for (i=0;i<{var_name}_len;i++) {var_name}[i] ^= 0x{key:02x};  /* undo XOR */")
    lines.extend(ops)
    lines.append("}")
    lines.append(f"/* Call decode_{var_name}() before executing {var_name} */")
    return "\n".join(lines) + "\n"

def build_decoder_python(var_name: str, args, arch) -> str:
    arch_comment = f"  # [{arch}]" if arch else ""
    lines = [f"# Decoder stub{arch_comment}", f"def decode_{var_name}(buf):"]
    ops   = []
    if args.sub is not None:
        val = parse_single_byte(args.sub, "--sub")
        ops.append(f"    buf = bytes((b + 0x{val:02x}) & 0xFF for b in buf)  # undo SUB")
    if args.add is not None:
        val = parse_single_byte(args.add, "--add")
        ops.append(f"    buf = bytes((b - 0x{val:02x}) & 0xFF for b in buf)  # undo ADD")
    if args.not_enc:
        ops.append(f"    buf = bytes(~b & 0xFF for b in buf)  # undo NOT")
    if args.xor_rolling is not None:
        keys    = parse_rolling_keys(args.xor_rolling)
        key_str = "[" + ", ".join(f"0x{k:02x}" for k in keys) + "]"
        ops.append(f"    rk  = {key_str}")
        ops.append(f"    buf = bytes(b ^ rk[i % {len(keys)}] for i, b in enumerate(buf))  # undo XOR-ROLLING")
    if args.xor is not None:
        key = parse_single_byte(args.xor, "--xor")
        ops.append(f"    buf = bytes(b ^ 0x{key:02x} for b in buf)  # undo XOR")
    ops.append("    return buf")
    lines.extend(ops)
    lines.append(f"\n{var_name} = decode_{var_name}({var_name})")
    return "\n".join(lines) + "\n"

# ============================================================
#  FORMATTERS
# ============================================================

def fmt_c_array(data: bytes, var_name: str, arch) -> str:
    hex_bytes = [f"0x{b:02x}" for b in data]
    lines     = []
    for i in range(0, len(hex_bytes), 12):
        lines.append("    " + ", ".join(hex_bytes[i:i+12]))
    body   = ",\n".join(lines)
    header = f"/* {arch} shellcode - {len(data)} bytes */\n" if arch else ""
    return (f"{header}unsigned char {var_name}[] = {{\n{body}\n}};\n"
            f"unsigned int  {var_name}_len = {len(data)};\n")

def fmt_python_block(data: bytes, var_name: str, arch) -> str:
    hex_bytes = [f"\\x{b:02x}" for b in data]
    lines     = []
    for i in range(0, len(hex_bytes), 16):
        lines.append('    b"' + "".join(hex_bytes[i:i+16]) + '"')
    body   = "\n".join(lines)
    header = f"# {arch} shellcode - {len(data)} bytes\n" if arch else ""
    return (f"{header}{var_name} = (\n{body}\n)\n"
            f"{var_name}_len = {len(data)}\n")

def fmt_powershell(data: bytes, var_name: str, arch) -> str:
    hex_bytes = [f"0x{b:02x}" for b in data]
    lines     = []
    for i in range(0, len(hex_bytes), 16):
        lines.append("    " + ",".join(hex_bytes[i:i+16]))
    body   = ",`\n".join(lines)
    header = f"# {arch} shellcode - {len(data)} bytes\n" if arch else ""
    return (f"{header}[Byte[]] ${var_name} = `\n{body}\n"
            f"${var_name}_len = {len(data)}\n")

def fmt_java(data: bytes, var_name: str, arch) -> str:
    def java_byte(b):
        return f"(byte)0x{b:02x}" if b > 0x7F else f"0x{b:02x}"
    byte_strs = [java_byte(b) for b in data]
    lines     = []
    for i in range(0, len(byte_strs), 8):
        lines.append("    " + ", ".join(byte_strs[i:i+8]))
    body   = ",\n".join(lines)
    header = f"// {arch} shellcode - {len(data)} bytes\n" if arch else ""
    return (f"{header}byte[] {var_name} = {{\n{body}\n}};\n"
            f"int    {var_name}_len = {len(data)};\n")

def fmt_go(data: bytes, var_name: str, arch) -> str:
    hex_bytes = [f"0x{b:02x}" for b in data]
    lines     = []
    for i in range(0, len(hex_bytes), 12):
        lines.append("\t" + ", ".join(hex_bytes[i:i+12]) + ",")
    body   = "\n".join(lines)
    header = f"// {arch} shellcode - {len(data)} bytes\n" if arch else ""
    return (f"{header}var {var_name} = []byte{{\n{body}\n}}\n"
            f"var {var_name}Len = {len(data)}\n")

def fmt_rust(data: bytes, var_name: str, arch) -> str:
    hex_bytes = [f"0x{b:02x}" for b in data]
    lines     = []
    for i in range(0, len(hex_bytes), 12):
        lines.append("    " + ", ".join(hex_bytes[i:i+12]) + ",")
    body   = "\n".join(lines)
    header = f"// {arch} shellcode - {len(data)} bytes\n" if arch else ""
    return (f"{header}static {var_name.upper()}: &[u8] = &[\n{body}\n];\n"
            f"const  {var_name.upper()}_LEN: usize = {len(data)};\n")

def fmt_nasm(data: bytes, var_name: str, arch) -> str:
    hex_bytes = [f"0x{b:02x}" for b in data]
    lines     = []
    pad       = " " * (len(var_name) + 1)
    for i in range(0, len(hex_bytes), 12):
        chunk = ", ".join(hex_bytes[i:i+12])
        lines.append((f"{var_name}: db {chunk}" if i == 0 else f"{pad}   db {chunk}"))
    header = f"; {arch} shellcode - {len(data)} bytes\n" if arch else ""
    footer = f"{var_name}_len equ $ - {var_name}\n"
    return header + "\n".join(lines) + "\n" + footer

def fmt_fasm(data: bytes, var_name: str, arch) -> str:
    hex_bytes = [f"0x{b:02x}" for b in data]
    lines     = []
    pad       = " " * len(var_name)
    for i in range(0, len(hex_bytes), 12):
        chunk = ", ".join(hex_bytes[i:i+12])
        lines.append((f"{var_name} db {chunk}" if i == 0 else f"{pad}    db {chunk}"))
    header = f"; {arch} shellcode - {len(data)} bytes\n" if arch else ""
    footer = f"{var_name}_size = $ - {var_name}\n"
    return header + "\n".join(lines) + "\n" + footer

def fmt_masm(data: bytes, var_name: str, arch) -> str:
    hex_bytes = [f"0{b:02x}h" for b in data]
    lines     = []
    pad       = " " * len(var_name)
    for i in range(0, len(hex_bytes), 12):
        chunk = ", ".join(hex_bytes[i:i+12])
        lines.append((f"{var_name} BYTE {chunk}" if i == 0 else f"{pad}      BYTE {chunk}"))
    header = f"; {arch} shellcode - {len(data)} bytes\n" if arch else ""
    footer = f"{var_name}_len EQU $ - {var_name}\n"
    return header + "\n".join(lines) + "\n" + footer

def fmt_base64(data: bytes, var_name: str, arch) -> str:
    b64    = base64.b64encode(data).decode("ascii")
    header = (f"# {arch} shellcode - {len(data)} bytes ({len(b64)} base64 chars)\n" if arch
              else f"# {len(data)} bytes ({len(b64)} base64 chars)\n")
    lines  = [b64[i:i+76] for i in range(0, len(b64), 76)]
    return (header + f"{var_name}_b64 = (\n" +
            "\n".join(f'    "{l}"' for l in lines) +
            f"\n)\nimport base64\n{var_name} = base64.b64decode(''.join({var_name}_b64))\n")

def fmt_uuid(data: bytes, var_name: str, arch) -> str:
    remainder = len(data) % 16
    if remainder:
        data = data + b"\x90" * (16 - remainder)
    uuids  = []
    header = (f"# {arch} shellcode - {len(data)} bytes as UUIDs\n" if arch
              else f"# {len(data)} bytes as UUIDs\n")
    header += f"# Usage: call UuidFromStringA on each entry, write to RWX buffer\n"
    for i in range(0, len(data), 16):
        block = data[i:i+16]
        p1 = block[0:4][::-1].hex()
        p2 = block[4:6][::-1].hex()
        p3 = block[6:8][::-1].hex()
        p4 = block[8:10].hex()
        p5 = block[10:16].hex()
        uuids.append(f"{p1}-{p2}-{p3}-{p4}-{p5}")
    lines = [f'    "{u}",' for u in uuids]
    return (f"{header}{var_name}_uuids = [\n" + "\n".join(lines) +
            f"\n]\n{var_name}_count = {len(uuids)}\n")

def fmt_hex_dump(data: bytes) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk    = data[i:i+16]
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(16 * 3 - 1)
        asc_part = "".join(chr(b) if 0x20 <= b <= 0x7e else "." for b in chunk)
        lines.append(f"  {i:08x}  {hex_part}  |{asc_part}|")
    return "\n".join(lines) + "\n"

def fmt_linear(data: bytes) -> str:
    return "".join(f"\\x{b:02x}" for b in data)

def fmt_hex(data: bytes) -> str:
    """
    Clean uppercase hex string, no prefix or separators.
    Useful for pasting into CyberChef, Wireshark display filters,
    debugger search boxes, or any tool expecting raw hex input.
    """
    return data.hex().upper() + "\n"

def fmt_csharp(data: bytes, var_name: str, arch) -> str:
    """
    C# byte array, 16 bytes per line.
    Common for .NET loaders, Cobalt Strike BOFs, and offensive C# tools.
    """
    hex_bytes = [f"0x{b:02x}" for b in data]
    lines     = []
    for i in range(0, len(hex_bytes), 16):
        lines.append("    " + ", ".join(hex_bytes[i:i+16]))
    body   = ",\n".join(lines)
    header = f"// {arch} shellcode - {len(data)} bytes\n" if arch else ""
    return (f"{header}"
            f"byte[] {var_name} = new byte[{len(data)}] {{\n{body}\n}};\n")

def fmt_raw(data: bytes) -> bytes:
    return data

# ============================================================
#  PATCH
# ============================================================

def apply_patch(data: bytes, patch_str: str) -> bytes:
    parts = patch_str.strip().split()
    if len(parts) != 2:
        print(f"[!] --patch expects 'OFFSET VAL'  e.g.  --patch 0x10 0x90", file=sys.stderr)
        sys.exit(1)
    try:
        offset = int(parts[0], 0)
        val    = int(parts[1], 0)
    except ValueError:
        print(f"[!] --patch invalid values: {parts}", file=sys.stderr); sys.exit(1)
    if not (0 <= offset < len(data)):
        print(f"[!] --patch offset 0x{offset:X} out of range (file size 0x{len(data):X})", file=sys.stderr); sys.exit(1)
    if not (0x00 <= val <= 0xFF):
        print(f"[!] --patch val must be 0x00-0xFF", file=sys.stderr); sys.exit(1)
    data    = bytearray(data)
    old     = data[offset]
    data[offset] = val
    print(f"  [~] Patched 0x{offset:X} : 0x{old:02x} -> 0x{val:02x}", file=sys.stderr)
    return bytes(data)

# ============================================================
#  SIZE ALIGN
# ============================================================

def apply_size_align(data: bytes, align: int) -> bytes:
    remainder = len(data) % align
    if remainder == 0:
        print(f"  [=] Already aligned to {align} bytes, no padding needed", file=sys.stderr)
        return data
    pad_count = align - remainder
    data      = data + b"\x90" * pad_count
    print(f"  [+] Padded {pad_count} NOP(s) -> new size {len(data)} bytes", file=sys.stderr)
    return data

# ============================================================
#  REVERSE
# ============================================================

def apply_reverse(data: bytes) -> bytes:
    """
    Reverse byte order of the entire payload.
    Used in certain injection techniques where a loader pushes
    bytes onto the stack in reverse, or for reflective loaders
    that walk backwards through a buffer.
    """
    return data[::-1]

# ============================================================
#  NULL FREE CHECK
# ============================================================

def check_null_free(data: bytes):
    nulls = [i for i, b in enumerate(data) if b == 0x00]
    print(file=sys.stderr)
    print(_section("NULL-FREE CHECK"), file=sys.stderr)
    if not nulls:
        print(f"  [+] Null-free        : YES  ({len(data)} bytes)", file=sys.stderr)
        print(f"      Note             : Safe for strcpy/strlen based copy routines", file=sys.stderr)
    else:
        print(f"  [x] Null-free        : NO  ({len(nulls)} null byte(s) found)", file=sys.stderr)
        preview = ", ".join(f"0x{o:X}" for o in nulls[:8])
        more    = f" ... (+{len(nulls)-8} more)" if len(nulls) > 8 else ""
        print(f"      Offsets          : {preview}{more}", file=sys.stderr)
        print(f"      Suggestion       : --xor-auto --badchars \"\\x00\"", file=sys.stderr)
    print(SEP, file=sys.stderr)

# ============================================================
#  PRINTABLE ANALYSIS
# ============================================================

def find_printable_ranges(data: bytes) -> list:
    MIN_RUN = 4
    ranges  = []
    start   = None
    run     = []
    for i, b in enumerate(data):
        if 0x20 <= b <= 0x7e:
            if start is None: start = i
            run.append(chr(b))
        else:
            if start is not None and len(run) >= MIN_RUN:
                ranges.append((start, i - 1, "".join(run)))
            start = None
            run   = []
    if start is not None and len(run) >= MIN_RUN:
        ranges.append((start, len(data) - 1, "".join(run)))
    return ranges

def print_printable(data: bytes):
    ranges = find_printable_ranges(data)
    print(file=sys.stderr)
    print(_section(f"PRINTABLE RANGES  ({len(ranges)} found, min 4 bytes)"), file=sys.stderr)
    if not ranges:
        print("  [-] None             : no printable ASCII runs of 4+ bytes", file=sys.stderr)
    else:
        print(f"  {'Offset range':<20}  {'Len':>5}  String", file=sys.stderr)
        print(f"  {'-'*20}  {'-'*5}  {'-'*40}", file=sys.stderr)
        for start, end, text in ranges:
            display = text[:48] + ("..." if len(text) > 48 else "")
            print(f"  0x{start:04X} - 0x{end:04X}    {end-start+1:>5}  {display!r}", file=sys.stderr)
    print(SEP, file=sys.stderr)

# ============================================================
#  BYTE FREQUENCY
# ============================================================

def print_freq(data: bytes):
    """
    Byte frequency histogram — top 32 most common bytes.
    Bar width scaled to terminal (60 chars max).
    Useful for spotting dominant bytes (e.g. 0x00 in sparse data),
    confirming encoding worked, or eyeballing byte distribution
    before checking entropy.
    """
    counts  = Counter(data)
    total   = len(data)
    top     = counts.most_common(32)
    max_cnt = top[0][1] if top else 1
    BAR_W   = 40

    print(file=sys.stderr)
    print(_section(f"BYTE FREQUENCY  (top {len(top)} of {len(counts)} unique)"), file=sys.stderr)
    print(f"  {'Byte':<6}  {'Count':>6}  {'Pct':>6}  {'':2}  Histogram", file=sys.stderr)
    print(f"  {'-'*6}  {'-'*6}  {'-'*6}  {'':2}  {'-'*BAR_W}", file=sys.stderr)
    for byte_val, cnt in top:
        bar   = int((cnt / max_cnt) * BAR_W)
        pct   = cnt / total * 100
        label = (chr(byte_val) if 0x20 <= byte_val <= 0x7e else ' ')
        print(f"  0x{byte_val:02x} {label:<2}  {cnt:>6}  {pct:>5.1f}%  |{'#' * bar:<{BAR_W}}|", file=sys.stderr)
    print(SEP, file=sys.stderr)


# ============================================================
#  FIND PATTERN
# ============================================================

def find_pattern(data: bytes, pattern: bytes) -> list:
    """Return all offsets where pattern appears in data."""
    offsets = []
    start   = 0
    while True:
        idx = data.find(pattern, start)
        if idx == -1:
            break
        offsets.append(idx)
        start = idx + 1
    return offsets

def parse_pattern(s: str) -> bytes:
    """
    Parse pattern string into bytes.
    Accepts: "\\x90\\x90"  or  "90 90"  or  "0x90 0x90"  or  mixed.
    """
    s = s.strip()
    if "\\x" in s or "0x" in s:
        parts = re.findall(r'(?:\\x|0x)([0-9a-fA-F]{2})', s)
    else:
        parts = s.split()
    if not parts:
        print(f"[!] --find-pattern: could not parse pattern: {s!r}", file=sys.stderr)
        sys.exit(1)
    return bytes(int(p, 16) for p in parts)

def print_find_pattern(data: bytes, pattern: bytes):
    hex_str = " ".join(f"0x{b:02x}" for b in pattern)
    offsets = find_pattern(data, pattern)
    print(file=sys.stderr)
    print(_section(f"PATTERN SEARCH"), file=sys.stderr)
    print(f"  Pattern              : {hex_str}  ({len(pattern)} bytes)", file=sys.stderr)
    print(f"  Matches              : {len(offsets)}", file=sys.stderr)
    if offsets:
        print(file=sys.stderr)
        print(f"  {'#':<5}  Offset", file=sys.stderr)
        print(f"  {'-'*5}  {'-'*12}", file=sys.stderr)
        for i, off in enumerate(offsets[:64]):
            print(f"  {i+1:<5}  0x{off:08X}  ({off})", file=sys.stderr)
        if len(offsets) > 64:
            print(f"  ... (+{len(offsets)-64} more matches not shown)", file=sys.stderr)
    else:
        print(f"  [-] Pattern not found in payload", file=sys.stderr)
    print(SEP, file=sys.stderr)




def diff_files(path_a: str, path_b: str):
    for p in [path_a, path_b]:
        if not os.path.isfile(p):
            print(f"[!] File not found: {p}", file=sys.stderr); sys.exit(1)

    with open(path_a, "rb") as f: a = f.read()
    with open(path_b, "rb") as f: b = f.read()

    print(file=sys.stderr)
    print(_section("DIFF"), file=sys.stderr)
    print(f"  File A               : {path_a}", file=sys.stderr)
    print(f"  File B               : {path_b}", file=sys.stderr)
    print(f"  Size A               : {len(a)} bytes  (0x{len(a):X})", file=sys.stderr)
    print(f"  Size B               : {len(b)} bytes  (0x{len(b):X})", file=sys.stderr)

    diffs = []
    for i in range(max(len(a), len(b))):
        ba = a[i] if i < len(a) else None
        bb = b[i] if i < len(b) else None
        if ba != bb:
            diffs.append((i, ba, bb))

    print(f"  Differences          : {len(diffs)}", file=sys.stderr)

    if len(diffs) == 0:
        print(f"  [=] Files are identical", file=sys.stderr)
    else:
        print(file=sys.stderr)
        print(f"  {'Offset':<14}  {'File A':>8}  {'File B':>8}", file=sys.stderr)
        print(f"  {'-'*14}  {'-'*8}  {'-'*8}", file=sys.stderr)
        for offset, ba, bb in diffs[:64]:
            a_str = f"0x{ba:02x}" if ba is not None else "EOF"
            b_str = f"0x{bb:02x}" if bb is not None else "EOF"
            print(f"  0x{offset:<12X}  {a_str:>8}  {b_str:>8}", file=sys.stderr)
        if len(diffs) > 64:
            print(f"  ... (+{len(diffs)-64} more diffs not shown)", file=sys.stderr)
        print(file=sys.stderr)
        print(f"  MD5 A                : {hashlib.md5(a).hexdigest()}", file=sys.stderr)
        print(f"  MD5 B                : {hashlib.md5(b).hexdigest()}", file=sys.stderr)

    print(SEP, file=sys.stderr)
    return len(diffs)

# ============================================================
#  XOR AUTO KEY FINDER
# ============================================================

def xor_auto_find(data: bytes, badchars: list) -> list:
    return [key for key in range(1, 256)
            if not scan_badchars(encode_xor(data, key), badchars)]

def print_xor_auto_results(clean_keys: list, badchars: list):
    bc_str = " ".join(f"\\x{b:02x}" for b in badchars)
    print(file=sys.stderr)
    print(_section("XOR AUTO-KEY SEARCH"), file=sys.stderr)
    print(f"  Bad chars            : {bc_str}", file=sys.stderr)
    if not clean_keys:
        print(f"  [x] Result           : No single-byte XOR key eliminates all bad chars", file=sys.stderr)
        print(f"      Suggestion       : Try --xor-rolling or --add/--sub instead", file=sys.stderr)
    else:
        print(f"  [+] Clean keys found : {len(clean_keys)}", file=sys.stderr)
        print(file=sys.stderr)
        print(f"  {'Key (hex)':<12}  {'Key (dec)':>10}", file=sys.stderr)
        print(f"  {'-'*12}  {'-'*10}", file=sys.stderr)
        for k in clean_keys:
            print(f"  0x{k:02x}          {k:>10}", file=sys.stderr)
        print(file=sys.stderr)
        print(f"  [>] Suggested        : --xor 0x{clean_keys[0]:02x}", file=sys.stderr)
    print(SEP, file=sys.stderr)


# ============================================================
#  VERIFY ROUND-TRIP
# ============================================================

def verify_round_trip(original: bytes, encoded: bytes, args) -> bool:
    """
    Decode the encoded payload in-memory using the same chain in reverse,
    then assert it matches the original byte-for-byte.
    Catches bugs in chained encoders (e.g. wrong key, wrong order).
    Exits with error if verification fails.
    """
    decoded = encoded

    # Reverse order: undo sub -> undo add -> undo not -> undo xor-rolling -> undo xor
    if args.sub is not None:
        val     = parse_single_byte(args.sub, "--sub")
        decoded = bytes((b + val) & 0xFF for b in decoded)

    if args.add is not None:
        val     = parse_single_byte(args.add, "--add")
        decoded = bytes((b - val) & 0xFF for b in decoded)

    if args.not_enc:
        decoded = bytes(~b & 0xFF for b in decoded)

    if args.xor_rolling is not None:
        keys    = parse_rolling_keys(args.xor_rolling)
        decoded = bytes(b ^ keys[i % len(keys)] for i, b in enumerate(decoded))

    if args.xor is not None:
        key     = parse_single_byte(args.xor, "--xor")
        decoded = bytes(b ^ key for b in decoded)

    print(file=sys.stderr)
    print(_section("VERIFY ROUND-TRIP"), file=sys.stderr)
    print(f"  Original size        : {len(original)} bytes", file=sys.stderr)
    print(f"  Encoded size         : {len(encoded)} bytes", file=sys.stderr)
    print(f"  Decoded size         : {len(decoded)} bytes", file=sys.stderr)

    if decoded == original:
        print(f"  [+] Result           : PASS — decoded matches original exactly", file=sys.stderr)
        print(SEP, file=sys.stderr)
        return True
    else:
        # find first mismatch for diagnosis
        mismatch = next((i for i in range(min(len(decoded), len(original)))
                         if decoded[i] != original[i]), None)
        print(f"  [x] Result           : FAIL — decoded does NOT match original", file=sys.stderr)
        if len(decoded) != len(original):
            print(f"      Size mismatch    : {len(decoded)} decoded vs {len(original)} original", file=sys.stderr)
        if mismatch is not None:
            print(f"      First diff       : offset 0x{mismatch:X}  "
                  f"decoded=0x{decoded[mismatch]:02x}  original=0x{original[mismatch]:02x}", file=sys.stderr)
        print(SEP, file=sys.stderr)
        return False

# ============================================================
#  ANALYSIS HELPERS
# ============================================================

def calc_entropy(data: bytes) -> float:
    if not data: return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())

def find_null_bytes(data: bytes):
    return [i for i, b in enumerate(data) if b == 0x00]

def parse_badchars(s: str):
    s = s.strip()
    if "\\x" in s or "0x" in s:
        return [int(m, 16) for m in re.findall(r'(?:\\x|0x)([0-9a-fA-F]{2})', s)]
    return [int(t, 16) for t in s.split() if t]

def scan_badchars(data: bytes, badchars: list):
    return {bc: [i for i, b in enumerate(data) if b == bc]
            for bc in badchars if any(b == bc for b in data)}

def calc_hashes(data: bytes):
    return {
        "MD5":    hashlib.md5(data).hexdigest(),
        "SHA1":   hashlib.sha1(data).hexdigest(),
        "SHA256": hashlib.sha256(data).hexdigest(),
    }

def parse_single_byte(val_str: str, flag: str) -> int:
    try:
        v = int(val_str, 0)
    except ValueError:
        print(f"[!] Invalid value for {flag}: {val_str}", file=sys.stderr); sys.exit(1)
    if not (0x00 <= v <= 0xFF):
        print(f"[!] {flag} must be a single byte (0x00-0xFF)", file=sys.stderr); sys.exit(1)
    return v

def parse_rolling_keys(keys_str: str) -> list:
    keys = []
    for p in keys_str.split(","):
        try:
            keys.append(int(p.strip(), 0))
        except ValueError:
            print(f"[!] Invalid rolling key: {p.strip()}", file=sys.stderr); sys.exit(1)
    if not keys:
        print("[!] --xor-rolling requires at least one key", file=sys.stderr); sys.exit(1)
    for k in keys:
        if not (0x00 <= k <= 0xFF):
            print(f"[!] Rolling key 0x{k:x} out of byte range", file=sys.stderr); sys.exit(1)
    return keys

def print_stats(data: bytes, badchars, label: str = ""):
    """Print aligned stats block: size, entropy, nulls, bad chars, hashes."""
    entropy   = calc_entropy(data)
    null_offs = find_null_bytes(data)
    hashes    = calc_hashes(data)

    if   entropy >= 7.5: rating = "very high  (looks encrypted / packed)"
    elif entropy >= 6.0: rating = "high       (likely compressed or binary)"
    elif entropy >= 4.0: rating = "medium"
    else:                rating = "low        (may contain readable strings)"

    print(file=sys.stderr)
    if label:
        print(_section(label), file=sys.stderr)
    else:
        print(SEP, file=sys.stderr)

    print(f"  Size                 : {len(data)} bytes  /  0x{len(data):X}", file=sys.stderr)
    print(f"  Entropy              : {entropy:.4f} / 8.0000", file=sys.stderr)
    print(f"                       : {rating}", file=sys.stderr)

    if null_offs:
        preview = ", ".join(f"0x{o:X}" for o in null_offs[:6])
        more    = f" ... (+{len(null_offs)-6} more)" if len(null_offs) > 6 else ""
        print(f"  Null bytes           : {len(null_offs)}  at {preview}{more}", file=sys.stderr)
    else:
        print(f"  Null bytes           : 0", file=sys.stderr)

    if badchars:
        hits = scan_badchars(data, badchars)
        if hits:
            print(f"  Bad chars            :", file=sys.stderr)
            for bc, offsets in hits.items():
                preview = ", ".join(f"0x{o:X}" for o in offsets[:4])
                more    = f" ... (+{len(offsets)-4} more)" if len(offsets) > 4 else ""
                print(f"    [x] \\x{bc:02x}          : {len(offsets)}x  at {preview}{more}", file=sys.stderr)
        else:
            print(f"  [+] Bad chars        : none found", file=sys.stderr)

    print(f"  MD5                  : {hashes['MD5']}", file=sys.stderr)
    print(f"  SHA1                 : {hashes['SHA1']}", file=sys.stderr)
    print(f"  SHA256               : {hashes['SHA256']}", file=sys.stderr)
    print(SEP, file=sys.stderr)

# ============================================================
#  OUTPUT HELPERS
# ============================================================

def write_text(content: str, out_path):
    if out_path:
        with open(out_path, "w", encoding="utf-8") as f: f.write(content)
    else:
        sys.stdout.write(content)

def write_binary(content: bytes, out_path):
    if out_path:
        with open(out_path, "wb") as f: f.write(content)
        print(f"  [+] Written to       : {out_path}", file=sys.stderr)
    else:
        sys.stdout.buffer.write(content)

# ============================================================
#  USAGE
# ============================================================

USAGE = """
bin2sc — Convert any binary file to shellcode-usable output formats

Usage:
    bin2sc.py <file> <format(s)> [encoding(s)] [options]
    bin2sc.py -      <format(s)> [encoding(s)] [options]

Output formats (combinable):
    --c  --python  --powershell  --java  --go  --rust
    --nasm  --fasm  --masm  --csharp  --base64  --uuid
    --hex-dump  --hex  --linear  --raw

    --csharp         C# byte[] array  (for .NET loaders / Cobalt Strike BOFs)
    --hex            Clean uppercase hex string  (CyberChef, Wireshark, debuggers)

Encoding (chainable, applied left to right):
    --xor KEY            Single byte XOR
    --xor-rolling KEYS   Rolling XOR  e.g. "0x41,0x42,0x43"
    --not                Bitwise NOT
    --add VAL            Add VAL to every byte mod 256
    --sub VAL            Subtract VAL from every byte mod 256
    --xor-auto           Try all 255 XOR keys  (requires --badchars)

Analysis:
    --badchars CHARS     Scan for bad characters  e.g. "\\x00\\x0a\\x0d"
    --null-free          Check for null bytes
    --printable          Show printable ASCII ranges
    --freq               Byte frequency histogram  (top 32 bytes)
    --find-pattern BYTES Search for byte pattern  e.g. "\\x90\\x90" or "90 90"
    --verify             Decode encoded payload in-memory, assert matches original
    --hash / --stats-only  Print stats then exit
    --diff FILE_B        Byte-by-byte diff

Transforms (applied before encoding):
    --patch "OFFSET VAL"   Patch a single byte  e.g. "0x10 0x90"
    --size-align N         Pad to next multiple of N bytes with NOPs
    --reverse              Reverse byte order of entire payload

Options:
    --name NAME    Variable name  (default: shellcode)
    --arch ARCH    Architecture label  e.g. x86, x64
    --out  FILE    Write to FILE instead of stdout
"""

# ============================================================
#  ENTRY POINT
# ============================================================

def main():
    if len(sys.argv) < 2:
        print(USAGE); sys.exit(0)

    class Parser(argparse.ArgumentParser):
        def error(self, message):
            print(f"[!] {message}", file=sys.stderr)
            print(f"    Run without arguments or see --help for usage.", file=sys.stderr)
            sys.exit(1)

    parser = Parser(description="bin2sc — binary to shellcode converter", add_help=True)
    parser.add_argument("file")

    parser.add_argument("--c",          action="store_true")
    parser.add_argument("--python",     action="store_true")
    parser.add_argument("--powershell", action="store_true")
    parser.add_argument("--java",       action="store_true")
    parser.add_argument("--go",         action="store_true")
    parser.add_argument("--rust",       action="store_true")
    parser.add_argument("--nasm",       action="store_true")
    parser.add_argument("--fasm",       action="store_true")
    parser.add_argument("--masm",       action="store_true")
    parser.add_argument("--csharp",     action="store_true")
    parser.add_argument("--base64",     action="store_true")
    parser.add_argument("--uuid",       action="store_true")
    parser.add_argument("--hex-dump",   action="store_true", dest="hex_dump")
    parser.add_argument("--hex",        action="store_true")
    parser.add_argument("--linear",     action="store_true")
    parser.add_argument("--raw",        action="store_true")

    parser.add_argument("--xor",         default=None, metavar="KEY")
    parser.add_argument("--xor-rolling", default=None, metavar="KEYS", dest="xor_rolling")
    parser.add_argument("--not",         action="store_true", dest="not_enc")
    parser.add_argument("--add",         default=None, metavar="VAL")
    parser.add_argument("--sub",         default=None, metavar="VAL")
    parser.add_argument("--xor-auto",    action="store_true", dest="xor_auto")

    parser.add_argument("--badchars",      default=None, metavar="CHARS")
    parser.add_argument("--null-free",     action="store_true", dest="null_free")
    parser.add_argument("--printable",     action="store_true")
    parser.add_argument("--freq",          action="store_true")
    parser.add_argument("--find-pattern",  default=None, metavar="BYTES", dest="find_pattern")
    parser.add_argument("--hash",          action="store_true")
    parser.add_argument("--stats-only",    action="store_true", dest="stats_only")
    parser.add_argument("--diff",          default=None, metavar="FILE_B")
    parser.add_argument("--verify",        action="store_true")

    parser.add_argument("--patch",      default=None, metavar="'OFFSET VAL'")
    parser.add_argument("--size-align", default=None, metavar="N", dest="size_align", type=int)
    parser.add_argument("--reverse",    action="store_true")

    parser.add_argument("--name", default="shellcode", metavar="NAME")
    parser.add_argument("--arch", default=None,        metavar="ARCH")
    parser.add_argument("--out",  default=None,        metavar="FILE")

    args = parser.parse_args()

    if args.file == "-":
        data, source_label = sys.stdin.buffer.read(), "stdin"
    else:
        if not os.path.isfile(args.file):
            print(f"[!] File not found: {args.file}", file=sys.stderr); sys.exit(1)
        with open(args.file, "rb") as f: data = f.read()
        source_label = args.file

    if len(data) == 0:
        print("[!] Input is empty.", file=sys.stderr); sys.exit(1)

    badchars = parse_badchars(args.badchars) if args.badchars else None

    if args.diff:
        diff_files(args.file, args.diff); sys.exit(0)

    if args.hash or args.stats_only:
        print_stats(data, badchars, label=f"Stats  -  {source_label}")
        sys.exit(0)

    if args.null_free:
        check_null_free(data)

    if args.printable:
        print_printable(data)

    if args.freq:
        print_freq(data)

    if args.find_pattern:
        pattern = parse_pattern(args.find_pattern)
        print_find_pattern(data, pattern)

    if args.xor_auto:
        if not badchars:
            print("[!] --xor-auto requires --badchars", file=sys.stderr); sys.exit(1)
        print_xor_auto_results(xor_auto_find(data, badchars), badchars)

    analysis_only = any([args.null_free, args.printable, args.xor_auto,
                         args.freq, args.find_pattern is not None])
    all_formats   = [args.c, args.python, args.powershell, args.java, args.go,
                     args.rust, args.nasm, args.fasm, args.masm, args.csharp,
                     args.base64, args.uuid, args.hex_dump, args.hex,
                     args.linear, args.raw]
    if analysis_only and not any(all_formats):
        sys.exit(0)

    if args.patch:
        data = apply_patch(data, args.patch)

    if args.size_align:
        data = apply_size_align(data, args.size_align)

    if args.reverse:
        data = apply_reverse(data)
        print(f"  [~] Reversed         : byte order flipped ({len(data)} bytes)", file=sys.stderr)

    print_stats(data, badchars, label=f"Original  -  {source_label}")

    encoded_data, enc_desc = apply_encoding_chain(data, args)
    encoding_applied       = any_encoding(args)

    if encoding_applied:
        print_stats(encoded_data, badchars, label=f"Encoded  ({enc_desc})")
        if args.verify:
            ok = verify_round_trip(data, encoded_data, args)
            if not ok:
                sys.exit(1)
        work_data = encoded_data
    else:
        if args.verify:
            print(f"  [!] --verify skipped : no encoding flags specified", file=sys.stderr)
        work_data = data

    if not any(all_formats):
        # verify-only is a valid run — encoding + verify with no output format
        if args.verify and encoding_applied:
            sys.exit(0)
        print("[!] No output format specified.", file=sys.stderr)
        print("    Run without arguments or see --help for usage.", file=sys.stderr)
        sys.exit(1)

    output_parts = []

    if args.c:
        part = fmt_c_array(work_data, args.name, args.arch)
        if encoding_applied: part += "\n" + build_decoder_c(args.name, args, args.arch)
        output_parts.append(part)

    if args.python:
        part = fmt_python_block(work_data, args.name, args.arch)
        if encoding_applied: part += "\n" + build_decoder_python(args.name, args, args.arch)
        output_parts.append(part)

    if args.powershell:  output_parts.append(fmt_powershell(work_data, args.name, args.arch))
    if args.java:        output_parts.append(fmt_java(work_data, args.name, args.arch))
    if args.go:          output_parts.append(fmt_go(work_data, args.name, args.arch))
    if args.rust:        output_parts.append(fmt_rust(work_data, args.name, args.arch))
    if args.nasm:        output_parts.append(fmt_nasm(work_data, args.name, args.arch))
    if args.fasm:        output_parts.append(fmt_fasm(work_data, args.name, args.arch))
    if args.masm:        output_parts.append(fmt_masm(work_data, args.name, args.arch))
    if args.csharp:      output_parts.append(fmt_csharp(work_data, args.name, args.arch))
    if args.base64:      output_parts.append(fmt_base64(work_data, args.name, args.arch))
    if args.uuid:        output_parts.append(fmt_uuid(work_data, args.name, args.arch))
    if args.hex_dump:    output_parts.append(fmt_hex_dump(work_data))
    if args.hex:         output_parts.append(fmt_hex(work_data))
    if args.linear:      output_parts.append(fmt_linear(work_data) + "\n")

    if output_parts:
        write_text("\n".join(output_parts), args.out)

    if args.raw:
        if output_parts and args.out:
            print("  [!] --raw skipped: --out already used by text output. Run --raw separately.", file=sys.stderr)
        else:
            write_binary(fmt_raw(work_data), args.out if not output_parts else None)


if __name__ == "__main__":
    main()