# bin2sc

Convert any binary file to shellcode-usable output formats. Supports multiple
output languages, chainable encoding, bad char scanning, analysis tools,
transforms, and verification.

---

## Table of Contents

- [Usage](#usage)
- [Output Formats](#output-formats)
  - [--c](#--c)
  - [--python](#--python)
  - [--csharp](#--csharp)
  - [--powershell](#--powershell)
  - [--java](#--java)
  - [--go](#--go)
  - [--rust](#--rust)
  - [--nasm](#--nasm)
  - [--fasm](#--fasm)
  - [--masm](#--masm)
  - [--base64](#--base64)
  - [--uuid](#--uuid)
  - [--hex-dump](#--hex-dump)
  - [--hex](#--hex)
  - [--linear](#--linear)
  - [--raw](#--raw)
- [Encoding](#encoding)
  - [--xor KEY](#--xor-key)
  - [--xor-rolling KEYS](#--xor-rolling-keys)
  - [--not](#--not)
  - [--add VAL](#--add-val)
  - [--sub VAL](#--sub-val)
  - [Chained encoding](#chained-encoding)
  - [--xor-auto](#--xor-auto)
- [Analysis](#analysis)
  - [--badchars CHARS](#--badchars-chars)
  - [--null-free](#--null-free)
  - [--printable](#--printable)
  - [--freq](#--freq)
  - [--find-pattern BYTES](#--find-pattern-bytes)
  - [--hash / --stats-only](#--hash----stats-only)
  - [--diff FILE_B](#--diff-file_b)
  - [--verify](#--verify)
- [Transforms](#transforms)
  - [--patch "OFFSET VAL"](#--patch-offset-val)
  - [--size-align N](#--size-align-n)
  - [--reverse](#--reverse)
- [Options](#options)
  - [--name NAME](#--name-name)
  - [--arch ARCH](#--arch-arch)
  - [--out FILE](#--out-file)
- [Stdin Support](#stdin-support)
- [Combining Flags](#combining-flags)
- [Exit Codes](#exit-codes)
- [Install](#install)
- [License](#license)

---

## Usage

```shell
bin2sc.py <file> <format(s)> [encoding(s)] [options]
bin2sc.py -      <format(s)> [encoding(s)] [options]
```

Pass `-` as the file to read raw bytes from stdin.

---

## Output Formats

Multiple format flags can be combined in a single run. Each produces a separate
block in the output.

---

### --c

C `unsigned char` array, 12 bytes per line. Also emits a `_len` variable.
If an encoding flag is present, a matching C decoder stub is appended.

```shell
bin2sc.py payload.bin --c
bin2sc.py payload.bin --c --name buf --arch x64
```

Output:

```c
/* x64 shellcode - 6 bytes */
unsigned char buf[] = {
    0x48, 0x31, 0xc0, 0x48, 0x31, 0xff
};
unsigned int  buf_len = 6;
```

---

### --python

Python `bytes` literal in parentheses, 16 bytes per line. Also emits a `_len`
variable. If an encoding flag is present, a matching Python decoder stub is
appended.

```shell
bin2sc.py payload.bin --python
bin2sc.py payload.bin --python --name sc --arch x86
```

Output:

```python
# x86 shellcode - 6 bytes
sc = (
    b"\x48\x31\xc0\x48\x31\xff"
)
sc_len = 6
```

---

### --csharp

C# `byte[]` array, 16 bytes per line. Standard format for .NET loaders,
Cobalt Strike BOFs, and offensive C# tooling.

```shell
bin2sc.py payload.bin --csharp
bin2sc.py payload.bin --csharp --name shellcode --arch x64
```

Output:

```csharp
// x64 shellcode - 6 bytes
byte[] shellcode = new byte[6] {
    0x48, 0x31, 0xc0, 0x48, 0x31, 0xff
};
```

---

### --powershell

PowerShell `[Byte[]]` array, 16 bytes per line, using backtick line
continuation.

```shell
bin2sc.py payload.bin --powershell
bin2sc.py payload.bin --powershell --name buf
```

Output:

```powershell
[Byte[]] $buf = `
    0x48,0x31,0xc0,0x48,0x31,0xff
$buf_len = 6
```

---

### --java

Java `byte[]` array, 8 entries per line. Values above `0x7F` are cast with
`(byte)` since Java bytes are signed.

```shell
bin2sc.py payload.bin --java
bin2sc.py payload.bin --java --name payload
```

Output:

```java
byte[] payload = {
    0x48, 0x31, 0xc0, (byte)0xff
};
int    payload_len = 4;
```

---

### --go

Go `[]byte` slice, 12 bytes per line.

```shell
bin2sc.py payload.bin --go
bin2sc.py payload.bin --go --name sc --arch x64
```

Output:

```go
// x64 shellcode - 6 bytes
var sc = []byte{
    0x48, 0x31, 0xc0, 0x48, 0x31, 0xff,
}
var scLen = 6
```

---

### --rust

Rust `&[u8]` static byte array, 12 bytes per line. Variable name is
uppercased per Rust convention.

```shell
bin2sc.py payload.bin --rust
bin2sc.py payload.bin --rust --name payload --arch x64
```

Output:

```rust
// x64 shellcode - 6 bytes
static PAYLOAD: &[u8] = &[
    0x48, 0x31, 0xc0, 0x48, 0x31, 0xff,
];
const  PAYLOAD_LEN: usize = 6;
```

---

### --nasm

NASM `db` format, 12 bytes per line. Uses `equ $ - label` for size.

```shell
bin2sc.py payload.bin --nasm
bin2sc.py payload.bin --nasm --name sc --arch x86
```

Output:

```asm
; x86 shellcode - 6 bytes
sc: db 0x48, 0x31, 0xc0, 0x48, 0x31, 0xff
sc_len equ $ - sc
```

---

### --fasm

FASM `db` format, 12 bytes per line. Uses `$ - label` for size.

```shell
bin2sc.py payload.bin --fasm
bin2sc.py payload.bin --fasm --name sc --arch x86
```

Output:

```asm
; x86 shellcode - 6 bytes
sc db 0x48, 0x31, 0xc0, 0x48, 0x31, 0xff
sc_size = $ - sc
```

---

### --masm

MASM `BYTE` format with `0NNh` suffix hex style, 12 bytes per line.

```shell
bin2sc.py payload.bin --masm
bin2sc.py payload.bin --masm --name sc --arch x86
```

Output:

```asm
; x86 shellcode - 6 bytes
sc BYTE 048h, 031h, 0c0h, 048h, 031h, 0ffh
sc_len EQU $ - sc
```

---

### --base64

Base64 encoded output split into 76-character lines, wrapped in a Python
block with an inline `base64.b64decode` call for direct use in scripts.

```shell
bin2sc.py payload.bin --base64
```

Output:

```python
# 6 bytes (8 base64 chars)
shellcode_b64 = (
    "SDHASDHw"
)
import base64
shellcode = base64.b64decode(''.join(shellcode_b64))
```

---

### --uuid

UUID shellcode format for `UuidFromStringA` / `RtlEthernetStringToAddress`
injection techniques. Pads the payload to a 16-byte boundary with NOPs
(`0x90`), then encodes each 16-byte block as a UUID string with correct
little-endian field ordering.

```shell
bin2sc.py payload.bin --uuid --arch x64
```

Output:

```python
# x64 shellcode - 16 bytes as UUIDs
# Usage: call UuidFromStringA on each entry, write to RWX buffer
shellcode_uuids = [
    "c0314831-ff31-9090-9090-909090909090",
]
shellcode_count = 1
```

---

### --hex-dump

`xxd`-style hex dump: offset, hex bytes, ASCII representation. 16 bytes per
line. Non-printable bytes shown as `.` in the ASCII column.

```shell
bin2sc.py payload.bin --hex-dump
```

Output:

```
00000000  48 31 c0 48 31 ff 90 90  90 90 90 90 90 90 90 90  |H1.H1...........|
```

---

### --hex

Clean uppercase hex string with no prefix, separators, or line breaks.
Useful for pasting into CyberChef, Wireshark display filters, debugger search
boxes, or any tool that expects raw hex input.

```shell
bin2sc.py payload.bin --hex
bin2sc.py payload.bin --xor 0x41 --hex
```

Output:

```
4831C04831FF
```

---

### --linear

Single continuous `\xNN` hex string on one line. Paste directly into Python,
C strings, or any tool that uses this notation.

```shell
bin2sc.py payload.bin --linear
```

Output:

```
\x48\x31\xc0\x48\x31\xff
```

---

### --raw

Write raw binary bytes to stdout or to `--out`. Use for piping or saving a
binary-transformed payload.

```shell
bin2sc.py payload.bin --xor 0x41 --raw --out encoded.bin
bin2sc.py payload.bin --raw | xxd | head
```

---

## Encoding

Encoding flags are chainable and applied left to right in a fixed order:
`xor` -> `xor-rolling` -> `not` -> `add` -> `sub`. The decoder stubs
(emitted automatically with `--c` and `--python`) reverse this order.

---

### --xor KEY

Single-byte XOR. Every byte is XOR'd with the same key.

```shell
bin2sc.py payload.bin --xor 0x41 --c
```

Produces a C array of the XOR'd bytes plus a decoder stub that XORs again
with `0x41` to restore the original.

---

### --xor-rolling KEYS

Rolling XOR. Cycles through the key list: `byte[0]^keys[0]`, `byte[1]^keys[1]`,
..., wrapping back to `keys[0]` after the last key. Harder to detect than
single-key XOR because the repeating pattern is `len(keys)` bytes wide.

```shell
bin2sc.py payload.bin --xor-rolling "0x41,0x42,0x43" --c
```

---

### --not

Bitwise NOT. Flips every bit in every byte. Applying NOT twice restores the
original, so the decoder just runs NOT again.

```shell
bin2sc.py payload.bin --not --linear
```

---

### --add VAL

Add a constant value to every byte, wrapping at 256.

```shell
bin2sc.py payload.bin --add 0x05 --c
```

---

### --sub VAL

Subtract a constant value from every byte, wrapping at 256.

```shell
bin2sc.py payload.bin --sub 0x13 --python
```

---

### Chained encoding

Flags combine in order. The decoder stubs undo them in reverse.

```shell
bin2sc.py payload.bin --xor 0x41 --add 0x05 --c
bin2sc.py payload.bin --not --xor-rolling "0x11,0x22,0x33" --python
```

---

### --xor-auto

Try all 255 possible single-byte XOR keys (skipping `0x00`) and report
which ones produce zero bad char hits. Requires `--badchars`.

```shell
bin2sc.py payload.bin --xor-auto --badchars "\x00\x0a\x0d"
```

Output lists each clean key and suggests the first one as a `--xor` argument.

---

## Analysis

Analysis flags operate on the original data before transforms and encoding.
They print to stderr so they do not interfere with format output on stdout.

---

### --badchars CHARS

Scan for bad characters and report their offsets. Accepts `\x00\x0a`,
`00 0a`, or `0x00 0x0a` notation. Works with any format or encoding flag.

```shell
bin2sc.py payload.bin --badchars "\x00\x0a\x0d"
bin2sc.py payload.bin --xor 0x41 --c --badchars "\x00\x0a\x0d"
```

When combined with encoding, bad char hits are reported for both the original
and the encoded output so you can verify the encoding eliminated them.

---

### --null-free

Check whether the payload contains any null bytes (`0x00`). Reports the count
and offsets if found, and notes whether the payload is safe for
`strcpy`/`strlen`-based copy routines.

```shell
bin2sc.py payload.bin --null-free
bin2sc.py payload.bin --xor 0x41 --null-free --c
```

---

### --printable

Find contiguous runs of printable ASCII (0x20-0x7e), minimum 4 bytes. Useful
for spotting embedded strings, identifying known code patterns, or checking
alphanumeric shellcode constraints.

```shell
bin2sc.py payload.bin --printable
```

Output:

```
=============  PRINTABLE RANGES  (3 found, min 4 bytes)  ==============
  Offset range            Len  String
  --------------------  -----  ----------------------------------------
  0x0005 - 0x000F          11  'Hello World'
```

---

### --freq

Byte frequency histogram for the top 32 most common bytes. Bar width is
scaled to the most frequent byte. Printable bytes show their ASCII character
alongside the hex value.

```shell
bin2sc.py payload.bin --freq
bin2sc.py payload.bin --xor 0x41 --freq
```

Useful for confirming encoding changed the byte distribution, or spotting a
dominant byte (such as `0x00` in sparse data) before choosing an XOR key.

Output:

```
==========  BYTE FREQUENCY  (top 8 of 8 unique)  ===========
  Byte     Count     Pct      Histogram
  ------  ------  ------      ----------------------------------------
  0x6c l      384   18.8%  |########################################|
  0x00        256   12.5%  |##########################              |
```

---

### --find-pattern BYTES

Search for a specific byte sequence and report all matching offsets.
Accepts `\x90\x90`, `90 90`, or `0x90 0x90` notation.

```shell
bin2sc.py payload.bin --find-pattern "\x48\x31\xc0"
bin2sc.py payload.bin --find-pattern "90 90 90 90"
```

Output shows a numbered table of all offsets, capped at 64 with an overflow
count. Useful for locating function prologues, NOPs sleds, known signatures,
or verifying a patch landed at the right location.

---

### --hash / --stats-only

Print size, entropy, null byte count, bad chars (if `--badchars` is set),
and MD5/SHA1/SHA256 hashes, then exit without producing any format output.
Both flags behave identically.

```shell
bin2sc.py payload.bin --hash
bin2sc.py payload.bin --stats-only --badchars "\x00"
```

---

### --diff FILE_B

Byte-by-byte comparison between the input file and `FILE_B`. Reports size,
total differences, a table of the first 64 differing offsets, and MD5 hashes
for both files.

```shell
bin2sc.py original.bin --diff modified.bin
```

---

### --verify

After applying the encoding chain, decode the encoded payload in-memory in
reverse order and assert it matches the original byte-for-byte. Exits with
code 1 if verification fails and prints the first mismatching offset.

Use this whenever working with chained encoders to catch silent bugs such as a
wrong key, wrong order, or off-by-one in the rolling XOR.

```shell
bin2sc.py payload.bin --xor 0x41 --add 0x05 --c --verify
bin2sc.py payload.bin --xor-rolling "0x11,0x22" --not --verify --linear
```

Output on success:

```
=============================  VERIFY ROUND-TRIP  ==============================
  Original size        : 2048 bytes
  Encoded size         : 2048 bytes
  Decoded size         : 2048 bytes
  [+] Result           : PASS -- decoded matches original exactly
```

---

## Transforms

Transforms are applied to the data before encoding. Order of application:
`--patch` -> `--size-align` -> `--reverse`.

---

### --patch "OFFSET VAL"

Patch a single byte at the given offset before output. Both offset and value
accept decimal or `0x` hex notation.

```shell
bin2sc.py payload.bin --patch "0x10 0x90" --c
bin2sc.py payload.bin --patch "16 144" --linear
```

Useful for replacing a placeholder byte in a template payload or converting
a `jmp` target without reassembling.

---

### --size-align N

Pad the payload to the next multiple of N bytes using NOP instructions
(`0x90`). Applied before encoding.

```shell
bin2sc.py payload.bin --size-align 4096 --c
bin2sc.py payload.bin --size-align 16 --uuid
```

Useful for page-boundary alignment, loader requirements, or ensuring the UUID
format receives full 16-byte blocks without unexpected NOP padding.

---

### --reverse

Reverse the byte order of the entire payload before encoding. Used in
injection techniques where a loader writes bytes onto the stack from high
address to low, or walks a buffer in reverse.

```shell
bin2sc.py payload.bin --reverse --linear
bin2sc.py payload.bin --reverse --xor 0x41 --c
```

---

## Options

---

### --name NAME

Set the variable name used in all format outputs. Default is `shellcode`.

```shell
bin2sc.py payload.bin --c --name buf
bin2sc.py payload.bin --python --rust --name stage2
```

---

### --arch ARCH

Add an architecture label as a comment in the output header. Has no effect
on the bytes themselves.

```shell
bin2sc.py payload.bin --c --arch x64
bin2sc.py payload.bin --nasm --arch x86
```

---

### --out FILE

Write text output to a file instead of stdout. Binary output (`--raw`) also
uses this flag, but cannot share it with text formats in the same run.

```shell
bin2sc.py payload.bin --c --out shellcode.h
bin2sc.py payload.bin --python --out sc.py --name buf --arch x64
```

---

## Stdin Support

Pass `-` as the filename to read from stdin. Useful for pipeline use.

```shell
cat payload.bin | bin2sc.py - --linear
cat payload.bin | bin2sc.py - --xor 0x41 --c --arch x64
cat payload.bin | bin2sc.py - --xor 0x41 --verify --hex
```

---

## Combining Flags

Most flags are orthogonal and compose freely. A typical workflow:

```shell
# Check the payload first
bin2sc.py payload.bin --hash --badchars "\x00\x0a\x0d"

# Find a clean XOR key
bin2sc.py payload.bin --xor-auto --badchars "\x00\x0a\x0d"

# Encode, verify, and output in two formats
bin2sc.py payload.bin --xor 0x41 --verify --c --python \
    --badchars "\x00\x0a\x0d" --arch x64 --name buf --out output.h

# Encode, save raw binary, check freq
bin2sc.py payload.bin --xor 0x41 --raw --out encoded.bin
bin2sc.py encoded.bin --freq
```

---

## Exit Codes

```
0   Success
1   Error (file not found, invalid argument, --verify failed)
```

---

## Install
```bash
git clone https://github.com/0xNullll/bin2sc
cd bin2sc
python3 bin2sc.py
```

---

## License

This project is released under the **MIT license**. See [LICENSE](LICENSE) for full text.