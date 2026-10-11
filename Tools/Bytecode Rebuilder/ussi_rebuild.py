"""Rebuild a USSI place saved with DumpBytecode into a place with real script source.

Takes a place saved with saveinstance's DumpBytecode option, decompiles every script's
bytecode with a local decompiler, and writes a copy of the place with real source in place
of each bytecode line. The bytecode is either embedded in the place itself
(`-- USSI_BYTECODE_BASE64: <bytecode>`, the default) or in a `<place>.bytecode.zip` saved
beside it (`-- USSI_BYTECODE: <file>`, with DumpBytecodeZip). "<place>.bytecode.rbxlx"
is rebuilt as "<place>.rbxlx" next to it.

    python -I ussi_rebuild.py "place 123 Name.bytecode.rbxlx"
    python -I ussi_rebuild.py "place 123 Name.bytecode.zip" --decompiler path/to/luau-lifter.exe

The decompiler is any command that takes a bytecode file path and prints Luau source to
stdout; the default arguments match Tovek's / medal's luau-lifter (`<file> -e`).

Safety:
  * The input files are only read. The output is written to a temporary file,
    re-read and checked, then renamed into place; an existing output is never overwritten
    unless --force is given.
  * Nothing is extracted from the zip by its own entry names. Names must match the exact
    pattern USSI writes, so path tricks like "../" are impossible, and entry sizes are capped.
  * The decompiler runs without a shell, on a private temp copy of one bytecode file at a
    time, with a timeout. Nothing is sent over the network.
  * Only the parts of the place that hold script source are touched. In .rbxl files every
    other chunk is copied byte for byte.

Needs Python 3.10+. zstd-compressed .rbxl chunks (the USSI default) need Python 3.14+ or
`pip install zstandard`.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import concurrent.futures
import hashlib
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from xml.parsers import expat

# Group 1: zip entry name (DumpBytecodeZip). Group 2: embedded base64 bytecode (default).
# Both captures stop at anything those can't contain (like XML's "]]>" or "<").
MARKER = re.compile(rb"-- USSI_BYTECODE(?:: ([A-Za-z0-9 _./\\-]*)|_BASE64: ([A-Za-z0-9+/=]*))")
# Exactly what DumpBytecode writes: bytecode/<n>_<sanitized ClassName Name>.luauc
VALID_ENTRY = re.compile(r"bytecode/[0-9]{1,9}_[A-Za-z0-9 _]{0,80}\.luauc")

MAX_ENTRY_BYTES = 64 << 20
MAX_TOTAL_BYTES = 4 << 30
MAX_ENTRIES = 1_000_000
MAX_SOURCE_BYTES = 64 << 20
MAX_CHUNK_BYTES = 1 << 30

RBXL_MAGIC = b"<roblox!\x89\xff\r\n\x1a\n"
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
STRING_TYPE = 0x01  # binary format type id shared by string / ProtectedString


class RebuildError(Exception):
    pass


# ---------------------------------------------------------------- zip input


def read_dump(zip_path: Path) -> tuple[dict, dict[str, bytes]]:
    """Returns (manifest, {entry name: bytecode}) after validating every entry."""
    try:
        archive = zipfile.ZipFile(zip_path)
    except zipfile.BadZipFile as e:
        raise RebuildError(f"{zip_path} is not a valid zip: {e}") from e

    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ENTRIES:
            raise RebuildError(f"zip has {len(infos)} entries, refusing more than {MAX_ENTRIES}")

        manifest, files, total = {}, {}, 0
        for info in infos:
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                raise RebuildError(f"zip entry {info.filename!r} is encrypted")
            if info.file_size > MAX_ENTRY_BYTES * (8 if info.filename == "manifest.json" else 1):
                raise RebuildError(f"zip entry {info.filename!r} is too large ({info.file_size} bytes)")
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise RebuildError("zip contents are too large")

            if info.filename == "manifest.json":
                try:
                    manifest = json.loads(archive.read(info))
                except ValueError as e:
                    raise RebuildError(f"manifest.json is not valid JSON: {e}") from e
                if not isinstance(manifest, dict):
                    raise RebuildError("manifest.json is not a JSON object")
            elif VALID_ENTRY.fullmatch(info.filename):
                files[info.filename] = archive.read(info)  # zipfile verifies the CRC
            else:
                print(f"warning: ignoring unexpected zip entry {info.filename!r}", file=sys.stderr)

    return manifest, files


# ---------------------------------------------------------------- decompiling


def lua_block_comment(text: str) -> str:
    level = 0
    while f"]{'=' * level}]" in text:
        level += 1
    eq = "=" * level
    return f"--[{eq}[{text}]{eq}]"


def script_names_by_file(manifest: dict) -> dict[str, str]:
    names = {}
    scripts = manifest.get("Scripts")
    if isinstance(scripts, list):
        for entry in scripts:
            if isinstance(entry, dict) and isinstance(entry.get("File"), str) and isinstance(entry.get("Path"), str):
                names.setdefault(entry["File"], entry["Path"])
    return names


def decompile_all(
    files: dict[str, bytes],
    command: list[str],
    script_names: dict[str, str],
    jobs: int,
    timeout: float,
) -> tuple[dict[str, bytes], dict[str, str]]:
    """Returns ({key: source}, {key: outcome}) where outcome is "ok", "partial", "empty" or
    "failed". Failures get a comment with the reason instead of source."""
    results: dict[str, bytes] = {}
    outcomes: dict[str, str] = {}

    with tempfile.TemporaryDirectory(prefix="ussi_rebuild_") as tmp:
        tmp_dir = Path(tmp)

        def decompile_once(args: list[str]) -> tuple[int, bytes, str]:
            try:
                proc = subprocess.run(
                    args,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    timeout=timeout,
                    shell=False,
                    cwd=tmp_dir,
                )
            except subprocess.TimeoutExpired:
                return -1, b"", f"timed out after {timeout:g}s"
            except OSError as e:
                return -1, b"", f"could not start decompiler: {e}"
            err = proc.stderr.decode("utf-8", "replace").strip() or f"exit code {proc.returncode}"
            return proc.returncode, proc.stdout, err[:4000]

        def run(index: int, entry: str) -> tuple[str, bytes | None, str, str]:
            bytecode_path = tmp_dir / f"{index}.luauc"
            bytecode_path.write_bytes(files[entry])
            args = [part.replace("{file}", str(bytecode_path)) for part in command]
            if "{file}" not in " ".join(command):
                args.append(str(bytecode_path))
            name = script_names.get(entry)
            if name and "{name}" in " ".join(command):
                # Strip control characters; the value is passed as one argv entry, never via a shell
                clean = re.sub(r"[\x00-\x1f\x7f]", "", name)[:500]
                args = [part.replace("{name}", clean) for part in args]
            try:
                code, stdout, err = decompile_once(args)
                outcome = "ok"
                if code > 0 and "--partial" not in args:
                    # Tovek's --partial (USSI patch) stubs only the functions it can't structure.
                    # A decompiler without it rejects the flag, and the first error is kept.
                    retry_code, retry_stdout, _ = decompile_once([*args, "--partial"])
                    if retry_code == 0 and retry_stdout.strip():
                        code, stdout, outcome = 0, retry_stdout, "partial"
            finally:
                bytecode_path.unlink(missing_ok=True)

            if code != 0:
                return entry, None, err, "failed"
            if not stdout.strip():
                # Tovek prints nothing when the script's top level is empty or just returns
                # (e.g. "do return end" disabling it); any functions in it are unreachable
                return entry, b"-- USSI rebuild: this script does nothing (its top level is empty or returns immediately)", "", "empty"
            if len(stdout) > MAX_SOURCE_BYTES:
                return entry, None, f"output too large ({len(stdout)} bytes)", "failed"
            source = stdout.replace(b"\r\n", b"\n").rstrip(b"\n")
            if outcome == "partial":
                source = (
                    b"-- USSI rebuild: partially decompiled. Functions that could not be decompiled are stubbed;\n"
                    b'-- search for "Tovek --partial". The original bytecode is kept at the bottom.\n\n' + source
                )
            return entry, source, "", outcome

        entries = sorted(files)
        done = 0
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            for entry, source, err, outcome in pool.map(lambda pair: run(*pair), enumerate(entries)):
                done += 1
                if source is None:
                    source = lua_block_comment(f" USSI rebuild: failed to decompile {entry}\n{err}\n").encode()
                results[entry] = source
                outcomes[entry] = outcome
                if done % 50 == 0 or done == len(entries):
                    print(f"  decompiled {done}/{len(entries)}", file=sys.stderr)

    return results, outcomes


def embedded_key(encoded: bytes) -> str:
    return "embedded/" + hashlib.sha256(encoded).hexdigest()[:16] + ".luauc"


def collect_embedded(source_texts) -> dict[str, bytes]:
    """Decodes every embedded bytecode marker once; identical bytecode shares one key."""
    found: dict[str, bytes] = {}
    for text in source_texts:
        for match in MARKER.finditer(text):
            encoded = match.group(2)
            if not encoded or len(encoded) > MAX_ENTRY_BYTES * 4 // 3 + 4:
                continue
            key = embedded_key(encoded)
            if key in found:
                continue
            try:
                found[key] = base64.b64decode(encoded, validate=True)
            except (binascii.Error, ValueError):
                print("warning: an embedded bytecode line is corrupt, leaving it as-is", file=sys.stderr)
    return found


class Replacer:
    """Swaps marker lines for decompiled source and counts what happened."""

    def __init__(self, sources: dict[str, bytes], failed: set[str]):
        self.sources = sources
        self.failed = failed
        self.replaced = 0
        self.unresolved: list[str] = []

    def lookup(self, match: re.Match) -> bytes | None:
        if match.group(2) is not None:
            key = embedded_key(match.group(2))
        else:
            name = match.group(1).decode("utf-8", "replace").strip()
            key = name if VALID_ENTRY.fullmatch(name) else None
        source = self.sources.get(key) if key else None
        if source is None:
            self.unresolved.append(key or "?")
            return None
        self.replaced += 1
        if key in self.failed:
            return source + b"\n" + match.group(0)  # marker kept so a later run can retry
        return source


# ---------------------------------------------------------------- binary (.rbxl / .rbxm)


def lz4_block_decompress(src: bytes, size: int) -> bytes:
    dst = bytearray()
    i, n = 0, len(src)
    try:
        while i < n:
            token = src[i]
            i += 1
            literal = token >> 4
            if literal == 15:
                while True:
                    b = src[i]
                    i += 1
                    literal += b
                    if b != 255:
                        break
            if i + literal > n:
                raise RebuildError("corrupt LZ4 data (literal overrun)")
            dst += src[i : i + literal]
            i += literal
            if i >= n:
                break
            offset = src[i] | (src[i + 1] << 8)
            i += 2
            match_len = token & 15
            if match_len == 15:
                while True:
                    b = src[i]
                    i += 1
                    match_len += b
                    if b != 255:
                        break
            match_len += 4
            start = len(dst) - offset
            if offset == 0 or start < 0:
                raise RebuildError("corrupt LZ4 data (bad offset)")
            if len(dst) + match_len > size:
                raise RebuildError("corrupt LZ4 data (output overrun)")
            if offset >= match_len:
                dst += dst[start : start + match_len]
            else:
                for k in range(match_len):
                    dst.append(dst[start + k])
    except IndexError as e:
        raise RebuildError("corrupt LZ4 data (truncated)") from e
    if len(dst) != size:
        raise RebuildError(f"LZ4 chunk decoded to {len(dst)} bytes, expected {size}")
    return bytes(dst)


def zstd_decompress(src: bytes, size: int) -> bytes:
    try:
        from compression import zstd  # Python 3.14+

        out = zstd.ZstdDecompressor().decompress(src, max_length=size + 1)
    except ImportError:
        try:
            import zstandard
        except ImportError as e:
            raise RebuildError("this place uses zstd compression: use Python 3.14+ or `pip install zstandard`") from e
        out = zstandard.ZstdDecompressor().decompress(src, max_output_size=size + 1)
    if len(out) != size:
        raise RebuildError(f"zstd chunk decoded to {len(out)} bytes, expected {size}")
    return out


class Chunk:
    __slots__ = ("name", "raw", "compressed_len", "size", "payload")

    def __init__(self, name: bytes, raw: bytes, compressed_len: int, size: int, payload: bytes):
        self.name, self.raw, self.compressed_len, self.size, self.payload = name, raw, compressed_len, size, payload

    def data(self) -> bytes:
        if self.compressed_len == 0:
            return self.payload
        if self.payload[:4] == ZSTD_MAGIC:
            return zstd_decompress(self.payload, self.size)
        return lz4_block_decompress(self.payload, self.size)


def parse_binary(data: bytes) -> tuple[bytes, list[Chunk], bytes]:
    if len(data) < 32 or data[:14] != RBXL_MAGIC:
        raise RebuildError("not a binary Roblox file")
    header, pos, chunks = data[:32], 32, []
    while True:
        if pos + 16 > len(data):
            raise RebuildError("truncated file: no END chunk")
        name = data[pos : pos + 4]
        compressed_len, size, _reserved = struct.unpack_from("<III", data, pos + 4)
        if size > MAX_CHUNK_BYTES or compressed_len > MAX_CHUNK_BYTES:
            raise RebuildError(f"chunk {name!r} is implausibly large")
        end = pos + 16 + (compressed_len or size)
        if end > len(data):
            raise RebuildError(f"truncated chunk {name!r}")
        chunks.append(Chunk(name, data[pos:end], compressed_len, size, data[pos + 16 : end]))
        pos = end
        if name == b"END\0":
            return header, chunks, data[pos:]


def split_strings(blob: bytes, start: int) -> list[bytes] | None:
    values, off = [], start
    while off < len(blob):
        if off + 4 > len(blob):
            return None
        (n,) = struct.unpack_from("<I", blob, off)
        if off + 4 + n > len(blob):
            return None
        values.append(blob[off + 4 : off + 4 + n])
        off += 4 + n
    return values


def source_prop(chunk: Chunk) -> tuple[bytes, list[bytes]] | None:
    """For a Source PROP chunk returns (prefix, values), otherwise None."""
    if chunk.name != b"PROP":
        return None
    blob = chunk.data()
    if len(blob) < 9:
        return None
    (name_len,) = struct.unpack_from("<I", blob, 4)
    name_end = 8 + name_len
    if name_end >= len(blob) or blob[8:name_end] != b"Source" or blob[name_end] != STRING_TYPE:
        return None
    values = split_strings(blob, name_end + 1)
    if values is None:
        raise RebuildError("malformed Source property chunk")
    return blob[: name_end + 1], values


def binary_source_texts(data: bytes):
    for chunk in parse_binary(data)[1]:
        prop = source_prop(chunk)
        if prop:
            yield from prop[1]


def rebuild_binary(data: bytes, replacer: Replacer) -> tuple[bytes, set[int]]:
    header, chunks, trailer = parse_binary(data)
    out, changed = [header], set()
    for index, chunk in enumerate(chunks):
        prop = source_prop(chunk)
        if prop is None:
            out.append(chunk.raw)
            continue
        prefix, values = prop
        new_values = [MARKER.sub(lambda m: replacer.lookup(m) or m.group(0), v) for v in values]
        if new_values == values:
            out.append(chunk.raw)
            continue
        blob = prefix + b"".join(struct.pack("<I", len(v)) + v for v in new_values)
        # Written uncompressed, which is how USSI itself writes Source chunks
        out.append(b"PROP" + struct.pack("<III", 0, len(blob), 0) + blob)
        changed.add(index)
    out.append(trailer)
    return b"".join(out), changed


def verify_binary(original: bytes, rebuilt: bytes, changed: set[int]) -> int:
    """Re-parses the output: every chunk must decode, untouched chunks must be identical."""
    _, old_chunks, old_trailer = parse_binary(original)
    header, new_chunks, new_trailer = parse_binary(rebuilt)
    if header != original[:32] or new_trailer != old_trailer or len(new_chunks) != len(old_chunks):
        raise RebuildError("verification failed: file structure changed")
    markers = 0
    for index, (old, new) in enumerate(zip(old_chunks, new_chunks)):
        if index not in changed:
            if old.raw != new.raw:
                raise RebuildError(f"verification failed: chunk {index} changed unexpectedly")
            prop = source_prop(new)
            if prop:
                markers += sum(len(MARKER.findall(v)) for v in prop[1])
            continue
        old_prop, new_prop = source_prop(old), source_prop(new)
        if not old_prop or not new_prop or old_prop[0] != new_prop[0] or len(old_prop[1]) != len(new_prop[1]):
            raise RebuildError(f"verification failed: Source chunk {index} is malformed")
        markers += sum(len(MARKER.findall(v)) for v in new_prop[1])
    return markers


# ---------------------------------------------------------------- XML (.rbxlx / .rbxmx)

XML_INVALID = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")
# USSI and Studio write ProtectedString; rbx-dom tools (Rojo, Lune) write string
SOURCE_PROPERTY = re.compile(rb'(<(ProtectedString|string) name="Source">)(.*?)(</\2>)', re.DOTALL)


def xml_text(source: bytes, in_cdata: bool) -> bytes:
    # Invalid UTF-8 and characters XML can't hold become Lua escapes (they can only
    # legally appear inside Lua string literals, where the escape means the same byte)
    text = source.decode("utf-8", "backslashreplace")
    text = XML_INVALID.sub(lambda m: "\\%03d" % ord(m.group(0)) if ord(m.group(0)) < 256 else "", text)
    if in_cdata:
        text = text.replace("]]>", "]]]]><![CDATA[>")
    else:
        text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return text.encode("utf-8")


def check_xml(data: bytes) -> None:
    if re.search(rb"<!DOCTYPE|<!ENTITY", data[:1 << 20]):
        raise RebuildError("XML file contains a DOCTYPE/ENTITY declaration, which USSI never writes")


def xml_source_texts(data: bytes):
    for prop in SOURCE_PROPERTY.finditer(data):
        yield prop.group(3)


def rebuild_xml(data: bytes, replacer: Replacer) -> bytes:
    check_xml(data)

    def fill_property(prop: re.Match) -> bytes:
        body = prop.group(3)

        def substitute(match: re.Match) -> bytes:
            source = replacer.lookup(match)
            if source is None:
                return match.group(0)
            before = body.rfind(b"<![CDATA[", 0, match.start())
            in_cdata = before != -1 and body.rfind(b"]]>", before, match.start()) == -1
            return xml_text(source, in_cdata)

        return prop.group(1) + MARKER.sub(substitute, body) + prop.group(4)

    return SOURCE_PROPERTY.sub(fill_property, data)


def verify_xml(rebuilt: bytes) -> int:
    parser = expat.ParserCreate()
    try:
        parser.Parse(rebuilt, True)
    except expat.ExpatError as e:
        raise RebuildError(f"verification failed: output is not well-formed XML ({e})") from e
    return len(MARKER.findall(rebuilt))


# ---------------------------------------------------------------- main


BYTECODE_TAG = ".bytecode"  # USSI names DumpBytecode saves "<place>.bytecode.rbxlx"


def strip_bytecode_tag(stem: str) -> str:
    return stem[: -len(BYTECODE_TAG)] if stem.lower().endswith(BYTECODE_TAG) else stem


def default_output(place_path: Path, force: bool) -> Path:
    """"<place>.bytecode.rbxlx" becomes "<place>.rbxlx"; other names get " decompiled".

    Never overwrites a previous result unless forced: picks the next free "(n)" name instead.
    """
    stem, ext = place_path.stem, place_path.suffix
    base = strip_bytecode_tag(stem)
    if base == stem:
        base = f"{stem} decompiled"  # the plain name would be the input itself
    out_path, counter = place_path.with_name(base + ext), 1
    while out_path.exists() and not force:
        counter += 1
        out_path = place_path.with_name(f"{base} ({counter}){ext}")
    return out_path


def find_decompiler(given: str | None) -> Path:
    candidates = [given] if given else [
        str(Path(__file__).with_name("luau-lifter.exe")),
        str(Path(__file__).with_name("luau-lifter")),
        shutil.which("luau-lifter"),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return Path(candidate).resolve()
    if given:
        raise RebuildError(f"decompiler not found: {given}")
    raise RebuildError("no decompiler found: pass --decompiler path/to/luau-lifter.exe")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "input", type=Path, help="the place saved with DumpBytecode (or the <place>.bytecode.zip beside it)"
    )
    parser.add_argument("--place", type=Path, help="the saved place, when it can't be found from the zip")
    parser.add_argument("--out", type=Path, help='output path (default: "<place>.bytecode.rbxlx" -> "<place>.rbxlx")')
    parser.add_argument("--decompiler", help="decompiler executable (default: luau-lifter next to this script or on PATH)")
    parser.add_argument(
        "--decompiler-args",
        default="{file} -e",
        help='arguments; {file} is the bytecode path, {name} the script path (default: "{file} -e")',
    )
    parser.add_argument("--unencoded", action="store_true", help="bytecode is plain Luau, not Roblox client (drops -e)")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 4, help="decompiler processes run at once")
    parser.add_argument("--timeout", type=float, default=120, help="seconds allowed per script")
    parser.add_argument("--force", action="store_true", help="overwrite the output if it exists")
    args = parser.parse_args()

    try:
        try:
            given = args.input.resolve(strict=True)
        except OSError as e:
            raise RebuildError(f"file not found: {args.input}") from e

        # USSI falls back to ".bytecode.zip.txt" on executors that refuse to write .zip files
        if given.name.lower().endswith((".zip", ".zip.txt")):
            zip_path = given
        else:
            if args.place is None:
                args.place = given
            # A zip beside the place is optional: the default embeds the bytecode in the place
            stem = strip_bytecode_tag(given.stem)
            candidates = [given.with_name(f"{stem}.bytecode.zip{ext}") for ext in ("", ".txt")]
            zip_path = next((c for c in candidates if c.is_file()), None)

        manifest, files = read_dump(zip_path) if zip_path else ({}, {})
        if zip_path:
            print(f"{len(files)} bytecode files in {zip_path.name}", file=sys.stderr)

        place_path = args.place
        if place_path is None:
            name = manifest.get("PlaceFile")
            if not isinstance(name, str) or not name or Path(name).name != name:
                raise RebuildError("the manifest doesn't name the place file: pass --place")
            place_path = zip_path.with_name(name)
        place_path = place_path.resolve()
        if not place_path.is_file():
            raise RebuildError(f"place file not found: {place_path} (pass --place)")

        if args.out:
            out_path = args.out.resolve()
        else:
            out_path = default_output(place_path, args.force)
        if out_path in (place_path, zip_path):
            raise RebuildError("the output would overwrite an input file")
        if out_path.exists() and not args.force:
            raise RebuildError(f"{out_path} already exists (pass --force to overwrite)")

        data = place_path.read_bytes()
        if data[:14] == RBXL_MAGIC:
            is_binary = True
            embedded = collect_embedded(binary_source_texts(data))
        elif data.lstrip()[:1] == b"<":
            is_binary = False
            check_xml(data)
            embedded = collect_embedded(xml_source_texts(data))
        else:
            raise RebuildError(f"{place_path.name} is neither a binary nor an XML Roblox file")
        if embedded:
            print(f"{len(embedded)} unique scripts embedded in {place_path.name}", file=sys.stderr)
        files.update(embedded)
        if not files:
            raise RebuildError(
                f"no bytecode found: {place_path.name} has no embedded bytecode and no .bytecode.zip beside it "
                "(was it saved with DumpBytecode = true?)"
            )

        decompiler = find_decompiler(args.decompiler)
        extra = [a.strip('"') for a in shlex.split(args.decompiler_args, posix=os.name != "nt")]
        if args.unencoded:
            extra = [a for a in extra if a != "-e"]
        command = [str(decompiler), *extra]
        print(f"decompiling with {decompiler.name} ({args.jobs} at a time)", file=sys.stderr)

        sources, outcomes = decompile_all(files, command, script_names_by_file(manifest), max(1, args.jobs), args.timeout)
        counts = {outcome: list(outcomes.values()).count(outcome) for outcome in ("partial", "empty", "failed")}
        # Bytecode stays in the output for anything not fully decompiled, so a later run can retry
        keep_marker = {key for key, outcome in outcomes.items() if outcome in ("partial", "failed")}

        replacer = Replacer(sources, keep_marker)
        if is_binary:
            rebuilt, changed = rebuild_binary(data, replacer)
            leftover = verify_binary(data, rebuilt, changed)
        else:
            rebuilt = rebuild_xml(data, replacer)
            leftover = verify_xml(rebuilt)

        if leftover < len(replacer.unresolved):  # decompiled code may itself contain marker text
            raise RebuildError("verification failed: marker count mismatch")

        temp_path = out_path.with_name(out_path.name + ".partial")
        temp_path.write_bytes(rebuilt)
        if temp_path.read_bytes() != rebuilt:
            temp_path.unlink(missing_ok=True)
            raise RebuildError("verification failed: output did not read back identically")
        os.replace(temp_path, out_path)
    except RebuildError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(f"\nwrote {out_path}", file=sys.stderr)
    print(f"  markers replaced:    {replacer.replaced}", file=sys.stderr)
    if counts["partial"]:
        print(f"  partially decompiled: {counts['partial']} (unsupported functions stubbed)", file=sys.stderr)
    if counts["empty"]:
        print(f"  empty scripts:        {counts['empty']} (they do nothing)", file=sys.stderr)
    if counts["failed"]:
        print(f"  failed to decompile:  {counts['failed']} (left as a comment with the reason)", file=sys.stderr)
    if replacer.unresolved:
        print(f"  markers left as-is:  {len(replacer.unresolved)} (bytecode missing or corrupt)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
