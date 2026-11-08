#!/usr/bin/env python3
"""
SignTools builder script for Linux.

Drop-in replacement for SignTools-CI's macOS-only sign.py. It speaks the exact
same protocol with the SignTools web service (download job tar + unsigned ipa,
upload signed ipa via tus, report /signed or /fail), but replaces every macOS
tool with a cross-platform equivalent:

    codesign            -> rcodesign (apple-codesign, the Rust signer Impactor uses)
    security (keychain) -> cryptography (p12 -> PEM), no keychain needed
    security cms -D     -> openssl cms / raw plist extraction
    plutil              -> python plistlib (reads binary + xml plists)
    codesign -d --ent   -> built-in Mach-O code signature parser
    otool / install_name_tool / insert_dylib -> LIEF
    perl byte patching  -> python bytes.replace

Only signing with a certificate + provisioning profile is supported
(e.g. an enterprise / distribution / development cert). Developer-account
login mode (fastlane) is not implemented.
"""

import copy
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import traceback
import json
import plistlib
import random
import string
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, IO, List, Mapping, NamedTuple, Optional, Set, Tuple, Union

# SECRET_URL is the service's public server_url. SIGNTOOLS_INTERNAL_URL lets the builder reach the
# service directly instead (e.g. http://signtools:8080 inside docker compose): avoids NAT hairpin
# problems and CDN request-size limits (Cloudflare's 100 MB) when moving multi-GB IPAs around.
secret_url = (os.environ.get("SIGNTOOLS_INTERNAL_URL") or os.path.expandvars("$SECRET_URL")).strip().rstrip("/")
secret_key = os.path.expandvars("$SECRET_KEY")
RCODESIGN = os.environ.get("RCODESIGN", "rcodesign")
# Apple's timestamp server is not needed for iOS apps and is often slow/unreachable.
TIMESTAMP_URL = os.environ.get("SIGN_TIMESTAMP_URL", "none")
StrPath = Union[str, Path]


# ---------------------------------------------------------------------------
# generic helpers
# ---------------------------------------------------------------------------


def safe_glob(input: Path, pattern: str):
    for f in sorted(input.glob(pattern)):
        if not f.name.startswith("._") and f.name not in [".DS_Store", ".AppleDouble", "__MACOSX"]:
            yield f


def decode_clean(b: Optional[bytes]):
    return "" if not b else b.decode("utf-8", errors="replace").strip()


def run_process(
    *cmd: str,
    capture: bool = True,
    check: bool = True,
    env: Optional[Mapping[str, str]] = None,
    cwd: Optional[str] = None,
    timeout: Optional[float] = None,
    input: Optional[bytes] = None,
):
    try:
        result = subprocess.run(
            cmd, capture_output=capture, check=check, env=env, cwd=cwd, timeout=timeout, input=input
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        raise Exception(
            {
                "cmd": " ".join(map(str, cmd)),
                "stdout": decode_clean(e.stdout),
                "stderr": decode_clean(e.stderr),
            }
        ) from e
    return result


def rand_str(len: int, seed: Any = None):
    old_state: object = None
    if seed is not None:
        old_state = random.getstate()
        random.seed(seed)
    result = "".join(random.choices(string.ascii_lowercase + string.digits, k=len))
    if old_state is not None:
        random.setstate(old_state)
    return result


def read_file(file_path: StrPath):
    with open(file_path) as f:
        return f.read()


def extract_zip(archive: Path, dest_dir: Path):
    return run_process("unzip", "-qq", "-o", str(archive), "-d", str(dest_dir))


def archive_zip(content_dir: Path, dest_file: Path):
    # -y keeps symlinks (frameworks may contain them)
    return run_process("zip", "-qry", str(dest_file.resolve()), ".", cwd=str(content_dir))


FileState = Tuple[int, int, int]  # size, mtime_ns, inode


def snapshot_tree(root: Path) -> Dict[str, FileState]:
    """Relative path -> state of every file, symlink and directory (dirs end with '/')."""
    result: Dict[str, FileState] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        for d in dirnames:
            p = os.path.join(dirpath, d)
            rel = os.path.normpath(os.path.join(rel_dir, d))
            if os.path.islink(p):
                st = os.lstat(p)
                result[rel] = (st.st_size, st.st_mtime_ns, st.st_ino)
            else:
                result[rel + "/"] = (0, 0, 0)
        for f in filenames:
            st = os.lstat(os.path.join(dirpath, f))
            result[os.path.normpath(os.path.join(rel_dir, f))] = (st.st_size, st.st_mtime_ns, st.st_ino)
    return result


def repack_incremental(original: Path, content_dir: Path, before: Dict[str, FileState], dest_file: Path) -> bool:
    """
    Turn the original IPA into the signed one by replacing only what signing touched
    (executables, Info.plists, _CodeSignature, embedded.mobileprovision ...). Untouched entries,
    e.g. a 10+ GB game image, are copied as-is in their compressed form instead of being
    deflated again. Returns False if the archive can't be updated this way (caller falls back
    to a full re-zip). The original archive is left untouched.
    """
    import zipfile

    after = snapshot_tree(content_dir)
    changed = sorted(p for p, st in after.items() if before.get(p) != st)
    deleted = sorted(p for p in before if p not in after)
    print(f"Incremental repack: {len(changed)} changed/new, {len(deleted)} removed, {len(after) - len(changed)} untouched")

    try:
        with zipfile.ZipFile(original) as z:
            names = z.namelist()
    except zipfile.BadZipFile as e:
        print("Original archive unreadable for incremental repack:", e)
        return False
    name_set = set(names)
    if len(name_set) != len(names):
        print("Original archive has duplicate entries, not updating in place")
        return False
    # every changed file that already existed must be addressable by the very same name in the archive
    for p in changed:
        if p in before and not p.endswith("/") and p not in name_set:
            print(f"Archive entry name mismatch for {p}, not updating in place")
            return False

    # free the disk space of the untouched extracted files right away: for a 10+ GB IPA this keeps
    # the peak usage at ~2x the IPA size instead of ~3x
    for p in after:
        if p not in changed and not p.endswith("/"):
            fp = content_dir / p
            if fp.is_file() and not fp.is_symlink():
                fp.unlink()

    # `zip -O` reads the original and writes a new archive: the original is never modified, so it
    # can be the service's own copy of the unsigned app (local transfer mode)
    zip_env = dict(os.environ, ZIPOPT="")
    src = original.resolve()
    dest = dest_file.resolve()
    dest.unlink(missing_ok=True)
    if not src.suffix:
        # Info-ZIP appends ".zip" to archive names without an extension (the service stores the
        # unsigned app as ".../unsigned"), so give it a name with one
        link = dest.parent / "source-archive.ipa"
        link.unlink(missing_ok=True)
        link.symlink_to(src)
        src = link
    if deleted:
        targets = [p for p in deleted if p in name_set]
        # whole removed directories: also drop everything below them
        dirs = [p for p in deleted if p.endswith("/")]
        targets += [n for n in names if any(n.startswith(d) for d in dirs) and n not in targets]
        if targets:
            r = run_process(
                "zip", "-q", "-nw", "-O", str(dest), str(src), "-d", "-@",
                input="\n".join(targets).encode(), check=False, env=zip_env,
            )
            if r.returncode not in (0, 12):  # 12 = nothing matched
                raise Exception({"zip -d failed": r.returncode, "stderr": decode_clean(r.stderr)})
            if dest.exists():
                src = dest  # continue from the trimmed copy
    if changed:
        cmd = ["zip", "-q", "-y", "-nw"] + (["-O", str(dest)] if src != dest else []) + [str(src), "-@"]
        r = run_process(
            *cmd,
            input="\n".join(p.rstrip("/") for p in changed).encode(),
            cwd=str(content_dir), check=False, env=zip_env,
        )
        if r.returncode != 0:
            raise Exception({"zip update failed": r.returncode, "stderr": decode_clean(r.stderr)})
    if not dest.exists():  # nothing changed at all (not really possible after signing)
        shutil.copyfile(src, dest)

    with zipfile.ZipFile(dest_file) as z:
        final = z.namelist()
    if len(set(final)) != len(final):
        raise Exception("incremental repack produced duplicate entries")
    return True


def extract_tar(archive: Path, dest_dir: Path):
    return run_process("tar", "-x", "-f", str(archive), "-C", str(dest_dir))


class PhaseTimer:
    def __init__(self):
        import time

        self._time = time.monotonic
        self._last = self._time()

    def done(self, phase: str):
        now = self._time()
        print(f"[time] {phase}: {now - self._last:.1f}s")
        self._last = now


def print_object(obj: Any):
    print(json.dumps(obj, indent=4, sort_keys=True, default=str))


def plist_load(plist: Path) -> Any:
    with plist.open("rb") as f:
        return plistlib.load(f)


def plist_loads(data: Union[str, bytes]) -> Any:
    if isinstance(data, str):
        data = data.encode()
    return plistlib.loads(data)


def plist_dump(data: Any, f: IO[bytes]):
    return plistlib.dump(data, f)


# ---------------------------------------------------------------------------
# networking (re-uses SignTools-CI node-utils for multi-connection dl / tus upload)
# ---------------------------------------------------------------------------


def network_init():
    if Path("node-utils/node_modules").is_dir():
        return
    return run_process("npm", "install", "--no-audit", "--no-fund", cwd="node-utils")


def node_upload(file: Path, endpoint: str, capture: bool = True):
    return run_process("node", "node-utils/upload.js", str(file), endpoint, secret_key, capture=capture)


def node_download(download_url: str, output_file: Path, capture: bool = True):
    return run_process(
        "node", "node-utils/download.js", download_url, secret_key, str(output_file), capture=capture
    )


def curl_download(download_url: str, output_file: Path):
    """
    Single-stream download with resume + retries. Used instead of node-utils/download.js (easydl),
    which writes N part files and then merges them: for a 10+ GB IPA that needs twice the disk
    space and an extra full copy.
    """
    return run_process(
        "curl", "-fSL", "--retry", "10", "--retry-all-errors", "--retry-delay", "3",
        "-C", "-", "-H", f"Authorization: Bearer {secret_key}",
        "-o", str(output_file), download_url,
        capture=False,
    )


def curl_with_auth(
    url: str,
    form_data: List[Tuple[str, str]] = [],
    output: Optional[Path] = None,
    check: bool = True,
    capture: bool = True,
):
    args = [item for x in form_data for item in ["-F", f"{x[0]}={x[1]}"]]
    if output:
        args.extend(["-o", str(output)])
    return run_process(
        "curl",
        *["-S", "-s", "-f", "-L", "-H"],
        f"Authorization: Bearer {secret_key}",
        *args,
        url,
        check=check,
        capture=capture,
    )


# ---------------------------------------------------------------------------
# certificate handling (replaces the macOS keychain)
# ---------------------------------------------------------------------------


class Identity(NamedTuple):
    common_name: str
    not_after: datetime
    pem_file: Path


def load_p12(cert: Path, cert_pass: str, out_dir: Path) -> Identity:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID

    data = cert.read_bytes()
    password = cert_pass.encode() if cert_pass else None
    try:
        key, certificate, _ = pkcs12.load_key_and_certificates(data, password)
    except Exception as e:
        # very old exports may use algorithms only the openssl "legacy" provider knows
        print("cryptography failed to read p12, retrying with openssl -legacy:", e)
        pem = run_process(
            "openssl", "pkcs12", "-legacy", "-nodes", "-in", str(cert), "-passin", f"pass:{cert_pass}"
        ).stdout
        key = serialization.load_pem_private_key(
            re.search(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----.+?-----END [A-Z ]*PRIVATE KEY-----", pem, re.S).group(0),
            None,
        )
        from cryptography import x509

        certificate = x509.load_pem_x509_certificate(
            re.search(rb"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", pem, re.S).group(0)
        )

    if key is None or certificate is None:
        raise Exception("No valid code signing certificate found, aborting.")

    cns = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    common_name = cns[0].value if cns else ""
    try:
        not_after = certificate.not_valid_after_utc
    except AttributeError:  # cryptography < 42
        not_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)

    # rcodesign: the first certificate is paired with the key, so only put the leaf here.
    # The Apple WWDR chain is added automatically by rcodesign for Apple-issued certs.
    pem_file = out_dir / "identity.pem"
    with pem_file.open("wb") as f:
        f.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    os.chmod(pem_file, 0o600)
    return Identity(str(common_name), not_after, pem_file)


def check_expiry(identity: Identity):
    if identity.not_after < datetime.now(timezone.utc):
        raise Exception(
            f"Code signing certificate '{identity.common_name}' expired on {identity.not_after}, aborting."
        )


# ---------------------------------------------------------------------------
# provisioning profile (replaces `security cms -D`)
# ---------------------------------------------------------------------------


def dump_prov(prov_file: Path) -> Dict[Any, Any]:
    result = run_process(
        "openssl", "cms", "-verify", "-noverify", "-inform", "DER", "-in", str(prov_file), check=False
    )
    if result.returncode == 0 and b"<plist" in result.stdout:
        return plist_loads(result.stdout)
    # fallback: the payload is an embedded, unencrypted xml plist
    raw = prov_file.read_bytes()
    m = re.search(rb"<\?xml.+?</plist>", raw, re.S)
    if not m:
        raise Exception(f"Failed to decode provisioning profile {prov_file}")
    return plist_loads(m.group(0))


def dump_prov_entitlements(prov_file: Path) -> Dict[Any, Any]:
    return dump_prov(prov_file)["Entitlements"]


# ---------------------------------------------------------------------------
# Mach-O helpers (replace `file`, `codesign -d --entitlements`)
# ---------------------------------------------------------------------------

# Entitlements big games (e.g. nxnative ports) rely on. They are "restricted": iOS only honours them
# when the provisioning profile grants them, so they can't simply be added at signing time.
MEMORY_ENTITLEMENTS = [
    "com.apple.developer.kernel.increased-memory-limit",
    "com.apple.developer.kernel.extended-virtual-addressing",
    "com.apple.developer.kernel.increased-debugging-memory-limit",
]

MH_MAGICS = {0xFEEDFACE, 0xFEEDFACF, 0xCEFAEDFE, 0xCFFAEDFE}
FAT_MAGICS = {0xCAFEBABE, 0xCAFEBABF}
LC_CODE_SIGNATURE = 0x1D
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171


def is_macho(file: Path) -> bool:
    if not file.is_file() or file.is_symlink():
        return False
    try:
        with file.open("rb") as f:
            head = f.read(8)
    except OSError:
        return False
    if len(head) < 8:
        return False
    le = struct.unpack("<I", head[:4])[0]
    be = struct.unpack(">I", head[:4])[0]
    if le in MH_MAGICS or be in MH_MAGICS:
        return True
    if be in FAT_MAGICS:
        # java class files share 0xCAFEBABE; they have a large "version" where nfat_arch would be
        nfat = struct.unpack(">I", head[4:8])[0]
        return 0 < nfat < 32
    return False


def macho_slices(data: bytes) -> List[Tuple[int, int]]:
    be = struct.unpack(">I", data[:4])[0]
    if be in FAT_MAGICS:
        nfat = struct.unpack(">I", data[4:8])[0]
        is64 = be == 0xCAFEBABF
        out = []
        off = 8
        for _ in range(nfat):
            if is64:
                _, _, offset, size, _, _ = struct.unpack(">iiQQII", data[off : off + 32])
                off += 32
            else:
                _, _, offset, size, _ = struct.unpack(">iiIII", data[off : off + 20])
                off += 20
            out.append((offset, size))
        return out
    return [(0, len(data))]


def macho_entitlements(file: Path) -> Dict[Any, Any]:
    """Read the embedded entitlements xml of the first slice of a Mach-O binary."""
    data = file.read_bytes()
    for offset, size in macho_slices(data):
        sl = data[offset : offset + size]
        magic = struct.unpack("<I", sl[:4])[0]
        if magic in (0xFEEDFACE, 0xFEEDFACF):
            endian = "<"
        elif magic in (0xCEFAEDFE, 0xCFFAEDFE):
            endian = ">"
        else:
            continue
        is64 = magic in (0xFEEDFACF, 0xCFFAEDFE)
        ncmds = struct.unpack(endian + "I", sl[16:20])[0]
        lc_off = 32 if is64 else 28
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack(endian + "II", sl[lc_off : lc_off + 8])
            if cmd == LC_CODE_SIGNATURE:
                dataoff, datasize = struct.unpack(endian + "II", sl[lc_off + 8 : lc_off + 16])
                blob = sl[dataoff : dataoff + datasize]
                sb_magic, _, count = struct.unpack(">III", blob[:12])
                if sb_magic != CSMAGIC_EMBEDDED_SIGNATURE:
                    return {}
                for i in range(count):
                    _, boff = struct.unpack(">II", blob[12 + i * 8 : 20 + i * 8])
                    bmagic, blen = struct.unpack(">II", blob[boff : boff + 8])
                    if bmagic == CSMAGIC_EMBEDDED_ENTITLEMENTS:
                        return plist_loads(blob[boff + 8 : boff + blen])
                return {}
            lc_off += cmdsize
        return {}
    return {}


def get_binary_map(dir: Path):
    return {file.name: file for file in safe_glob(dir, "**/*") if is_macho(file)}


def binary_replace(old: str, new: str, f: Path):
    if not f.exists() or not f.is_file():
        raise Exception(f, "does not exist or is a directory")
    data = f.read_bytes()
    patched = data.replace(old.encode(), new.encode())
    if patched != data:
        f.write_bytes(patched)


# ---------------------------------------------------------------------------
# tweak injection (replaces otool / install_name_tool / insert_dylib) via LIEF
# ---------------------------------------------------------------------------


def _lief_parse(binary: Path):
    import lief

    try:
        lief.logging.disable()
    except Exception:
        pass
    fat = lief.MachO.parse(str(binary))
    if fat is None:
        raise Exception(f"LIEF failed to parse {binary}")
    return fat


def _lief_slices(fat):
    return [fat.at(i) for i in range(fat.size)]


def get_otool_imports(binary: Path) -> List[str]:
    fat = _lief_parse(binary)
    return [lib.name for lib in _lief_slices(fat)[0].libraries]


def install_name_change(binary: Path, old: Path, new: Path, capture: bool = True):
    fat = _lief_parse(binary)
    changed = False
    for b in _lief_slices(fat):
        for lib in b.libraries:
            if lib.name == str(old):
                lib.name = str(new)
                changed = True
    if changed:
        fat.write(str(binary))


def insert_dylib(binary: Path, path: Path, capture: bool = True):
    fat = _lief_parse(binary)
    for b in _lief_slices(fat):
        if any(lib.name == str(path) for lib in b.libraries):
            continue
        b.add_library(str(path))
    fat.write(str(binary))
    os.chmod(binary, 0o755)


def extract_deb(app_bin_name: str, app_bundle_id: str, archive: Path, dest_dir: Path):
    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        run_process("ar", "x", str(archive.resolve()), cwd=str(temp_dir))
        with tempfile.TemporaryDirectory() as temp_dir2_str:
            temp_dir2 = Path(temp_dir2_str)
            extract_tar(next(safe_glob(temp_dir, "data.tar*")), temp_dir2)

            for file in safe_glob(temp_dir2, "**/*"):
                if file.is_symlink():
                    target = Path(os.readlink(file))
                    if target.is_absolute():
                        target = temp_dir2.joinpath(str(target)[1:])
                        os.unlink(file)
                        if target.is_dir():
                            shutil.copytree(target, file)
                        elif target.exists():
                            shutil.copy2(target, file)

            rootless_dir = temp_dir2 / "var" / "jb"
            if rootless_dir.is_dir():
                temp_dir2 = rootless_dir

            for glob in [
                "Library/Application Support/*/*.bundle",
                "Library/Application Support/*",
                "Library/Frameworks/*.framework",
                "usr/lib/*.framework",
            ]:
                for file in safe_glob(temp_dir2, glob):
                    if file.is_dir() and next(safe_glob(file, "*"), None) is None:
                        continue
                    move_merge_replace(file, dest_dir)
            for glob in [
                "Library/MobileSubstrate/DynamicLibraries/*.dylib",
                "usr/lib/*.dylib",
            ]:
                for file in safe_glob(temp_dir2, glob):
                    if not file.is_file():
                        continue
                    file_plist = file.parent.joinpath(file.stem + ".plist")
                    if file_plist.exists():
                        info = plist_load(file_plist)
                        if "Filter" in info:
                            ok = False
                            if "Bundles" in info["Filter"] and app_bundle_id in info["Filter"]["Bundles"]:
                                ok = True
                            elif "Executables" in info["Filter"] and app_bin_name in info["Filter"]["Executables"]:
                                ok = True
                            if not ok:
                                continue
                    move_merge_replace(file, dest_dir)


def move_merge_replace(src: Path, dest_dir: Path):
    dest = dest_dir.joinpath(src.name)
    if src == dest:
        return
    dest_dir.mkdir(exist_ok=True, parents=True)
    if src.is_dir():
        shutil.copytree(src, dest, dirs_exist_ok=True)
        shutil.rmtree(src)
    else:
        shutil.copy2(src, dest)
        os.remove(src)


def inject_tweaks(ipa_dir: Path, tweaks_dir: Path):
    main_app = get_main_app_path(ipa_dir)
    main_info_plist = get_info_plist_path(main_app)
    info = plist_load(main_info_plist)
    app_bundle_id = info["CFBundleIdentifier"]
    app_bundle_exe = info["CFBundleExecutable"]
    is_mac_app = main_info_plist.parent.name == "Contents"

    if is_mac_app:
        base_dir = main_info_plist.parent
        app_bin = base_dir.joinpath("MacOS", app_bundle_exe)
        base_load_path = Path("@executable_path").joinpath("..")
    else:
        base_dir = main_app
        app_bin = base_dir.joinpath(app_bundle_exe)
        base_load_path = Path("@executable_path")

    with tempfile.TemporaryDirectory() as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        for tweak in safe_glob(tweaks_dir, "*"):
            print("Processing", tweak.name)
            if tweak.suffix == ".zip":
                extract_zip(tweak, temp_dir)
            elif tweak.suffix == ".tar":
                extract_tar(tweak, temp_dir)
            elif tweak.suffix == ".deb":
                extract_deb(app_bin.name, app_bundle_id, tweak, temp_dir)
            else:
                move_merge_replace(tweak, temp_dir)

        move_map = {"Frameworks": ["*.framework", "*.dylib"], "PlugIns": ["*.appex"]}
        for dest_dir, globs in move_map.items():
            for glob in globs:
                for file in safe_glob(temp_dir, glob):
                    move_merge_replace(file, temp_dir.joinpath(dest_dir))

        support_libs = {
            Path("./libsubstrate"): ["libsubstrate.dylib", "CydiaSubstrate"],
        }
        aliases = {
            "libsubstitute.0.dylib": "libsubstitute.dylib",
            "CydiaSubstrate": "libsubstrate.dylib",
        }

        binary_map = get_binary_map(temp_dir)

        for binary_path in binary_map.values():
            binary_rel = binary_path.relative_to(temp_dir)
            if (len(binary_rel.parts) == 2 and binary_rel.parent.name == "Frameworks") or (
                len(binary_rel.parts) == 3
                and binary_rel.parent.suffix == ".framework"
                and binary_rel.parent.parent.name == "Frameworks"
            ):
                binary_fixed = base_load_path.joinpath(binary_rel)
                print("Injecting", binary_path, binary_fixed)
                insert_dylib(app_bin, binary_fixed, False)

        for binary_path in binary_map.values():
            for link in get_otool_imports(binary_path):
                link_path = Path(link)
                for lib_dir, lib_names in support_libs.items():
                    if link_path.name not in lib_names:
                        continue
                    print("Detected", lib_dir.name)
                    for lib_src in safe_glob(lib_dir, "*"):
                        lib_dest = temp_dir.joinpath("Frameworks").joinpath(lib_src.name)
                        if not lib_dest.exists():
                            print(f"Installing {lib_src.name} to {lib_dest}")
                            lib_dest.parent.mkdir(exist_ok=True, parents=True)
                            shutil.copy2(lib_src, lib_dest)

        binary_map = get_binary_map(temp_dir)

        for binary_path in binary_map.values():
            for link in get_otool_imports(binary_path):
                link_path = Path(link)
                link_name = aliases[link_path.name] if link_path.name in aliases else link_path.name
                if link_name in binary_map:
                    link_fixed = base_load_path.joinpath(binary_map[link_name].relative_to(temp_dir))
                    print("Re-linking", binary_path, link_path, link_fixed)
                    install_name_change(binary_path, link_path, link_fixed, False)

        for file in safe_glob(temp_dir, "*"):
            move_merge_replace(file, base_dir)


# ---------------------------------------------------------------------------
# signer
# ---------------------------------------------------------------------------


class SignOpts(NamedTuple):
    app_dir: Path
    identity: Identity
    team_id: str
    prov_file: Path
    bundle_id: Optional[str]
    bundle_name: Optional[str]
    patch_debug: bool
    patch_all_devices: bool
    patch_mac: bool
    patch_file_sharing: bool
    encode_ids: bool
    patch_ids: bool
    force_original_id: bool


class ComponentData(NamedTuple):
    old_bundle_id: str
    bundle_id: str
    entitlements: Dict[Any, Any]
    info_plist: Path


def get_info_plist_path(app_dir: Path):
    return min(list(safe_glob(app_dir, "**/Info.plist")), key=lambda p: len(str(p)))


def get_main_app_path(app_dir: Path):
    return min(list(safe_glob(app_dir, "**/*.app")), key=lambda p: len(str(p)))


def bundle_main_executable(bundle: Path) -> Optional[Path]:
    plist = bundle / "Info.plist"
    if not plist.exists():
        plist = bundle / "Contents" / "Info.plist"
    if not plist.exists():
        return None
    try:
        exe = plist_load(plist).get("CFBundleExecutable")
    except Exception:
        return None
    if not exe:
        return None
    for cand in [plist.parent / exe, plist.parent / "MacOS" / exe]:
        if cand.is_file():
            return cand
    return None


class Signer:
    opts: SignOpts
    main_app: Path
    main_bundle_id: str
    old_main_bundle_id: str
    mappings: Dict[str, str]
    removed_entitlements: Set[str]
    is_distribution: bool
    components: List[Path]
    is_mac_app: bool

    def gen_id(self, input_id: str):
        if not input_id.strip():
            return input_id
        if not self.opts.encode_ids:
            return input_id
        new_parts = map(lambda x: rand_str(len(x), x + self.opts.team_id), input_id.split("."))
        return ".".join(new_parts)

    def __app_id_key(self):
        return "com.apple.application-identifier" if self.is_mac_app else "application-identifier"

    def __aps_key(self):
        return "com.apple.developer.aps-environment" if self.is_mac_app else "aps-environment"

    def __init__(self, opts: SignOpts):
        self.opts = opts
        self.main_app = main_app = get_main_app_path(opts.app_dir)
        main_info_plist = get_info_plist_path(main_app)
        main_info: Dict[Any, Any] = plist_load(main_info_plist)
        self.old_main_bundle_id = main_info["CFBundleIdentifier"]
        self.is_distribution = "Distribution" in opts.identity.common_name
        self.is_mac_app = main_info_plist.parent.name == "Contents"

        if self.is_distribution and self.is_mac_app:
            raise Exception("Cannot use distribution certificate for macOS apps.")

        self.mappings = {}
        self.removed_entitlements = set()
        self.missing_entitlements = set()

        if opts.bundle_id is None:
            print("Using original bundle id")
            self.main_bundle_id = self.old_main_bundle_id
        elif opts.bundle_id == "":
            print("Using provisioning profile's application id")
            prov_app_id = dump_prov_entitlements(opts.prov_file)[self.__app_id_key()]
            self.main_bundle_id = prov_app_id[prov_app_id.find(".") + 1 :]
            if self.main_bundle_id == "*":
                print("Provisioning profile is wildcard, using original bundle id")
                self.main_bundle_id = self.old_main_bundle_id
        else:
            print("Using custom bundle id")
            self.main_bundle_id = opts.bundle_id

        if opts.bundle_name:
            print(f"Setting CFBundleDisplayName to {opts.bundle_name}")
            main_info["CFBundleDisplayName"] = opts.bundle_name

        if self.opts.patch_all_devices:
            if self.is_mac_app:
                main_info["LSMinimumSystemVersion"] = "10.0"
            else:
                main_info["MinimumOSVersion"] = "3.0"

        with open("bundle_id.txt", "w") as f:
            f.write(self.old_main_bundle_id if opts.force_original_id else self.main_bundle_id)

        with main_info_plist.open("wb") as f:
            plist_dump(main_info, f)

        for watch_name in ["com.apple.WatchPlaceholder", "Watch"]:
            watch_dir = main_app.joinpath(watch_name)
            if watch_dir.exists():
                print(f"Removing {watch_name} directory")
                shutil.rmtree(watch_dir)

        component_exts = ["*.app", "*.appex", "*.framework", "*.dylib", "PlugIns/*.bundle"]
        self.components = [item for e in component_exts for item in safe_glob(main_app, "**/" + e)][::-1]
        self.components.append(main_app)

    def __prepare_primary(self, component: Path) -> ComponentData:
        info_plist = get_info_plist_path(component)
        info: Dict[Any, Any] = plist_load(info_plist)
        old_bundle_id = info["CFBundleIdentifier"]
        bundle_id = f"{self.main_bundle_id}{old_bundle_id[len(self.old_main_bundle_id):]}"
        if not self.opts.force_original_id and old_bundle_id != bundle_id:
            if len(old_bundle_id) != len(bundle_id):
                print(
                    f"WARNING: Component's bundle id '{bundle_id}' is different length from the original bundle id '{old_bundle_id}'.",
                    "The signed app may crash!",
                )
            else:
                self.mappings[old_bundle_id] = bundle_id

        old_entitlements: Dict[Any, Any] = {}
        exe = bundle_main_executable(component)
        if exe is not None:
            try:
                old_entitlements = macho_entitlements(exe)
            except Exception as e:
                print("Failed to dump entitlements, using empty:", e)
        print("Original entitlements:")
        print_object(old_entitlements)

        old_team_id: Optional[str] = old_entitlements.get("com.apple.developer.team-identifier", None)
        if old_team_id and old_team_id != self.opts.team_id:
            if len(old_team_id) != len(self.opts.team_id):
                print("WARNING: Team ID length mismatch:", old_team_id, self.opts.team_id)
            else:
                self.mappings[old_team_id] = self.opts.team_id

        old_app_id_prefix = str(old_entitlements.get(self.__app_id_key(), "")).split(".")[0] or None
        if old_app_id_prefix and old_app_id_prefix != self.opts.team_id:
            if len(old_app_id_prefix) != len(self.opts.team_id):
                print("WARNING: App ID Prefix length mismatch:", old_app_id_prefix, self.opts.team_id)
            else:
                self.mappings[old_app_id_prefix] = self.opts.team_id

        entitlements = dump_prov_entitlements(self.opts.prov_file)

        prov_app_id = entitlements[self.__app_id_key()]
        component_app_id = f"{self.opts.team_id}.{bundle_id}"
        wildcard_app_id = f"{self.opts.team_id}.*"

        if prov_app_id == wildcard_app_id:
            entitlements[self.__app_id_key()] = component_app_id
        elif prov_app_id != component_app_id:
            print(
                f"WARNING: Provisioning profile's app id '{prov_app_id}' does not match component's app id '{component_app_id}'.",
                "Using provisioning profile's app id - the component will run, but some functions such as file importing will not work!",
                sep="\n",
            )

        keychain: Optional[List[str]] = entitlements.get("keychain-access-groups", None)
        old_keychain: Optional[List[str]] = old_entitlements.get("keychain-access-groups", None)
        if old_keychain is None:
            entitlements.pop("keychain-access-groups", None)
        elif keychain and any(item == wildcard_app_id for item in keychain):
            keychain.clear()
            for item in old_keychain:
                keychain.append(f"{self.opts.team_id}.{item[item.index('.')+1:]}")

        for key in MEMORY_ENTITLEMENTS:
            wanted = bool(old_entitlements.get(key))
            granted = bool(entitlements.get(key))
            if wanted and granted:
                print(f"{key}: requested by the app and granted by the profile -> signed in")
            elif wanted:
                self.missing_entitlements.add(key)
                print(
                    "#" * 78,
                    f"WARNING: the app requests {key},",
                    "but the provisioning profile does not grant it, so the signed app will NOT get it",
                    "(iOS will kill memory-hungry games). Enable the capability on an *explicit* App ID",
                    "in the Apple developer portal (wildcard App IDs can't carry it), regenerate the",
                    "provisioning profile, and sign with the profile's bundle id.",
                    "#" * 78,
                    sep="\n",
                )
            elif granted:
                print(f"{key}: granted by the profile -> signed in")

        # wildcard values are valid in a profile but not in a binary signature
        for k in list(entitlements.keys()):
            v = entitlements[k]
            if v == "*" or (isinstance(v, list) and any(x == "*" for x in v)):
                print(f"Dropping wildcard entitlement {k}={v}")
                self.removed_entitlements.add(k)
                entitlements.pop(k)

        return ComponentData(old_bundle_id, bundle_id, entitlements, info_plist)

    def __patch_primary(self, data: ComponentData, tmpdir: Path, index: int) -> Path:
        info = plist_load(data.info_plist)

        if self.opts.force_original_id:
            print("Keeping original CFBundleIdentifier")
            info["CFBundleIdentifier"] = data.old_bundle_id
        else:
            print(f"Setting CFBundleIdentifier to {data.bundle_id}")
            info["CFBundleIdentifier"] = data.bundle_id

        if self.opts.patch_debug:
            data.entitlements["get-task-allow"] = True
            print("Enabled app debugging")
        else:
            data.entitlements.pop("get-task-allow", False)
            print("Disabled app debugging")

        if not self.is_mac_app:
            if self.opts.patch_all_devices:
                print("Force enabling support for all devices")
                info.pop("UISupportedDevices", False)
                info["UIDeviceFamily"] = [1, 2, 3, 4]

            if self.opts.patch_mac:
                info.pop("UIRequiresFullScreen", False)
                for device in ["ipad", "iphone", "ipod"]:
                    info.pop("UISupportedInterfaceOrientations~" + device, False)
                info["UISupportedInterfaceOrientations"] = [
                    "UIInterfaceOrientationPortrait",
                    "UIInterfaceOrientationPortraitUpsideDown",
                    "UIInterfaceOrientationLandscapeLeft",
                    "UIInterfaceOrientationLandscapeRight",
                ]

            if self.opts.patch_file_sharing:
                print("Force enabling file sharing")
                info["UIFileSharingEnabled"] = True
                info["UISupportsDocumentBrowser"] = True

        with data.info_plist.open("wb") as f:
            plist_dump(info, f)

        print("Signing with entitlements:")
        print_object(data.entitlements)

        embedded_prov = data.info_plist.parent.joinpath(
            "embedded.provisionprofile" if self.is_mac_app else "embedded.mobileprovision"
        )
        shutil.copy2(self.opts.prov_file, embedded_prov)

        ent_file = tmpdir / f"entitlements-{index}.plist"
        with ent_file.open("wb") as f:
            plist_dump(data.entitlements, f)
        return ent_file

    def __fixup_bundles(self):
        """
        Work around the two things Impactor patches into apple-codesign:
          * Mach-O files extracted from zips made on Windows may lack +x
          * rcodesign refuses nested bundles without CFBundleIdentifier
        """
        for f in safe_glob(self.main_app, "**/*"):
            if is_macho(f):
                mode = f.stat().st_mode
                os.chmod(f, mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH | stat.S_IRUSR | stat.S_IWUSR)
        for component in self.components:
            if component.is_file():
                continue
            plist = component / "Info.plist"
            if not plist.exists():
                continue
            try:
                info = plist_load(plist)
            except Exception:
                continue
            if not info.get("CFBundleIdentifier"):
                ident = re.sub(r"[^A-Za-z0-9.-]", "-", f"{self.main_bundle_id}.{component.stem}")
                print(f"Adding missing CFBundleIdentifier {ident} to {plist}")
                info["CFBundleIdentifier"] = ident
                with plist.open("wb") as fp:
                    plist_dump(info, fp)

    def sign(self):
        with tempfile.TemporaryDirectory() as tmpdir_str:
            tmpdir = Path(tmpdir_str)

            job_defs: List[Tuple[Path, Optional[ComponentData]]] = []
            for component in self.components:
                print(f"Preparing component {component}")
                if component.suffix in [".appex", ".app"]:
                    job_defs.append((component, self.__prepare_primary(component)))
                else:
                    job_defs.append((component, None))

            print("ID mappings:")
            print_object(self.mappings)
            assert all(len(k) == len(v) for k, v in self.mappings.items())

            if self.removed_entitlements:
                print("Removed entitlements:")
                print_object(sorted(self.removed_entitlements))

            if self.missing_entitlements and os.environ.get("SIGN_REQUIRE_MEMORY_ENTITLEMENTS"):
                raise Exception(
                    f"Provisioning profile lacks {sorted(self.missing_entitlements)} which the app requests "
                    "(SIGN_REQUIRE_MEMORY_ENTITLEMENTS is set, refusing to sign)"
                )

            # scope -> entitlements file, for a single recursive rcodesign run
            scoped_entitlements: List[Tuple[str, Path]] = []

            for index, (component, data) in enumerate(job_defs):
                print(f"Processing component {component}")

                sc_info = component.joinpath("SC_Info")
                if sc_info.exists():
                    print(
                        "WARNING: Found leftover AppStore metadata - removing it.",
                        "If the app is encrypted, it will fail to launch!",
                        sep="\n",
                    )
                    shutil.rmtree(sc_info)

                if self.opts.patch_ids:
                    patches = dict(
                        sorted(
                            ((k, v) for k, v in self.mappings.items() if len(k) == len(v)),
                            key=lambda x: len(x[0]),
                            reverse=True,
                        )
                    )
                    if len(patches) < 1:
                        print("Nothing to patch")
                    else:
                        targets: List[Path] = []
                        if component.is_file():
                            targets.append(component)
                        else:
                            exe = bundle_main_executable(component)
                            if exe is not None:
                                targets.append(exe)
                        if data is not None:
                            targets.append(data.info_plist)
                        for target in targets:
                            print(f"Patching {len(patches)} patterns in {target}")
                            for old, new in patches.items():
                                binary_replace(old, new, target)

                if data is not None:
                    ent_file = self.__patch_primary(data, tmpdir, index)
                    if component == self.main_app:
                        scope = ""  # unscoped = the bundle being signed
                    else:
                        scope = str(component.relative_to(self.main_app))
                    scoped_entitlements.append((scope, ent_file))
                elif component != self.main_app:
                    # rcodesign keeps a binary's existing entitlements unless told otherwise, while
                    # `codesign -f` drops them for frameworks/dylibs: do the same with an empty set
                    exe = component if component.is_file() else bundle_main_executable(component)
                    if exe is not None and is_macho(exe):
                        try:
                            has_ents = bool(macho_entitlements(exe))
                        except Exception:
                            has_ents = True
                        if has_ents:
                            empty = tmpdir / "entitlements-empty.plist"
                            if not empty.exists():
                                with empty.open("wb") as f:
                                    plist_dump({}, f)
                            print(f"Clearing old entitlements of {component.name}")
                            scoped_entitlements.append((str(component.relative_to(self.main_app)), empty))

            self.__fixup_bundles()

            cmd: List[str] = [
                RCODESIGN,
                "sign",
                "--pem-file",
                str(self.opts.identity.pem_file),
                "--timestamp-url",
                TIMESTAMP_URL,
                # codesign puts the cert's OU (team id) into the code directory; rcodesign only
                # does that automatically for Apple-issued certs, so be explicit
                "--team-name",
                self.opts.team_id,
            ]
            # NOTE: rcodesign 0.29 does not apply the documented "main:" scope to a bundle's main
            # executable (the old entitlements are silently kept), so the main bundle's entitlements
            # are passed unscoped. Path scopes ("PlugIns/X.appex:") work. Paths must not contain ':'.
            for scope, ent_file in scoped_entitlements:
                if ":" in str(ent_file):
                    raise Exception(f"entitlements path must not contain ':' ({ent_file})")
                cmd.extend(["--entitlements-xml-file", f"{scope}:{ent_file}" if scope else str(ent_file)])
            cmd.append(str(self.main_app))

            print("Signing all components with rcodesign...")
            print(" ".join(cmd))
            result = run_process(*cmd, capture=True)
            # rcodesign is chatty on stderr; only keep the useful part in the log
            for line in decode_clean(result.stderr).splitlines():
                if line.startswith(("signing ", "writing ", "sealing ", "processing ")) or "warn" in line.lower():
                    print("  ", line)

            print("Verifying signature...")
            verify = run_process(RCODESIGN, "verify", str(bundle_main_executable(self.main_app)), check=False)
            if verify.returncode != 0:
                print("WARNING: rcodesign verify reported problems:")
                print(decode_clean(verify.stdout), decode_clean(verify.stderr))


# ---------------------------------------------------------------------------
# entrypoint
# ---------------------------------------------------------------------------


def run(work_dir: Path):
    print("Loading certificate...")
    identity = load_p12(Path("cert.p12"), cert_pass, work_dir)
    print(f"Certificate: {identity.common_name} (valid until {identity.not_after})")
    if "Distribution" in identity.common_name:
        print("Using distribution certificate")
        if "-d" in sign_args:
            raise Exception("Debugging cannot be enabled on distribution certificate, use development.")
    elif "Develop" in identity.common_name:
        print("Using development certificate")
    else:
        print(f"WARNING: unrecognized certificate type '{identity.common_name}', continuing anyway")
    check_expiry(identity)

    prov_profile = Path("prov.mobileprovision")
    bundle_name = Path("bundle_name.txt")
    if prov_profile.is_file():
        print("Using provisioning profile")
        prov = dump_prov(prov_profile)
        print(f"Profile: {prov.get('Name')} / team {prov.get('TeamIdentifier')} / expires {prov.get('ExpirationDate')}")
        if prov.get("ProvisionsAllDevices"):
            print("Profile is an enterprise (in-house) profile, installable on any device")
        prov_ents = prov.get("Entitlements", {})
        print(f"Profile app id: {prov_ents.get('application-identifier')}")
        for key in MEMORY_ENTITLEMENTS:
            print(f"Profile grants {key}: {'YES' if prov_ents.get(key) else 'no'}")
    elif Path("account_name.txt").is_file():
        raise Exception(
            "Developer account (login) mode is not supported by the Linux builder. "
            "Upload a provisioning profile with your signing profile instead."
        )
    else:
        raise Exception("Provisioning profile required, found none.")

    unsigned_ipa = unsigned_source
    print(f"IPA size: {unsigned_ipa.stat().st_size / 2**30:.2f} GiB")
    # extract next to the job (the builder's work dir), not to /tmp: that is where the disk space is
    with tempfile.TemporaryDirectory(prefix="extracted-", dir=".") as temp_dir_str:
        temp_dir = Path(temp_dir_str).resolve()
        timer = PhaseTimer()
        print("Extracting app...")
        extract_zip(unsigned_ipa, temp_dir)
        before = snapshot_tree(temp_dir)
        timer.done("extract")

        tweaks_dir = Path("tweaks")
        if tweaks_dir.exists():
            print("Found tweaks, injecting...")
            inject_tweaks(temp_dir, tweaks_dir)

        print("Signing...")
        Signer(
            SignOpts(
                temp_dir,
                identity,
                team_id,
                prov_profile,
                "" if "-n" in sign_args else user_bundle_id,
                read_file(bundle_name) if bundle_name.exists() else None,
                "-d" in sign_args,
                "-a" in sign_args,
                "-m" in sign_args,
                "-s" in sign_args,
                "-e" in sign_args,
                "-p" in sign_args,
                "-o" in sign_args,
            )
        ).sign()
        timer.done("sign")

        print("Packaging signed app...")
        signed_ipa = Path("signed.ipa")
        ok = False
        if not os.environ.get("SIGN_FULL_REZIP"):
            try:
                ok = repack_incremental(unsigned_ipa, temp_dir, before, signed_ipa)
            except Exception as e:
                raise Exception("incremental repack failed (set SIGN_FULL_REZIP=1 to always re-zip)") from e
        if not ok:
            print("Re-zipping the whole app...")
            signed_ipa.unlink(missing_ok=True)
            archive_zip(temp_dir, signed_ipa)
        timer.done("package")
        print(f"Signed IPA size: {signed_ipa.stat().st_size / 2**30:.2f} GiB")
    if unsigned_ipa == Path("unsigned.ipa"):
        unsigned_ipa.unlink(missing_ok=True)  # our downloaded copy, no longer needed

    if os.environ.get("SIGN_LOCAL_ONLY"):
        print("SIGN_LOCAL_ONLY set, skipping upload")
        return

    bundle_id = read_file(Path("bundle_id.txt"))
    if local_transfer:
        # same machine: hand the file over by path, the service moves it into place (no upload)
        print("Handing signed app over by path...")
        r = run_process(
            "curl", "-sS", "-f", "-H", f"Authorization: Bearer {secret_key}",
            "--form-string", f"file_path={signed_ipa.resolve()}",
            "--form-string", f"bundle_id={bundle_id}",
            f"{secret_url}/jobs/{job_id}/signed",
            check=False,
        )
        if r.returncode == 0:
            print("Done! (local transfer)")
            return
        print(
            "Local transfer refused, falling back to upload. Is the builder's work dir inside the",
            "service's local_transfer_dir, at the same path for both?",
            decode_clean(r.stdout), decode_clean(r.stderr),
        )

    print("Uploading...")
    upload_timer = PhaseTimer()
    node_upload(signed_ipa, f"{secret_url}/jobs/{job_id}/tus/", capture=False)
    upload_timer.done("upload")
    file_id = read_file(Path("file_id.txt"))
    curl_with_auth(f"{secret_url}/jobs/{job_id}/signed", [("file_id", file_id), ("bundle_id", bundle_id)])
    print("Done!")


if __name__ == "__main__":
    local_only = bool(os.environ.get("SIGN_LOCAL_ONLY"))
    if not local_only:
        print("Initializing dependencies...")
        network_init()

        print("Downloading job files...")
        job_archive = Path("job.tar")
        node_download(secret_url + "/jobs", job_archive, capture=False)
        extract_tar(job_archive, Path("."))
        os.remove(job_archive)

    cert_pass = read_file("cert_pass.txt")
    sign_args = read_file("args.txt")
    job_id = read_file("id.txt")
    user_bundle_id: Optional[str] = read_file("user_bundle_id.txt")
    if user_bundle_id.strip() == "":
        user_bundle_id = None
    team_id = read_file("team_id.txt").strip()

    # The service has local_transfer_dir set and runs on this machine: it tells us where the unsigned
    # app is on its disk. Use it in place when we can see it (same path, e.g. a shared volume).
    unsigned_source = Path("unsigned.ipa")
    local_transfer = Path("unsigned_path.txt").is_file() and not os.environ.get("SIGN_NO_LOCAL_TRANSFER")
    if local_transfer:
        p = Path(read_file("unsigned_path.txt").strip())
        if p.is_file() and os.access(p, os.R_OK):
            print(f"Using the unsigned app in place: {p}")
            unsigned_source = p
        else:
            print(f"Unsigned app path {p} not visible here, downloading instead")

    if not local_only and unsigned_source == Path("unsigned.ipa"):
        print("Downloading app...")
        dl_timer = PhaseTimer()
        if os.environ.get("SIGN_DOWNLOADER") == "easydl":
            node_download(secret_url + f"/jobs/{job_id}/unsigned", Path("unsigned.ipa"), capture=False)
        else:
            curl_download(secret_url + f"/jobs/{job_id}/unsigned", Path("unsigned.ipa"))
        dl_timer.done("download")

    work_dir = Path(tempfile.mkdtemp(prefix="ios-signer-"))
    failed = False
    try:
        run(work_dir)
    except Exception:
        failed = True
        traceback.print_exc()
    finally:
        print("Cleaning up...")
        shutil.rmtree(work_dir, ignore_errors=True)
        if failed:
            if not local_only:
                curl_with_auth(f"{secret_url}/jobs/{job_id}/fail", check=False)
            sys.exit(1)
