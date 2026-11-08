#!/usr/bin/env python3
"""Check a signed IPA: signer CN, entitlements per component, embedded profile, sealed resources."""
import importlib.util
import plistlib
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("signpy", here.parent / "sign.py")
s = importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)

ipa, team = Path(sys.argv[1]), sys.argv[2]
ok = True


def check(cond, msg):
    global ok
    print(("  OK   " if cond else "  FAIL ") + msg)
    ok &= bool(cond)


with tempfile.TemporaryDirectory() as d:
    d = Path(d)
    with zipfile.ZipFile(ipa) as z:
        z.extractall(d)
    # zipfile drops unix perms; restore them from the archive
    with zipfile.ZipFile(ipa) as z:
        for info in z.infolist():
            mode = info.external_attr >> 16
            if mode:
                (d / info.filename).chmod(mode & 0o7777)
    app = next(d.glob("Payload/*.app"))
    for bundle in [app, *app.glob("PlugIns/*.appex"), *app.glob("Frameworks/*.framework")]:
        print(bundle.relative_to(d))
        info = plistlib.loads((bundle / "Info.plist").read_bytes())
        exe = bundle / info["CFBundleExecutable"]
        check(exe.stat().st_mode & 0o111, "executable bit set")
        check((bundle / "_CodeSignature" / "CodeResources").is_file(), "_CodeSignature/CodeResources present")
        cms = subprocess.run(["rcodesign", "extract", "cms-info", str(exe)], capture_output=True, text=True).stdout
        check("iPhone Distribution: Test Corp" in cms, "CMS signed by our certificate")
        cd = subprocess.run(["rcodesign", "extract", "code-directory", str(exe)], capture_output=True, text=True).stdout
        check(f'team_name: Some(\n        "{team}"' in cd or f'team_name: Some("{team}")' in cd, f"code directory team id = {team}")
        check(f'ident: "{info['CFBundleIdentifier']}"' in cd, f"code directory identifier = {info['CFBundleIdentifier']}")
        v = subprocess.run(["rcodesign", "verify", str(exe)], capture_output=True, text=True)
        check(v.returncode == 0, "rcodesign verify")
        ents = s.macho_entitlements(exe)
        if bundle.suffix in (".app", ".appex"):
            check(ents.get("application-identifier") == f"{team}.{info['CFBundleIdentifier']}",
                  f"application-identifier = {ents.get('application-identifier')}")
            check("ZZZZZ99999" not in str(ents), "no old team id in entitlements")
            check("com.apple.developer.associated-domains" not in ents, "entitlement not in profile was dropped")
            check((bundle / "embedded.mobileprovision").is_file(), "embedded.mobileprovision present")
            if bundle == app and len(sys.argv) > 3:
                want = sys.argv[3] == "memory"
                k = "com.apple.developer.kernel.increased-memory-limit"
                check(bool(ents.get(k)) == want, f"{k} {'present' if want else 'absent'} in signature")
            check(b"ZZZZZ99999" not in exe.read_bytes(), "old team id byte-patched out of binary")
        else:
            check(ents == {}, "framework has no entitlements")
    # the main app's seal must cover the nested bundles
    res = plistlib.loads((app / "_CodeSignature" / "CodeResources").read_bytes())
    files2 = res.get("files2", {})
    check(any(k.startswith("PlugIns/Share.appex") for k in files2), "main seal covers PlugIns/Share.appex")
    check(any(k.startswith("Frameworks/Foo.framework") for k in files2), "main seal covers Frameworks/Foo.framework")
    check("resource.txt" in files2, "main seal covers resource.txt")

print("ALL OK" if ok else "SOME CHECKS FAILED")
sys.exit(0 if ok else 1)
