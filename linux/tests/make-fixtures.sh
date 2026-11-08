#!/usr/bin/env bash
# Build test fixtures: a fake "enterprise" cert (p12), a CMS-signed provisioning
# profile with the same layout as Apple's, and an IPA with an app extension and
# a framework, whose binaries already carry an old (ad-hoc) signature with
# entitlements from a different team. Needs clang + lld + openssl + rcodesign.
set -euo pipefail
OUT=${1:-fixtures}
TEAM=${TEAM:-ABCDE12345}
OLDTEAM=ZZZZZ99999
mkdir -p "$OUT" && cd "$OUT"
rm -rf work && mkdir work && cd work

# --- certificate --------------------------------------------------------------
cat > cert.cnf <<EOF
[req]
distinguished_name = dn
prompt = no
[dn]
CN = iPhone Distribution: Test Corp
OU = $TEAM
O = Test Corp
C = US
[ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,codeSigning
EOF
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 \
  -config cert.cnf -extensions ext 2>/dev/null
openssl pkcs12 -export -inkey key.pem -in cert.pem -out ../cert.p12 -passout pass:test1234
printf 'test1234' > ../cert_pass.txt
printf '%s' "$TEAM" > ../team_id.txt

# --- provisioning profile (enterprise style, wildcard app id) -----------------
CERT_B64=$(openssl x509 -in cert.pem -outform DER | base64 -w0)
cat > prov.plist <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>AppIDName</key><string>Wildcard</string>
  <key>ApplicationIdentifierPrefix</key><array><string>$TEAM</string></array>
  <key>CreationDate</key><date>2026-01-01T00:00:00Z</date>
  <key>Platform</key><array><string>iOS</string></array>
  <key>DeveloperCertificates</key><array><data>$CERT_B64</data></array>
  <key>Entitlements</key>
  <dict>
    <key>application-identifier</key><string>$TEAM.*</string>
    <key>com.apple.developer.team-identifier</key><string>$TEAM</string>
    <key>get-task-allow</key><false/>
    <key>keychain-access-groups</key><array><string>$TEAM.*</string></array>
    $( [ "${PROFILE_MEMORY:-1}" = 1 ] && echo '<key>com.apple.developer.kernel.increased-memory-limit</key><true/>' )
  </dict>
  <key>ExpirationDate</key><date>2027-01-01T00:00:00Z</date>
  <key>Name</key><string>Test Enterprise Wildcard</string>
  <key>ProvisionsAllDevices</key><true/>
  <key>TeamIdentifier</key><array><string>$TEAM</string></array>
  <key>TeamName</key><string>Test Corp</string>
  <key>TimeToLive</key><integer>365</integer>
  <key>UUID</key><string>11111111-2222-3333-4444-555555555555</string>
  <key>Version</key><integer>1</integer>
</dict>
</plist>
EOF
openssl cms -sign -nodetach -binary -outform DER -in prov.plist -signer cert.pem -inkey key.pem \
  -out ../prov.mobileprovision

# --- IPA ------------------------------------------------------------------------
build_exe() { # name out
  printf 'int main(void){return 0;}\n' > "$1.c"
  clang -target arm64-apple-ios14.0 -c "$1.c" -o "$1.o"
  ld64.lld -arch arm64 -platform_version ios 14.0 14.0 -e _main -o "$2" "$1.o"
}
build_dylib() { # name out
  printf 'int %s_fn(void){return 1;}\n' "$1" > "$1.c"
  clang -target arm64-apple-ios14.0 -c "$1.c" -o "$1.o"
  ld64.lld -arch arm64 -platform_version ios 14.0 14.0 -dylib -install_name "@rpath/$1.framework/$1" -o "$2" "$1.o"
}
info_plist() { # path id exe [type]
  cat > "$1" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  ${2:+<key>CFBundleIdentifier</key><string>$2</string>}
  <key>CFBundleExecutable</key><string>$3</string>
  <key>CFBundleName</key><string>$3</string>
  <key>CFBundlePackageType</key><string>${4:-APPL}</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>MinimumOSVersion</key><string>14.0</string>
</dict></plist>
EOF
}
old_ents() { # path bundle-id
  cat > "$1" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>application-identifier</key><string>$OLDTEAM.$2</string>
  <key>com.apple.developer.team-identifier</key><string>$OLDTEAM</string>
  <key>keychain-access-groups</key><array><string>$OLDTEAM.$2</string></array>
  <key>com.apple.developer.associated-domains</key><array><string>applinks:example.com</string></array>
  $( [ "$2" = com.example.demo ] && echo '<key>com.apple.developer.kernel.increased-memory-limit</key><true/>' )
</dict></plist>
EOF
}

APP=Payload/Demo.app
mkdir -p $APP/PlugIns/Share.appex $APP/Frameworks/Foo.framework
build_exe demo $APP/Demo
build_exe share $APP/PlugIns/Share.appex/Share
build_dylib Foo $APP/Frameworks/Foo.framework/Foo
info_plist $APP/Info.plist com.example.demo Demo
info_plist $APP/PlugIns/Share.appex/Info.plist com.example.demo.share Share XPC!
info_plist $APP/Frameworks/Foo.framework/Info.plist "" Foo FMWK   # no CFBundleIdentifier on purpose
echo hello > $APP/resource.txt
old_ents ents-main.plist com.example.demo
old_ents ents-share.plist com.example.demo.share
# pre-sign ad-hoc with "original" entitlements, like an app pulled from a device
rcodesign sign --entitlements-xml-file ents-main.plist $APP/Demo >/dev/null 2>&1
rcodesign sign --entitlements-xml-file ents-share.plist $APP/PlugIns/Share.appex/Share >/dev/null 2>&1
rm -f ../unsigned.ipa && zip -qry ../unsigned.ipa Payload
cd .. && rm -rf work
echo "fixtures in $(pwd): $(ls | tr '\n' ' ')"
