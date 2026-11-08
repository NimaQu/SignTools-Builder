#!/usr/bin/env bash
# End-to-end test without Docker: SignTools server + SignTools-Builder + the Linux sign.py.
# Submits a job like the web UI does and verifies the signed IPA.
#
#   SERVER_BIN / BUILDER_BIN  use these binaries (default: download upstream releases)
#   BIG_MB=300                add a random file of this size to the app (exercises big-file paths)
#   LOCAL=1                   same-machine mode (needs the NimaQu/SignTools fork as SERVER_BIN): the IPA is
#                             dropped into import_dir and picked by name (like the web UI's "Server"
#                             switch), local_transfer_dir is set and the builder works inside it:
#                             no HTTP transfer of the app at all
#   LOCAL=outside             local_transfer_dir set but the builder works elsewhere: must fall back to upload
#
# The service's server_url is deliberately unreachable: the builder must use SIGNTOOLS_INTERNAL_URL.
# Uploads use TUS_CHUNK_SIZE_MB=8, downloads use curl.
# Needs: curl, python3 (cryptography, lief), node/npm, unzip, zip, openssl, rcodesign, clang + lld.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
E=${E2E_DIR:-/tmp/signtools-e2e}
ST_VER=${ST_VER:-3.0.13}; B_VER=${B_VER:-1.1.21}
rm -rf "$E"; mkdir -p "$E"/{data/profiles/ent,data/work,data/import,signfiles,www}; cd "$E"
if [[ -n "${LOCAL:-}" && "${LOCAL}" != outside ]]; then BWORK="$E/data/work"; else BWORK="$E/bwork"; mkdir -p "$BWORK"; fi

if [[ -n "${SERVER_BIN:-}" ]]; then cp "$SERVER_BIN" SignTools; else
  curl -fsSL -o SignTools "https://github.com/SignTools/SignTools/releases/download/v$ST_VER/SignTools_${ST_VER}_linux_amd64"; fi
if [[ -n "${BUILDER_BIN:-}" ]]; then cp "$BUILDER_BIN" SignTools-Builder; else
  curl -fsSL -o SignTools-Builder "https://github.com/SignTools/SignTools-Builder/releases/download/v$B_VER/SignTools-Builder_${B_VER}_linux_amd64"; fi
chmod +x SignTools SignTools-Builder

bash "$ROOT/tests/make-fixtures.sh" "$E/fx" >/dev/null
cp fx/{cert.p12,cert_pass.txt,prov.mobileprovision} data/profiles/ent/
printf 'Enterprise (test)' > data/profiles/ent/name.txt
if [[ -n "${BIG_MB:-}" ]]; then
  mkdir big && (cd big && unzip -qq ../fx/unsigned.ipa && head -c "$((BIG_MB * 1024 * 1024))" /dev/urandom > Payload/Demo.app/romfs.img \
    && zip -qry -0 ../www/Demo.ipa Payload) && rm -rf big
else
  cp fx/unsigned.ipa www/Demo.ipa
fi
cp -r "$ROOT"/{sign.py,node-utils,libsubstrate} signfiles/
(cd signfiles/node-utils && npm ci --no-audit --no-fund >/dev/null)

cat > signer-cfg.yml <<EOF
builder:
  selfhosted: {enable: true, url: "http://127.0.0.1:8090", key: e2e-builder-key}
server_url: http://unreachable.invalid:8080
save_dir: data
cleanup_interval_mins: 1
sign_timeout_mins: 15
basic_auth: {enable: false}
EOF
if [[ -n "${LOCAL:-}" ]]; then printf 'local_transfer_dir: %s\nimport_dir: %s\n' "$E/data/work" "$E/data/import" >> signer-cfg.yml; fi

pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true' EXIT
(cd "$BWORK" && SIGNTOOLS_INTERNAL_URL=http://127.0.0.1:8080 TUS_CHUNK_SIZE_MB=8 \
  exec "$E/SignTools-Builder" -key e2e-builder-key -files "$E/signfiles") > builder.log 2>&1 & pids+=($!)
sleep 1
./SignTools -config signer-cfg.yml > server.log 2>&1 & pids+=($!)
(cd www && exec python3 -m http.server 8000) > www.log 2>&1 & pids+=($!)
sleep 3

if [[ "${LOCAL:-}" == 1 ]]; then
  # as if copied there with rsync/SMB; must show up in the web UI's list
  cp www/Demo.ipa data/import/Demo.ipa
  curl -fsS http://127.0.0.1:8080/ | grep -q '<option value="Demo.ipa">' || { echo "import file not listed in web UI"; exit 1; }
  source=(-F file_local=Demo.ipa)
else
  source=(-F file_url=http://127.0.0.1:8000/Demo.ipa)
fi
curl -fsS -o /dev/null -X POST http://127.0.0.1:8080/apps "${source[@]}" \
  -F profile_id=ent -F builder_id=SelfHosted -F id=id_original -F bundle_name="Demo Signed"

app=""
for _ in $(seq 1 150); do
  app=$(ls data/apps 2>/dev/null | head -1 || true)
  [[ -n "$app" && -s "data/apps/$app/signed" ]] && break
  sleep 2
done
[[ -n "$app" && -s "data/apps/$app/signed" ]] || { echo "signing did not finish"; tail -30 builder.log; exit 1; }

plain=$(sed 's/\x1b\[[0-9;]*m//g' server.log)
echo "builder downloads of the unsigned app: $(grep -c "uri=/jobs/[^ ]*/unsigned" <<<"$plain" || true)"
echo "tus upload requests from the builder:  $(grep -c "uri=/jobs/[^ ]*/tus/" <<<"$plain" || true)"
if [[ "${LOCAL:-}" == 1 ]]; then
  [[ $(stat -c %i data/import/Demo.ipa) == $(stat -c %i "data/apps/$app/unsigned") ]] \
    && echo "import: hard-linked into storage (no copy), original kept" || { echo "import was copied, not linked"; exit 1; }
fi
curl -fsS -o signed.ipa "http://127.0.0.1:8080/apps/$app/signed"
python3 "$ROOT/tests/verify-ipa.py" signed.ipa ABCDE12345 memory
