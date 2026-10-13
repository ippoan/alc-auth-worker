#!/usr/bin/env bash
# check-exposure.sh の陰性対照 (ippoan/rust-leave-worker の同名の script の写し、元は ippoan/alc-vein-worker。この worker に
# 無い binding (R2・一番星・既存の services / queue) を崩す行は、表を挿す形に置き換えた)。wrangler.toml を 1 か所ずつ崩したコピーで
# exit 1 になること、元のままなら exit 0 になることを確かめる。CI で check-exposure.sh の直後に走る。
set -euo pipefail
cd "$(dirname "$0")/.."

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fail=0

expect() {
  local want="$1" label="$2" toml="$3"
  if bash scripts/check-exposure.sh "$toml" >"$tmp/out" 2>&1; then got=0; else got=1; fi
  if [ "$got" = "$want" ]; then
    echo "ok   ${label} (exit ${got})"
  else
    echo "FAIL ${label}: exit ${got}, want ${want}"; sed 's/^/     /' "$tmp/out"; fail=1
  fi
}

mutate() { # $1 = label, $2 = python の置換式 (s を書き換える)
  python3 - wrangler.toml "$tmp/w.toml" "$2" <<'PY'
import re
import sys
s = open(sys.argv[1]).read()
before = s
exec(sys.argv[3])
assert s != before, "mutation did not change wrangler.toml"
open(sys.argv[2], "w").write(s)
PY
  expect 1 "$1" "$tmp/w.toml"
}

expect 0 "wrangler.toml そのまま" wrangler.toml
mutate "staging で workers_dev = true" \
  's = s.replace("name = \"alc-auth-worker-staging\"\nworkers_dev = false", "name = \"alc-auth-worker-staging\"\nworkers_dev = true", 1)'
mutate "staging で preview_urls = true" \
  's = s.replace("preview_urls = false\n\n[env.staging.observability]", "preview_urls = true\n\n[env.staging.observability]", 1)'
mutate "staging 以外の env で workers_dev = true" \
  's += "\n[env.dev]\nname = \"auth-dev\"\nworkers_dev = true\n"'
mutate "staging 以外の env で preview_urls = true" \
  's += "\n[env.preview]\nname = \"auth-preview\"\npreview_urls = true\n"'
mutate "staging 以外の env がトップレベルの true を継承" \
  's = re.sub(r"^workers_dev = false$", "workers_dev = true", s, count=1, flags=re.M) + "\n[env.other]\nname = \"x\"\n"'
mutate "トップレベルの vars に ALLOW_INSECURE_DB" \
  's = s.replace("[build]", "[vars]\nALLOW_INSECURE_DB = \"1\"\n\n[build]", 1)'
mutate "staging の vars に ALLOW_INSECURE_DB" \
  's = s.replace("[env.staging.observability]", "[env.staging.vars]\nALLOW_INSECURE_DB = \"1\"\n\n[env.staging.observability]", 1)'
mutate "トップレベルの workers_dev を true に" \
  's = re.sub(r"^workers_dev = false$", "workers_dev = true", s, count=1, flags=re.M)'
mutate "トップレベルの preview_urls を消す" \
  's = re.sub(r"^preview_urls = false\n", "", s, count=1, flags=re.M)'
mutate "本番に routes を足す" \
  's = s.replace("[build]", "routes = [{ pattern = \"auth.example.com\", custom_domain = true }]\n\n[build]", 1)'
mutate "staging に route を足す" \
  's = s.replace("[env.staging.observability]", "route = \"auth.example.com/*\"\n\n[env.staging.observability]", 1)'
mutate "本番に vpc_services (平文の DB 経路) を足す" \
  's = s.replace("[build]", "[[vpc_services]]\nbinding = \"AUTH_DB_VPC\"\nservice_id = \"x\"\nremote = true\n\n[build]", 1)'
# DO の binding は env.staging の STAGING_DB 1 件 (name・class_name・script_name の完全一致) だけ許す。
# 元の wrangler.toml が持つその 1 件を崩す / 別の形を足す
mutate "staging の DO の script_name が別名" \
  's = s.replace("script_name = \"alc-staging-db-staging\"", "script_name = \"alc-staging-db\"", 1)'
mutate "staging の DO に script_name が無い (この worker 自身の class を指す)" \
  's = s.replace("script_name = \"alc-staging-db-staging\"\n", "", 1)'
mutate "staging の DO の class_name が違う" \
  's = s.replace("class_name = \"StagingDb\"", "class_name = \"AuthDb\"", 1)'
mutate "staging の DO の binding 名が違う" \
  's = s.replace("name = \"STAGING_DB\"", "name = \"AUTH_DB\"", 1)'
mutate "staging の DO を 2 件にする" \
  's = s.replace("[env.staging.version_metadata]", "[[env.staging.durable_objects.bindings]]\nname = \"OTHER_DB\"\nclass_name = \"OtherDb\"\nscript_name = \"alc-staging-db-staging\"\n\n[env.staging.version_metadata]", 1)'
mutate "トップレベル (本番) に DO の binding を足す" \
  's = s.replace("[build]", "[[durable_objects.bindings]]\nname = \"STAGING_DB\"\nclass_name = \"StagingDb\"\nscript_name = \"alc-staging-db-staging\"\n\n[build]", 1)'
mutate "staging 以外の env (local) に DO の binding を足す" \
  's += "\n[[env.local.durable_objects.bindings]]\nname = \"STAGING_DB\"\nclass_name = \"StagingDb\"\nscript_name = \"alc-staging-db-staging\"\n"'
mutate "トップレベルに migrations (DO の class の定義) を足す" \
  's = s.replace("[build]", "[[migrations]]\ntag = \"v1\"\nnew_sqlite_classes = [\"AuthDb\"]\n\n[build]", 1)'
mutate "staging に migrations を足す" \
  's = s.replace("[env.staging.version_metadata]", "[[env.staging.migrations]]\ntag = \"v1\"\nnew_sqlite_classes = [\"AuthDb\"]\n\n[env.staging.version_metadata]", 1)'
mutate "本番に containers を足す" \
  's = s.replace("[build]", "[[containers]]\nclass_name = \"X\"\nimage = \"./x\"\n\n[build]", 1)'
mutate "staging に containers を足す" \
  's = s.replace("[env.staging.version_metadata]", "[[env.staging.containers]]\nclass_name = \"X\"\nimage = \"./x\"\n\n[env.staging.version_metadata]", 1)'
mutate "staging に hyperdrive (本番の DB へ届く binding) を足す" \
  's = s.replace("[env.staging.observability]", "[[env.staging.hyperdrive]]\nbinding = \"AUTH_HYPERDRIVE\"\nid = \"x\"\n\n[env.staging.observability]", 1)'
mutate "local に hyperdrive を足す" \
  's += "\n[[env.local.hyperdrive]]\nbinding = \"AUTH_HYPERDRIVE\"\nid = \"x\"\n"'
mutate "staging の services が本番の auth-worker を指す" \
  's = s.replace("[env.staging.observability]", "[[env.staging.services]]\nbinding = \"AUTH_WORKER\"\nservice = \"auth-worker\"\n\n[env.staging.observability]", 1)'
mutate "staging に本番の queue の consumer を足す" \
  's = s.replace("[env.staging.observability]", "[[env.staging.queues.consumers]]\nqueue = \"auth-inbox\"\n\n[env.staging.observability]", 1)'
mutate "staging の queue consumer の dead letter queue が本番のもの" \
  's = s.replace("[env.staging.observability]", "[[env.staging.queues.consumers]]\nqueue = \"auth-inbox-staging\"\ndead_letter_queue = \"auth-inbox-dlq\"\n\n[env.staging.observability]", 1)'

exit "$fail"
