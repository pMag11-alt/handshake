#!/usr/bin/env bash
# Interoperability with OpenSSL (and curl) in both directions:
#   1. tlsget against `openssl s_server`, for every suite x group.
#   2. `openssl s_client` and curl against tlsserve, for every key type.
# Needs openssl 3.x and curl on PATH.
set -euo pipefail

cd "$(dirname "$0")/.."
work=$(mktemp -d)
pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true; rm -rf "$work"' EXIT

go build -o "$work/tlsget" ./cmd/tlsget
go build -o "$work/tlsserve" ./cmd/tlsserve
openssl version

pass=0
failures=0
check() { # description, command...
  local desc=$1
  shift
  if out=$("$@" 2>&1); then
    pass=$((pass + 1))
    printf '  ok    %s\n' "$desc"
  else
    failures=$((failures + 1))
    printf '  FAIL  %s\n%s\n' "$desc" "$out" | sed 's/^/        /'
  fi
}

wait_for_port() {
  for _ in $(seq 1 50); do
    (echo >"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0
    sleep 0.1
  done
  echo "port $1 never opened" >&2
  return 1
}

echo "== tlsget -> openssl s_server"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost -addext extendedKeyUsage=serverAuth \
  -keyout "$work/ec.key" -out "$work/ec.pem" 2>/dev/null
openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost -addext extendedKeyUsage=serverAuth \
  -keyout "$work/rsa.key" -out "$work/rsa.pem" 2>/dev/null

port=19443
for key in ec rsa; do
  for suite in TLS_AES_128_GCM_SHA256:aes128 TLS_AES_256_GCM_SHA384:aes256 TLS_CHACHA20_POLY1305_SHA256:chacha20; do
    for group in X25519:x25519 P-256:p256 P-384:p384; do
      port=$((port + 1))
      openssl s_server -quiet -www -tls1_3 -accept "$port" \
        -cert "$work/$key.pem" -key "$work/$key.key" \
        -ciphersuites "${suite%%:*}" -groups "${group%%:*}" >/dev/null 2>&1 &
      server=$!
      pids+=("$server")
      wait_for_port "$port"
      # Lead with X25519 always, so the P-256/P-384 servers exercise
      # HelloRetryRequest.
      check "$key cert, ${suite%%:*}, ${group%%:*}" \
        sh -c "'$work/tlsget' -handshake-only -suite ${suite##*:} -cacert '$work/$key.pem' https://localhost:$port/ 2>&1 | grep -q '${suite%%:*}'"
      kill "$server" 2>/dev/null || true
      wait "$server" 2>/dev/null || true
    done
  done
done

echo "== openssl s_client and curl -> tlsserve"
for keytype in ecdsa ecdsa384 rsa; do
  port=$((port + 1))
  "$work/tlsserve" -addr "localhost:$port" -keytype "$keytype" -write-cert "$work/served-$keytype.pem" >/dev/null 2>&1 &
  server=$!
  pids+=("$server")
  wait_for_port "$port"
  for suite in TLS_AES_128_GCM_SHA256 TLS_AES_256_GCM_SHA384 TLS_CHACHA20_POLY1305_SHA256; do
    for group in X25519 P-256 P-384; do
      check "s_client, $keytype server, $suite, $group" sh -c "
        printf 'GET /plain HTTP/1.1\r\nHost: localhost\r\n\r\n' |
        openssl s_client -quiet -tls1_3 -connect localhost:$port -servername localhost \
          -ciphersuites $suite -groups $group -CAfile '$work/served-$keytype.pem' -verify_return_error 2>/dev/null |
        grep -q 'TLS 1.3, $suite'"
    done
  done
  check "curl, $keytype server" sh -c "curl -sS --tlsv1.3 --cacert '$work/served-$keytype.pem' https://localhost:$port/plain | grep -q 'TLS 1.3'"
  kill "$server" 2>/dev/null || true
  wait "$server" 2>/dev/null || true
done

echo
echo "$pass passed, $failures failed"
[[ $failures -eq 0 ]]
