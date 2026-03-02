#!/bin/sh

variety="${1}"
prefix="${2:-ValidCertificatePathTest1EE}"

for p12 in ./target/${variety}/pkcs12/${prefix}_*.p12; do
    base=$(basename "$p12" .p12)
    out="${base}.bin"
    echo "=== $base ==="
    openssl pkcs12 -in "$p12" -nodes -nocerts -passin pass:password -out "$out"
    openssl pkey -in "$out" -outform DER -out "$out"
    dumpasn1 "$out"
done
