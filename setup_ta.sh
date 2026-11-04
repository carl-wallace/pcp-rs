#!/bin/bash

set -euo pipefail

VARIANTS=(
    pkits_ml_dsa_44
    pkits_ml_dsa_65
    pkits_ml_dsa_87
    pkits_slh_dsa_sha2_128s
    pkits_slh_dsa_sha2_128f
    pkits_slh_dsa_sha2_192s
    pkits_slh_dsa_sha2_192f
    pkits_slh_dsa_sha2_256s
    pkits_slh_dsa_sha2_256f
    pkits_slh_dsa_shake_128s
    pkits_slh_dsa_shake_128f
    pkits_slh_dsa_shake_192s
    pkits_slh_dsa_shake_192f
    pkits_slh_dsa_shake_256s
    pkits_slh_dsa_shake_256f
)

BASE="$(cd "$(dirname "$0")" && pwd)/target"

for variant in "${VARIANTS[@]}"; do
    dir="$BASE/$variant"
    if [ ! -d "$dir" ]; then
        echo "WARNING: $dir not found, skipping"
        continue
    fi

    ta_dir="$dir/ta"
    ta_src="$dir/certs/TrustAnchorRootCertificate.der"

    echo "=== $variant ==="

    # Create ta/ folder and copy trust anchor
    mkdir -p "$ta_dir"
    if [ -f "$ta_src" ]; then
        cp "$ta_src" "$ta_dir/TrustAnchorRootCertificate.der"
        echo "  copied TrustAnchorRootCertificate.der -> ta/"
    else
        echo "  WARNING: $ta_src not found"
    fi
done

echo ""
echo "Done."
