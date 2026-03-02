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

# Certs whose signature must be altered to introduce a bad signature.
# - BadSignedCACert: CA cert issued by TrustAnchor with a corrupted sig (PKITS 4.1.2)
# - InvalidEESignatureTest3EE: EE cert with a bad sig (PKITS 4.1.3)
# - InvalidDSASignatureTest6EE: EE cert with a bad sig (PKITS 4.1.6)
BAD_SIG_CERTS=(
    BadSignedCACert.der
    InvalidEESignatureTest3EE.der
    InvalidDSASignatureTest6EE.der
)

flip_last_byte() {
    local file="$1"
    python3 - "$file" <<'PYEOF'
import sys
path = sys.argv[1]
data = bytearray(open(path, 'rb').read())
data[-1] ^= 0xFF
open(path, 'wb').write(data)
print(f"  flipped last byte of {path}")
PYEOF
}

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

    # Corrupt last byte of bad-signature certs
    for cert in "${BAD_SIG_CERTS[@]}"; do
        f="$dir/certs/$cert"
        if [ -f "$f" ]; then
            flip_last_byte "$f"
        else
            echo "  WARNING: $cert not found in $dir/certs"
        fi
    done
done

echo ""
echo "Done."
