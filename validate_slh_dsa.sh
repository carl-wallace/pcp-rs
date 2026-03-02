#!/bin/sh

PITTV3=/Users/cwallace/devel/carl-wallace/rust-pki-cert-limbo/target/release/pittv3
PCP_TARGET=/Users/cwallace/devel/redhound/pcp-rs/target

ML_DSA_VARIANTS="44 65 87"
SLH_DSA_VARIANTS="sha2_128s sha2_128f sha2_192s sha2_192f sha2_256s sha2_256f shake_128s shake_128f shake_192s shake_192f shake_256s shake_256f"

for VARIANT in $ML_DSA_VARIANTS; do
    DIR="pkits_ml_dsa_${VARIANT}"
    CBOR="pkits_ml_dsa_${VARIANT}.cbor"
    RESULTS="${PCP_TARGET}/ml_dsa_${VARIANT}_results.txt"

    echo "Generating CBOR for ml_dsa_${VARIANT}..."
    $PITTV3 \
        -t "${PCP_TARGET}/${DIR}/ta" \
        -c "${PCP_TARGET}/${DIR}/certs" \
        -b "$CBOR" \
        -g

    echo "Validating ml_dsa_${VARIANT}..."
    $PITTV3 \
        -b "$CBOR" \
        -f "${PCP_TARGET}/${DIR}/certs" \
        --crl-folder "${PCP_TARGET}/${DIR}/crls" \
        -t "${PCP_TARGET}/${DIR}/ta" \
        -v > "$RESULTS"

    echo "  Results -> $RESULTS"
done

for VARIANT in $SLH_DSA_VARIANTS; do
    DIR="pkits_slh_dsa_${VARIANT}"
    CBOR="pkits_slh_dsa_${VARIANT}.cbor"
    RESULTS="${PCP_TARGET}/slh_dsa_${VARIANT}_results.txt"

    echo "Generating CBOR for slh_dsa_${VARIANT}..."
    $PITTV3 \
        -t "${PCP_TARGET}/${DIR}/ta" \
        -c "${PCP_TARGET}/${DIR}/certs" \
        -b "$CBOR" \
        -g

    echo "Validating slh_dsa_${VARIANT}..."
    $PITTV3 \
        -b "$CBOR" \
        -f "${PCP_TARGET}/${DIR}/certs" \
        --crl-folder "${PCP_TARGET}/${DIR}/crls" \
        -t "${PCP_TARGET}/${DIR}/ta" \
        -v > "$RESULTS"

    echo "  Results -> $RESULTS"
done

echo "Done."
