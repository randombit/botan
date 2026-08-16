#!/bin/bash

# Helper script to generate the PQC-signed OCSP test data in
# src/tests/data/x509/ocsp/ ({mldsa,slhdsa}_root.pem, *_ee.pem, *_ocsp.der).
#
# For each algorithm it creates a self-signed root CA and an end-entity
# certificate, and lets the CA itself sign a "good" OCSP response for the
# end-entity certificate.
#
# Note that the OCSP response's thisUpdate is the time of generation and its
# nextUpdate lies 3650 days after it. The fixed validation timestamp used in
# test_pqc_signed_ocsp_response() (src/tests/test_ocsp.cpp) must lie within
# that window, so it needs to be adjusted when regenerating the data.
#
# Requires OpenSSL >= 3.5.
#
# (C) 2026 Falko Strenzke
#
# Botan is released under the Simplified BSD License (see license.txt)

set -ex

gen() {
    local alg="$1"
    local prefix="$2"
    local name="$3"

    local dir
    dir="$(mktemp -d)"
    pushd "$dir"

    # Self-signed root CA that also signs the OCSP response itself
    openssl genpkey -algorithm "$alg" -out root.key
    openssl req -x509 -key root.key -out "${prefix}_root.pem" -days 7300 \
        -subj "/O=Botan Tests/CN=${name} OCSP Test CA" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign,digitalSignature"

    # End-entity certificate
    openssl genpkey -algorithm "$alg" -out ee.key
    openssl req -new -key ee.key -out ee.csr \
        -subj "/O=Botan Tests/CN=${name} OCSP Test EE"
    openssl x509 -req -in ee.csr -CA "${prefix}_root.pem" -CAkey root.key \
        -out "${prefix}_ee.pem" -days 7300 -set_serial 0x1001

    # OCSP request and CA-signed "good" response
    openssl ocsp -issuer "${prefix}_root.pem" -cert "${prefix}_ee.pem" \
        -no_nonce -reqout req.der

    printf 'V\t460801000000Z\t\t1001\tunknown\t/O=Botan Tests/CN=%s OCSP Test EE\n' "$name" > index.txt

    # -resp_no_certs keeps the signature BIT STRING as the last element of the
    # response encoding, which the signature tampering test relies on
    openssl ocsp -index index.txt -rsigner "${prefix}_root.pem" -rkey root.key \
        -CA "${prefix}_root.pem" -reqin req.der -respout "${prefix}_ocsp.der" \
        -ndays 3650 -resp_no_certs

    popd

    cp "$dir/${prefix}_root.pem" "$dir/${prefix}_ee.pem" "$dir/${prefix}_ocsp.der" .
    rm -rf "$dir"
}

gen ML-DSA-65 mldsa ML-DSA
gen SLH-DSA-SHA2-128s slhdsa SLH-DSA
