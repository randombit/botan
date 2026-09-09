#!/bin/bash

# Helper script to generate the otherName test certificates in
# src/tests/data/x509/othername/ (see the README.md there for a description of
# each file).
#
# Every certificate is self-signed with a fresh P-256 key and carries otherName
# entries in its SubjectAlternativeName, IssuerAlternativeName or
# NameConstraints extension. The tests only parse these certificates (they are
# never path validated), so the validity period merely has to be plausible; it
# follows the convention of src/tests/data/x509/name_constraints/.
#
# Requires OpenSSL >= 3.4 (for -not_before/-not_after).
#
# (C) 2026 Moritz Schmitt
#
# Botan is released under the Simplified BSD License (see license.txt)

set -eu

OUT_DIR="${1:-src/tests/data/x509/othername}"

NOT_BEFORE=20260101000000Z
NOT_AFTER=20351230000000Z

# Microsoft User Principal Name (szOID_NT_PRINCIPAL_NAME)
UPN=1.3.6.1.4.1.311.20.2.3
# Arc below Botan's private enterprise number, also used in src/tests/test_alt_name.cpp
ARC=1.3.6.1.4.1.25258.10000

UMLAUT_NAME=$(printf 'J\303\274rgen@example.com')
LONG_VALUE=$(printf 'x%.0s' $(seq 1 3000))

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "$OUT_DIR"

serial=0

# gen <file name> <common name> <extension config>
#
# The extension config is appended to the config file and must define the
# section [ext], which may reference further sections.
gen() {
    local name="$1"
    local cn="$2"
    local ext="$3"

    serial=$((serial + 1))

    local key="$WORK_DIR/$name.key"
    local cnf="$WORK_DIR/$name.cnf"

    cat > "$cnf" <<EOF
[req]
distinguished_name = dn
prompt = no
utf8 = yes
string_mask = utf8only

[dn]
C = US
O = OtherName Tests
CN = $cn

$ext
EOF

    openssl ecparam -name prime256v1 -genkey -noout -out "$key"
    openssl req -new -x509 -key "$key" -config "$cnf" -extensions ext \
        -sha256 -set_serial "$serial" \
        -not_before "$NOT_BEFORE" -not_after "$NOT_AFTER" \
        -out "$OUT_DIR/$name.pem"
}

gen msupn-san "MS UPN SAN" "
[ext]
basicConstraints = critical,CA:FALSE
subjectAltName = @san

[san]
DNS.0 = www.example.com
email.0 = alice@example.com
otherName.0 = $UPN;UTF8:alice@corp.example.com
"

gen string-utf8 "UTF8String otherName" "
[ext]
basicConstraints = critical,CA:FALSE
subjectAltName = @san

[san]
otherName.0 = $ARC.1;FORMAT:UTF8,UTF8:$UMLAUT_NAME
"

gen string-ia5 "IA5String otherName" "
[ext]
basicConstraints = critical,CA:FALSE
subjectAltName = @san

[san]
otherName.0 = $ARC.2;IA5:ia5@example.com
"

gen string-printable "PrintableString otherName" "
[ext]
basicConstraints = critical,CA:FALSE
subjectAltName = @san

[san]
otherName.0 = $ARC.3;PRINTABLE:Printable Name 42
"

gen string-visible "VisibleString otherName" "
[ext]
basicConstraints = critical,CA:FALSE
subjectAltName = @san

[san]
otherName.0 = $ARC.4;VISIBLE:Visible String!
"

gen string-numeric "NumericString otherName" "
[ext]
basicConstraints = critical,CA:FALSE
subjectAltName = @san

[san]
otherName.0 = $ARC.5;NUMERIC:0123456789
"

gen string-bmp "BMPString otherName" "
[ext]
basicConstraints = critical,CA:FALSE
subjectAltName = @san

[san]
otherName.0 = $ARC.6;BMP:bmp
"

gen string-universal "UniversalString otherName" "
[ext]
basicConstraints = critical,CA:FALSE
subjectAltName = @san

[san]
otherName.0 = $ARC.7;UNIV:uni
"

gen string-teletex "TeletexString otherName" "
[ext]
basicConstraints = critical,CA:FALSE
subjectAltName = @san

[san]
otherName.0 = $ARC.8;T61:teletex
"

gen non-string "Non-string otherNames" "
[ext]
basicConstraints = critical,CA:FALSE
subjectAltName = @san

[san]
otherName.0 = $ARC.10;SEQUENCE:seq_int
otherName.1 = $ARC.11;FORMAT:HEX,OCT:DEADBEEF

[seq_int]
i = INT:42
"

gen multi "Multiple otherNames" "
[ext]
basicConstraints = critical,CA:FALSE
subjectAltName = @san

[san]
DNS.0 = multi.example.com
email.0 = multi@example.com
IP.0 = 192.0.2.1
otherName.0 = $UPN;UTF8:multi@corp.example.com
otherName.1 = $ARC.2;IA5:ia5@example.com
otherName.2 = $ARC.6;BMP:bmp
otherName.3 = $ARC.10;SEQUENCE:seq_int

[seq_int]
i = INT:42
"

gen ian "IssuerAltName otherName" "
[ext]
basicConstraints = critical,CA:FALSE
subjectAltName = DNS:www.example.com
issuerAltName = @ian

[ian]
DNS.0 = ca.example.com
otherName.0 = $UPN;UTF8:issuer@corp.example.com
"

gen nc-excluded "Excluded otherName CA" "
[ext]
basicConstraints = critical,CA:TRUE
nameConstraints = critical,@nc

[nc]
permitted;DNS.0 = example.com
permitted;otherName.0 = $ARC.2;IA5:permitted@example.com
excluded;otherName.0 = $UPN;UTF8:excluded@corp.example.com
"

gen edge-values "Edge case otherName values" "
[ext]
basicConstraints = critical,CA:FALSE
subjectAltName = @san

[san]
otherName.0 = $ARC.20;UTF8:
otherName.1 = $ARC.21;UTF8:$LONG_VALUE
"
