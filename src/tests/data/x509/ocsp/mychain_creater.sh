#!/bin/sh

# Helper script to generate a certificate chain
# alternative certificates might sign the OCSP responses.
#
# (C) 2022 Jack Lloyd
# (C) 2022 René Meusel (Rohde & Schwarz Cybersecurity)
#
# Botan is released under the Simplified BSD License (see license.txt)

if [ $(date "+%y%m%d") != "220922" ]; then
    echo "You should use a time machine to run this script..."
    echo "Use libfaketime to set the system clock back to the 22nd of September 2022. This recreates the certificates with the same timestamps as used in the tests and saves you from re-setting the validation reference dates."
    echo
    echo "Like so (path is for Ubuntu, might vary):"
    echo "  LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1 FAKETIME=\"2022-09-22 12:00:00\" $0 $@"
    exit 1
fi

set -ex

PREFIX="mychain_"

ROOTkey="root.key"
ROOTcsr="root.csr"
ROOTcert="${PREFIX}root.pem"
ROOTindex="root_index.txt"
ROOTconf="root.conf"

INTkey="int.key"
INTcsr="int.csr"
INTcert="${PREFIX}int.pem"
INTindex="int_index.txt"
INTconf="int.conf"

DELRESPkey="int_ocsp_delegate_responder.key"
DELRESPcsr="int_ocsp_delegate_responder.csr"
DELRESPcert="${PREFIX}int_ocsp_delegate_responder.pem"
DELRESPconf="int_ocsp_delegate_responder.conf"

DELRESPnoOCSPcsr="int_ocsp_delegate_responder_no_ocsp_key_usage.csr"
DELRESPnoOCSPcert="${PREFIX}int_ocsp_delegate_responder_no_ocsp_key_usage.pem"
DELRESPnoOCSPconf="int_ocsp_delegate_responder_no_ocsp_key_usage.conf"

EEkey="ee.key"
EEcsr="ee.csr"
EEcert="${PREFIX}ee.pem"
EEconf="ee.conf"

#
# Create the Root CA
#
cat > $ROOTconf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:TRUE
keyUsage=cRLSign, digitalSignature, keyCertSign
extendedKeyUsage=OCSPSigning
EOF

openssl req -sha256 \
            -noenc \
            -newkey rsa:2048 \
            -subj "/CN=My OCSP Root CA/C=DE/L=Berlin" \
            -keyout $ROOTkey -out $ROOTcsr

openssl x509 -req \
    -in $ROOTcsr \
    -key $ROOTkey \
    -CAcreateserial -out $ROOTcert \
    -days 365 \
    -sha256 -extfile $ROOTconf

#
# Create Intermediate CA issued by Root CA
#
cat > $INTconf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:TRUE
keyUsage=cRLSign, digitalSignature, keyCertSign
extendedKeyUsage=OCSPSigning
EOF

openssl req -sha256 \
            -noenc \
            -config $INTconf \
            -newkey rsa:2048 \
            -subj "/CN=My OCSP Local CA/C=DE/L=Berlin" \
            -keyout $INTkey -out $INTcsr

openssl x509 -req \
    -in $INTcsr \
    -CA $ROOTcert -CAkey $ROOTkey \
    -CAcreateserial -out $INTcert \
    -days 365 \
    -sha256 -extfile $INTconf

#
# Create Delegate OCSP responder issued by Intermediate CA
# (one regular cert, one with lacking key usage flags but same public key)
#
openssl genrsa -out $DELRESPkey 2048

cat > $DELRESPconf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=cRLSign, digitalSignature
extendedKeyUsage=OCSPSigning
noCheck=ignored
EOF

openssl req -sha256 \
            -noenc \
            -config $DELRESPconf \
            -new -key $DELRESPkey \
            -subj "/CN=My OCSP Responder/C=DE/L=Berlin" \
            -out $DELRESPcsr

openssl x509 -req \
    -in $DELRESPcsr \
    -CA $INTcert -CAkey $INTkey \
    -CAcreateserial -out $DELRESPcert \
    -days 15 \
    -sha256 -extfile $DELRESPconf

cat > $DELRESPnoOCSPconf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature
noCheck=ignored
EOF

openssl req -sha256 \
            -noenc \
            -config $DELRESPnoOCSPconf \
            -new -key $DELRESPkey \
            -subj "/CN=My OCSP Responder/C=DE/L=Berlin" \
            -out $DELRESPnoOCSPcsr

openssl x509 -req \
    -in $DELRESPnoOCSPcsr \
    -CA $INTcert -CAkey $INTkey \
    -CAcreateserial -out $DELRESPnoOCSPcert \
    -days 15 \
    -sha256 -extfile $DELRESPnoOCSPconf

#
# Create End Entity issued by Intermediate CA
#
cat > $EEconf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature
EOF

openssl req -sha256 \
            -noenc \
            -config $EEconf \
            -newkey rsa:2048 \
            -subj "/CN=My OCSP End Entity/C=DE/L=Berlin" \
            -keyout $EEkey -out $EEcsr

openssl x509 -req \
    -in $EEcsr \
    -CA $INTcert -CAkey $INTkey \
    -CAcreateserial -out $EEcert \
    -days 365 \
    -sha256 -extfile $EEconf

#
# OCSP creation helper function
#
create_ocsp_response()
{
    local subjectCert="$1"
    local caCert="$2"
    local responderCert="$3"
    local responderKey="$4"
    local subjectStatus="$5"
    local ocspResponse="$6"
    local stapling="$7"

    local CAindex="index.txt"
    local ocspReq="req.der"

    enddate=$(openssl x509 -in $subjectCert -enddate -noout | sed 's/notAfter=//')
    formatted_enddate=$(date -d "$enddate" "+%y%m%d%H%M%S")
    serial=$(openssl x509 -in $subjectCert -serial -noout | sed 's/serial=//')
    subject=$(openssl x509 -in $subjectCert -subject -nameopt "oneline,RFC2253" -noout | sed 's/subject=//')

    if [ "$subjectStatus" = "valid" ]; then
        echo "V\t${formatted_enddate}Z\t\t${serial}\tunknown\t${subject}" > $CAindex
    elif [ "$subjectStatus" = "revoked" ]; then
        formatted_currentdate=$(date "+%y%m%d%H%M%S")
        echo "R\t${formatted_enddate}Z\t${formatted_currentdate}Z\t${serial}\tunknown\t${subject}" > $CAindex
    else
        echo "Don't understand OCSP response status: $subjectStatus"
        exit 1
    fi

    if [ "$stapling" = "no_staple" ]; then
        staple="-resp_no_certs"
    else
        staple=""
    fi

    # generate an OCSP response using the just-created certificate
    openssl ocsp -issuer $caCert -cert $subjectCert -reqout $ocspReq -text -no_nonce
    openssl ocsp -reqin $ocspReq -rsigner $responderCert -rkey $responderKey -CA $caCert -index $CAindex -ndays 30 -respout $ocspResponse $staple -text
}

# (Malformed) OCSP response for Intermediate signed by Intermediate itself
create_ocsp_response $INTcert $ROOTcert $INTcert $INTkey "valid" "${PREFIX}ocsp_for_int_self_signed.der" "no_staple"

# (Malformed) OCSP response for End Entity signed by Root certificate
create_ocsp_response $EEcert $INTcert $ROOTcert $ROOTkey "valid" "${PREFIX}ocsp_for_ee_root_signed.der" "no_staple"

# OCSP response for End Entity signed by Intermediate certificate
create_ocsp_response $EEcert $INTcert $INTcert $INTkey "valid" "${PREFIX}ocsp_for_ee.der" "no_staple"

# OCSP response for End Entity signed by Delegate Responder of Intermediate certificate
create_ocsp_response $EEcert $INTcert $DELRESPcert $DELRESPkey "valid" "${PREFIX}ocsp_for_ee_delegate_signed.der" "staple"

# OCSP response for End Entity signed by Delegate Responder of Intermediate certificate that does not have sufficient key usage flags
create_ocsp_response $EEcert $INTcert $DELRESPnoOCSPcert $DELRESPkey "valid" "${PREFIX}ocsp_for_ee_delegate_signed_malformed.der" "staple"
