#!/bin/sh

# Helper script to generate forged OCSP responses
# that are signed by a random self-signed CA that
# has no authority to judge the revocation status
# of the given certificate.
#
# (C) 2022 Jack Lloyd
# (C) 2022 René Meusel (Rohde & Schwarz Cybersecurity)
#
# Botan is released under the Simplified BSD License (see license.txt)

if [ $# -ne 3 ]; then
    echo "Usage: $0 <victim's cert> <victim's cert's issuer> <valid/revoked>"
    exit 1
fi

if [ $(date "+%y%m%d") != "161118" ]; then
    echo "You need a time machine to run this script..."
    echo "Use libfaketime to set the system clock back to the 18th of November 2016"
    echo "Like so (path is for Ubuntu, might vary):"
    echo "  LD_PRELOAD=/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1 FAKETIME=\"2016-11-18 12:00:00\" $0 $@"
    exit 1
fi

set -ex

Vcert="$1"
Vissuer="$2"
Vstatus="$3"

RQ="req.der"
RP="forged_response.der"
RPnocerts="forged_response_nocerts.der"

RPcakey="ca.key"
RPcacert="ca.pem"

RPcsrconf="cert_csr.conf"
RPcsr="cert.csr"
RPcertconf="cert.conf"
RPkey="cert.key"
RPcert="cert.pem"
RPindex="index.txt"

# create a forged Certificate Authority
openssl req -x509 \
            -sha256 -days 356 \
            -nodes \
            -newkey rsa:2048 \
            -subj "/CN=Forged OCSP CA/C=DE/L=Berlin" \
            -keyout $RPcakey -out $RPcacert

# create a self-signed certificate
openssl genrsa -out $RPkey 2048

cat > $RPcsrconf <<EOF
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[ dn ]
C = DE
ST = Berlin
L = Berlin
O = Hackerspace
OU = OCSP Breaking Lab
CN = Forged OCSP Signer

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ocsp.hackerspace.org
EOF

openssl req -new -key $RPkey -out $RPcsr -config $RPcsrconf

cat > $RPcertconf <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage=OCSPSigning
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ocsp.hackerspace.org
EOF

openssl x509 -req \
    -in $RPcsr \
    -CA $RPcacert -CAkey $RPcakey \
    -CAcreateserial -out $RPcert \
    -days 365 \
    -sha256 -extfile $RPcertconf

# mark victim's cert as "valid" or "revoked"
enddate=$(openssl x509 -in $Vcert -enddate -noout | sed 's/notAfter=//')
formatted_enddate=$(date -d "$enddate" "+%y%m%d%H%M%S")
serial=$(openssl x509 -in $Vcert -serial -noout | sed 's/serial=//')
subject=$(openssl x509 -in $Vcert -subject -nameopt "oneline,RFC2253" -noout | sed 's/subject=//')

if [ "$Vstatus" = "valid" ]; then
    echo "V\t${formatted_enddate}Z\t\t${serial}\tunknown\t${subject}" > $RPindex
elif [ "$Vstatus" = "revoked" ]; then
    formatted_currentdate=$(date "+%y%m%d%H%M%S")
    echo "R\t${formatted_enddate}Z\t${formatted_currentdate}Z\t${serial}\tunknown\t${subject}" > $RPindex
else
    echo "Don't understand OCSP response status: $Vstatus"
    exit 1
fi

# generate an OCSP response using the just-created certificate
openssl ocsp -issuer $Vissuer -cert $Vcert -reqout $RQ -text -no_nonce
openssl ocsp -reqin $RQ -rsigner $RPcert -rkey $RPkey -CA $Vissuer -index $RPindex -ndays 5 -respout $RP -text
openssl ocsp -reqin $RQ -rsigner $RPcert -rkey $RPkey -CA $Vissuer -index $RPindex -ndays 5 -respout $RPnocerts -resp_no_certs -text
