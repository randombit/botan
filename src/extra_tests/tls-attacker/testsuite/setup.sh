#!/bin/sh

if [ ! -d output ]
then
    mkdir output
fi

cd ..

openssl genpkey -algorithm RSA -out rsa2048key.pem -pkeyopt rsa_keygen_bits:2048 
openssl req -key rsa2048key.pem -new -x509 -days 365 -out rsa2048cert.pem -subj "/C=DE/ST=NRW/L=Bochum/O=TLS-Attacker/CN=tls-attacker.de"

if [ ! -d TLS-Attacker ]
then
    git clone https://github.com/RUB-NDS/TLS-Attacker.git
fi

cd TLS-Attacker
git checkout .
git pull
./mvnw clean package -DskipTests=true
