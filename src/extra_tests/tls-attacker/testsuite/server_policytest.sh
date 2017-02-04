#!/bin/sh

../../../../botan tls_server ../rsa2048cert.pem ../rsa2048key.pem --port=4434 --policy=../../../tests/data/tls-policy/bsi.txt > output/server_policytest.log 2>&1 &
botan_pid=$!

java -jar ../TLS-Attacker/Runnable/target/TLS-Attacker-1.2.jar -loglevel INFO testtls_server -policy ../../../tests/data/tls-policy/bsi.txt -connect localhost:4434 -tls_timeout 1000
rc=$?

if [ $rc -eq 0 ]; then
    echo Policy tests finished without failures
else
    echo '\n\nPolicy tests failed. See the recent error and the server log output.'
#    cat output/server_policytest.log
fi

kill $botan_pid
exit $rc