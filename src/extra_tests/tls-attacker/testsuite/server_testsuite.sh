#!/bin/sh

../../../../botan tls_server ../rsa2048cert.pem ../rsa2048key.pem --port=4433 > output/server_testsuite.log 2>&1 &
botan_pid=$!

java -jar ../TLS-Attacker/Runnable/target/TLS-Attacker-1.2.jar -loglevel INFO testsuite_server -folder ../TLS-Attacker/resources/testsuite -tls_timeout 1000
rc=$?

if [ $rc -eq 0 ]; then
    echo Tests finished without failures
else
    echo '\n\nTests failed. See the recent error and the server log output.'
#    cat output/server_testsuite.log
fi

kill $botan_pid
exit $rc