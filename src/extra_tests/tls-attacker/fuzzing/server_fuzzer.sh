#!/bin/sh

if [ -d tls-testsuite ] 
then
    cd tls-testsuite
fi

java -jar ../TLS-Attacker/Runnable/target/TLS-Attacker-1.2.jar -loglevel ERROR multi_fuzzer -startup_command_file config.xml