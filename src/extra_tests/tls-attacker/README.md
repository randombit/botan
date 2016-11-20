# TLS-Attacker testsuite and fuzzing

Extended Botan library tests with TLS-Attacker. https://github.com/RUB-NDS/TLS-Attacker

## Testsuite
Contains a testsuite to validate correct TLS server behavior. 

Run
```bash
setup.sh
```
to download and build the recent TLS-Attacker version, and generate RSA key pairs.

Run 
```bash
server_testsuite.sh
server_policytest.sh
```
to run the tests. Testsuite executes specific TLS handshakes with the Botan server and verifies that the server correctly handles specific TLS versions and cipher suites. The policy test instantiates the Botan server with a specific policy and verifies that the server behaves according to this policy.


## Fuzzing
Starts the TLS-Attacker fuzzer against the Botan server.

Run
```bash
setup.sh
```
to download and build the recent TLS-Attacker version, generate RSA key pairs, and re-compile Botan with Address Sanitizer.

Run
```bash
server_fuzzer.sh
```
to start the fuzzer. The fuzzer config is located in `config.xml`. Per default, one Botan server is started on port 55020, with the generated RSA keys.`