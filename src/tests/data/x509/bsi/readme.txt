The test cases were developed during a project with the German BSI.

Each test case contains
* An end certificate that is to be validated: contains "TC" in its certificate file name
* A trusted CA certificate: contains "TA" in its certificate file name
* A set of sub CA certificates that may or may not be needed to construct a patht from TC to TA
* A description.txt file that explains what the is meant to be tested

expected.txt contains the status code that is expected as the path validation
output for each test case. The expected output may also be the message string
of an exception.

Certificate revocation lists must be checked if and only if the test directory
has "CRL" in its filename.