# CRL without a nextUpdate field

This is allowed by the X.509 standard but RFC 5280 requires all CAs to set it.
The CRL in this test body does not comply with that, nevertheless parsing and
path validation should still work as expected.

## Find Contained

 * valid_forever.crl - a CRL that does not define nextUpdate
                       revoking serial numbers "1" and "10"
 * ca.pem            - a CA root certificate issuing the CRL
 * 01.pem            - a certificate with serial number "1", issued by the CA
                       and revoked by the CRL
 * 42.pem            - a certificate with serial number "42", issued by the CA
                       and _not_ revoked by the CRL

## Recreation of this test data

The CRL originates from a downstream application and cannot be easily recreated.
Scripts and private key to regenerate the root CA and leaf certificates can be
found in GH #4732.
