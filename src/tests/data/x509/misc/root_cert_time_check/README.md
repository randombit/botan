# Test: Root Certificate Time Check
RFC 5280 does not disallow CAs to sign certificates with wider validity
ranges than theirs. When checking a certificate chain at a specific
point in time, this can lead to situations where a CA is expired or not
yet valid, but the end-entity certificate is in the validity range.

Botan provides an option to decide if such cases are considered valid.

## Test Certificates
This test case contains two certificates:
- A trusted root certificate `root.crt`. Validity range (years): 2022-2028.
- An end-entity certificate `leaf.crt` chaining to `root.crt`.
  Validity range (years): 2020-2030.

These certificates are used to test Botan's behavior for verification at
specific time points. For example, verification in 2025 succeeds,
verification in 2031 fails, and verification at 2029 depends on the option.