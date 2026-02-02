
Development Roadmap
========================================

Near Term Plans
----------------------------------------

Here is an outline of the development plans over the next ~12 months, as of
February 2026.

Botan2
---------------

As of 2025-01-01, Botan2 has reached end of life. No further releases are planned.

Botan3
---------------

The following major feature work is currently planned for Botan3:

* SPAKE2+ password authenticated key exchange
* BLS12-381
* HPKE (RFC 9180)
* XMSS^MT
* HQC, possibly implemented using Rust

Along with the usual optimizations, bug fixes, and refinements.

Botan4
---------------

Botan4 is currently planned for release in 2027.

See the current planning discussion in https://github.com/randombit/botan/issues/4666

Botan4 will continue using C++20 rather than adopting a more recent language version.

Botan4 is expected to be largely a subtractive major release;
deprecated APIs and functionality will be removed, with few additions.

One notable change planned for Botan4 is that in that release, Public_Key
will no longer derive from Private_Key. And similarly, specific private keys
(for example RSA_PrivateKey) will no longer derive from their corresponding
public key type.
