
Development Roadmap
========================================

Near Term Plans
----------------------------------------

Here is an outline of the development plans over the next ~12 months, as of
February 2025.

Botan2
---------------

As of 2025-01-01, Botan2 has reached end of life. No further releases are planned.

Botan3
---------------

The following future work is currently planned for Botan3:

* New ECC based password authenticated key exchanges, to replace SRP.
  The most likely candidate algorithms are SPAKE2(+) and CPace.

* Adding an implementation of BLS12-381 elliptic curve pairing.

* HPKE (RFC 9180)

Botan4
---------------

Botan4 is currently planned for release in 2027.

See the current planning discussion in https://github.com/randombit/botan/issues/4666

One notable change planned for Botan4 is that in that release, Public_Key
will no longer derive from Private_Key. And similarly, specific private keys
(for example RSA_PrivateKey) will no longer derive from their corresponding
public key type.
