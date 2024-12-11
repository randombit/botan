
Development Roadmap
========================================

Near Term Plans
----------------------------------------

Here is an outline of the development plans over the next ~12 months,
as of December 2024.

Botan2
---------------

Botan2 is still supported, but no further feature work is planned.
Only security issues and serious bugs will be addressed.

Currently, Botan2 is scheduled to reach end of life at the end of 2024.

Botan3
---------------

The following future work is currently planned for Botan3:

* New ECC based password authenticated key exchanges, to replace SRP.
  The most likely candidate algorithms are SPAKE2(+) and CPace.

* Adding an implementation of BLS12-381 elliptic curve pairing.

* HPKE (RFC 9180)

Botan4
---------------

At this time there is no immediate plan for a new major version. When it occurs,
it will remove functionality currently marked as deprecated, and adopt a new C++
version. This is unlikely to occur before 2027, at the earliest.

One major change already planned for Botan4 is that in that release, Public_Key
will no longer derive from Private_Key. And similarly, specific private keys
(for example RSA_PrivateKey) will no longer derive from their corresponding
public key type.
