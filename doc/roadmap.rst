
Development Roadmap
========================================

Near Term Plans
----------------------------------------

Here is an outline for the development plans over the next 12-24 months,
as of May 2024.

Botan 2
---------------

Botan 2 is still supported, but no further feature work is planned.
Only security issues and serious bugs will be addressed.

Botan 3
---------------

The following future work is currently planned for Botan 3:

* BSI Project 481 [https://github.com/randombit/botan/issues/3108]
  will add several new post-quantum algorithms including LMS signatures
  and Classic McEliece.

* New ECC based password authenticated key exchanges, to replace SRP.
  The most likely candidate algorithms are CPace and OPAQUE.

* Adding an implementation of BLS12-381 elliptic curve pairing.

* Low level integer math and elliptic curve arithmetic optimizations.

Botan 4
---------------

At this time there is no immediate plan for a new major version. When it occurs,
it will remove functionality currently marked as deprecated, and adopt a new C++
version. This is unlikely to occur before 2027, at the earliest.

One major change already planned for Botan 4 is that in this release, Public_Key
will no longer derive from Private_Key. And similarly, specific private keys
(for example RSA_PrivateKey) will no longer derive from their corresponding
public key type.
