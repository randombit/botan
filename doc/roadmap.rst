
Development Roadmap
========================================

Near Term Plans
----------------------------------------

Here is an outline for the development plans over the next 12-18 months, as of
June 2019.

TLS Hardening/Testing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Leverage TLS-Attacker better, for example using custom workflows. Add
interop testing with OpenSSL as part of CI. Improve fuzzer coverage.

Expose TLS at FFI layer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Exposing TLS to C would allow for many new applications to make use of Botan.

TLS v1.3
^^^^^^^^^^^^^^^

A complete implementation of TLS v1.3 is planned. DTLS v1.3 may or may not be
supported as well.

Botan 3.x
----------------------------------------

Botan 3 is currently planned for release in 2021. Botan 2 will remain
supported for several years past that, to allow plenty of time for
applications to switch over.

This version will adopt C++17 and use new std types such as string_view,
optional, and any, along with adopting memory span and guarded integer
types. All deprecated features/APIs of 2.x (which notably includes TLS v1.0/v1.1
support) will be removed. Beyond explicitly deprecated functionality, there
should be no breaking API changes in the transition to 3.x

Features currently targeted for Botan 3 include

* New post-quantum algorithms: especially a CCA2 secure encryption scheme and a
  lattice-based signature scheme are of interest.

* Password Authenticated Key Exchanges: one or more modern PAKEs
  (such as SPAKE2+ or OPAQUE) to replace SRP.

* Elliptic Curve Pairings: useful in many interesting protocols.
  BN-256 and BLS12-381 seem the most likely.

* New ASN.1 library

Some of these features may end being backported to Botan 2 as well.
