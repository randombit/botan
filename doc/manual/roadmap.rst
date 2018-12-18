
Development Roadmap
========================================

Near Term Plans
----------------------------------------

Here is an outline for the development plans over the next 12-18 months, as of
December 2018.

TLS Hardening/Testing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Leverage TLS-Attacker better, for example using custom workflows. Add tests
using BoringSSL's hacked Go TLS stack. Add interop testing with OpenSSL as part
of CI. Improve fuzzer coverage.

Expose TLS at FFI layer
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Exposing TLS to C would allow for many new applications to make use of Botan.

Multiparty Computation
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Threshold key generation and signature schemes, homomorphic encryption, basic
ZKP proof systems.

Post-Quantum CCA2 Encryption
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Which scheme(s) to implement is open to question. HRSS is one possiblity.
But providing at least one PQ-secure CCA2 encryption scheme would be very
useful for TLS, PGP, and other protocols.

Password Authenticated Key Exchanges
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Adding support for modern PAKE algorithms (such as SPAKE2+ or OPAQUE),
including encrypted database backed storage for verifiers.

Elliptic Curve Pairings
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These are useful in many interesting protocols. Initially BN curves are the main
target (particularly BN-256 for compatibility with Go's bn256 module) but likely
we'll also want BLS curves.

And possibly some functionality built on top of pairings, such as identity based
encryption.

TLS 1.3
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The handshake differences in v1.3 are quite substantial and it's an open
question how to implement that without overly complicating the existing TLS
v1.0-v1.2 handshake code. Assuming no source of dedicated funding appears, a
full v1.3 implementation will likely not be available until at least Q4 2019.

ASN.1 Redesign
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Design and build a new ASN.1 encoding/decoding library which is easier to use
and more efficient (fewer memory copies, etc). For at least 2.x this new ASN.1
code will exist in parallel with the existing library to avoid breaking applications.

Longer View (Future Major Release)
----------------------------------------

Eventually (currently estimated for mid 2020), Botan 3.x will be released.
This schedule allows some substantial time with Botan 2.x and 3.x supported
simultaneously, to allow for application switch over.

This version will adopt C++17 and use new std types such as string_view,
optional, and any, along with adopting memory span and guarded integer
types. Likely C++17 constexpr will also be leveraged.

In this future 3.x release, all deprecated features/APIs of 2.x (which notably
includes TLS v1.0/v1.1 support) will be removed. Beyond explicitly deprecated
functionality, there should be no breaking API changes in the transition to 3.x
