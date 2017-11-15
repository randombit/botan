
Botan Development Roadmap
========================================

Near Term Plans
----------------------------------------

Here is an outline for the development plans over the next 12-18 months, as of
November 2017.

TLS Hardening/Testing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Leverage TLS-Attacker better, for example using custom workflows. Add tests
using BoringSSL's hacked Go TLS stack. Add interop testing with OpenSSL as part
of CI. Improve fuzzer coverage.

Expose TLS to C89 and Python
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Exposing TLS to C would allow for many new applications to make use of Botan.

Interface to PSK and SRP databases
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Adding support for databases storing encrypted PSKs and SRP credentials.

ECC Refactoring
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Refactoring how elliptic curve groups are stored, sharing representation and
allowing better precomputations (eg precomputing base point multiples).

Performance Improvements
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The eventual goal would be performance parity with OpenSSL, but initial
target is probably more like "no worse than 30% slower for any algorithm".

Elliptic Curve Pairings
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

These are useful in many interesting protocols. Initially BN curves are the main
target (particularly BN-256 for compatability with Go's bn256 module) but likely
we'll also want BLS curves.

TLS 1.3
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The RFC process seems to be approaching consensus so hopefully there will be a
final spec soon. The handshake differences are quite substantial, it's an open
question how to implement that without overly complicating the existing TLS
v1.0-v1.2 handshake code. There will also be some API extensions required to
support 0-RTT data.

Initial work is focused on features which are included in TLS v1.3 but also
available for TLS v1.2 (such as PSS signatures and FFDHE) as well as
refactorings which will make the eventual implementation of v1.3 simpler.
Assuming no source of dedicated funding appears, a full v1.3 implementation will
likely not available until late in 2018.

ASN.1 Redesign
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. note::

   This project has been deferred to 3.x as constexpr will likely make it
   much easier to implement.

The current ASN.1 library (DER_Encoder/BER_Decoder) does make it
roughly possible to write C++ code matching the ASN.1 structures. But
it is not flexible enough for all cases and makes many unnecessary
copies (and thus memory allocations) of the data as it works.

It would be better to have a system that used (a simple subset of) ASN.1 to
define the types as well as encoding/decoding logic. Then new types could be
easily defined. This could also obviate the current code for handling OIDs, and
allow representing the OIDs using the natural OID tree syntax of ASN.1.

Another important feature will be supporting copy-free streaming decoding. That
is, given a (ptr,len) range the decoding operation either returns an error
(throws exception) or else the decoded object plus the number of bytes after ptr
that contain the object, and it does so without making any allocations or
copies.

It will probably be easier to be consistently allocation free in machine
generated code, so the two goals of the redesign seem to reinforce each other.

Longer View (Future Major Release)
----------------------------------------

Eventually (currently estimated for summer 2019), Botan 3.x will be
released. This schedule allows some substantial time with Botan 2.x and 3.x
supported simultaneously, to allow for application switch over.

This version will adopt C++17 and use new std types such as string_view,
optional, and any, along with adopting memory span and guarded integer
types. Likely C++17 constexpr will also be leveraged.

In this future 3.x release, all deprecated features/APIs of 2.x will be removed.
However outside of that, breaking API changes should be relatively minimal.
