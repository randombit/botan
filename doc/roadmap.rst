
Botan Development Roadmap
========================================

Near Term Plans
----------------------------------------

Here are the development plans for the next 12-18 months, as of January 2017.

TLS Hardening/Testing
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Improve testing of TLS: leverage TLS-Attacker better, for example using custom
workflows. Add tests using BoringSSL's hacked Go TLS stack.

X509_Certificate Refactor
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The certificate classes use a type called Data_Store which ends up shoving
everything (DN values, extension info, etc) into a single std::multimap<string,string>.
This was a bad design. Instead the certificate type should contain X509_DN
objects for the subject and issuer, an int value for the format version, and so on.
The Data_Store type should be removed entirely.

ASN.1 Redesign
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

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

Expose TLS to C89 and Python
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Exposing TLS to C would allow for many new applications to make use of Botan.

Interface to PSK and SRP databases
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Adding support for databases storing encrypted PSKs and SRP credentials.

Ed25519 signatures
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Used by many protocols these days including SSH and Tor.
Probably will be done by importing from SUPERCOP or similar.

TLS 1.3
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The RFC process seems to be approaching consensus so hopefully there will be a
final spec soon.

The handshake differences are quite substantial, it's an open question how to
implement that without overly complicating the existing TLS v1.0-v1.2 handshake
code. There will also be some API extensions required to support 0-RTT data.

This is a major project, and probably will not start until late in 2017.

Longer View (Future Major Release)
----------------------------------------

Eventually (target is early 2019), Botan 3.x will be released. This
schedule allows some substantial time with Botan 2.x and 3.x supported
simultaneously, to allow for application switch over.

This version will adopt C++17 and use new std types such as
string_view, optional, and any, along with adopting memory span and
guarded integer types. Likely C++17 constexpr will also be leveraged.

In this future 3.x release, all deprecated features/APIs of 2.x will
be removed.
