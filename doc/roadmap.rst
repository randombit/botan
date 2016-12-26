
Botan Development Roadmap
========================================

Branch Structure
----------------------------------------

Stability of branches is indicated by even or odd minor version numbers. The
minor number of master is always odd, and devel releases come from it. Every
once in a while a new even-numbered branch is forked. All development continues
on the main trunk, with fixes and API compatible features backported to the
stable branch. Stability of API and ABI is very important in the stable
branches, whereas in master ABI changes happen with no warning, and API changes
are made whenever it would serve the ends of justice.

Current Status
----------------------------------------

Currently (as of 2016-11-03) git master is approaching feature freeze for a
stable 2.0 branch by the end of December 2016.

At some point between the final release candidate and the 2.0.0 release, a new
release-2.0 branch will be created off of master. Development will continue on
master (renumbered as 2.1.0), with chosen changes backported to release-2.0
branch.

Theoretically a new development release could be created at any time after this.
But it is likely that for at least several months after branching, most
development will be oriented towards being applied also to 2.0, and so there
will not be any interesting diff between 2.1 and 2.0. At some point when the
divergence grows enough to be 'interesting' a new development release will be
created. These early development releases would only be for experimenters, with
2.0 recommended for general use.

Support Lifetimes
----------------------------------------

Botan 2.0.x will be supported for at least 24 months from the date of 2.0.0
(probably longer)

Botan 1.10.x is supported (for security patches only) through 2017-12-31

All prior versions are no longer supported in any way.


Ongoing Issues
----------------------------------------

Documentation could always use help. Many things are completely undocumented,
few things are documented well.

Plans for 2017
----------------------------------------

It's an open question how many of these will end up being backported to 2.0.x,
versus being features only in 2.1.x development snapshots.

TLS 1.3
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The RFC process seems to be approaching consensus so hopefully there will be a
final spec soon.

The handshake differences are quite substantial, it's an open question how to
implement that without overly complicating the existing TLS v1.0-v1.2 handshake
code. There will also be some API changes to support 0-RTT data.

This is a major project and probably will not start until later in the year.

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

Interface to PSK and SRP databases
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Adding support for databases storing encrypted PSKs and SRP credentials.

Ed25519 signatures
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Used by many protocols these days including SSH and Tor.
Probably will be done by importing from SUPERCOP or similar.
