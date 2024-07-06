Checklist For Next Major Version
==================================

* Remove most/all explicitly deprecated modules, interfaces, and features.
  Check deprecated.rst plus BOTAN_DEPRECATED annotations.

* Make the remaining PasswordHash interfaces internal

* Remove EC_Point/CurveGFp


Big Project: Public Key Split
-------------------------------

Some complications of this aren't going to become clear until we get
into it...

A number of operations currently defined on Public_Key can be
moved to Asymetric_Key, for example key_length and algorithm_identifier.

Due to Private_Key deriving from Public_Key, the fingerprint functions
are oddly named. Otherwise we can't correctly disambiguate sk->fingerprint();
should this be the fingerprint of the public or private key. With the
split we can move this to Asymetric_Key::fingerprint and know that the
correct thing happens.

The public and private key encoding functions (pkcs8.h, x509_key.h)
are also complicated by the combined keys. For example we have to use
PKCS8::PEM_encode(key) because key.PEM_encode() would be ambigious
(similar situation as with the fingerprint APIs currently).  Once the
key types are split, we can move all of this to the key types
themselves, or again (for the shared cases, like unencrypted PEM) to
Asymetric_Key.

Decoding also can become simpler. We could consider moving to a model
that doesn't use DataSource? Maybe just a span even?

Put `_` prefixes on all of the internal operations getters
(create_signature_op, etc)
