Reading List
================

These are papers, articles and books that are interesting or useful from the
perspective of crypto implementation.

Papers
--------

Implementation Techniques
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* "Randomizing the Montgomery Powering Ladder"
  Le, Tan, Tunstall https://eprint.iacr.org/2015/657
  A variant of Algorithm 7 is used for GF(p) point multplications when
  BOTAN_POINTGFP_BLINDED_MULTIPLY_USE_MONTGOMERY_LADDER is set

* "Accelerating AES with vector permute instructions"
  Mike Hamburg https://shiftleft.org/papers/vector_aes/
  His public doman assembly code was rewritten into SSS3 intrinsics
  for aes_ssse3.

* "Elliptic curves and their implementation" Langley
  http://www.imperialviolet.org/2010/12/04/ecc.html
  Describes sparse representations for ECC math

Random Number Generation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* "On Extract-then-Expand Key Derivation Functions and an HMAC-based KDF"
  Hugo Krawczyk http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.131.8254
  RNG design underlying HMAC_RNG

AES Side Channels
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* "Software mitigations to hedge AES against cache-based software side
  channel vulnerabilities" https://eprint.iacr.org/2006/052.pdf

* "Cache Games - Bringing Access-Based Cache Attacks on AES to Practice"
  http://www.ieee-security.org/TC/SP2011/PAPERS/2011/paper031.pdf

* "Cache-Collision Timing Attacks Against AES" Bonneau, Mironov
  http://citeseerx.ist.psu.edu/viewdoc/summary?doi=10.1.1.88.4753

Public Key Side Channels
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* "Fast Elliptic Curve Multiplications Resistant against Side Channel Attacks"
  http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.98.1028&rep=rep1&type=pdf

* "Resistance against Differential Power Analysis for Elliptic Curve Cryptosystems"
  Coron http://www.jscoron.fr/publications/dpaecc.pdf

* "Further Results and Considerations on Side Channel Attacks on RSA"
  Klima, Rosa https://eprint.iacr.org/2002/071
  Side channel attacks on RSA-KEM and MGF1-SHA1

* "Side-Channel Attacks on the McEliece and Niederreiter Public-Key Cryptosystems"
  Avanzi, Hoerder, Page, and Tunstall https://eprint.iacr.org/2010/479

* "Minimum Requirements for Evaluating Side-Channel Attack Resistance
  of Elliptic Curve Implementations" BSI
  https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/Zertifizierung/Interpretationen/AIS_46_ECCGuide_e_pdf.pdf

Books
------

* "Handbook of Elliptic and Hyperelliptic Curve Cryptography"
  Cohen and Frey https://www.hyperelliptic.org/HEHCC/
  An excellent reference for ECC math, algorithms, and side channels

* "Post-Quantum Cryptography" Bernstein, Buchmann, Dahmen
  Covers code, lattice, and hash based cryptography

Standards
-----------

* IEEE 1363 http://grouper.ieee.org/groups/1363/
  Very influential early in the library lifetime, so a lot of terminology used
  in the public key (such as "EME" for message encoding) code comes from here.

* ISO/IEC 18033-2 http://www.shoup.net/iso/std4.pdf
  RSA-KEM, PSEC-KEM

* NIST SP 800-108
  http://csrc.nist.gov/publications/nistpubs/800-108/sp800-108.pdf
  KDF schemes

* NIST SP 800-90A
  http://csrc.nist.gov/publications/nistpubs/800-90A/SP800-90A.pdf
  HMAC_DRBG, Hash_DRBG, CTR_DRBG, maybe one other thing?

