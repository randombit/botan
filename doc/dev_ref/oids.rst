Private OID Assignments
==========================

The library uses some OIDs under a private arc assigned by IANA,
1.3.6.1.4.1.25258

Values currently assigned are::

  randombit   OBJECT IDENTIFIER ::= { 1 3 6 1 4 1 25258 }

  publicKey   OBJECT IDENTIFIER ::= { randombit 1 }

  mceliece    OBJECT IDENTIFIER ::= { publicKey 3 }
  -- { publicKey 4 } previously used as private X25519
  -- { publicKey 5 } previously used for XMSS draft 6
  gost-3410-with-sha256 OBJECT IDENTIFIER ::= { publicKey 6 1 }
  kyber       OBJECT IDENTIFIER ::= { publicKey 7 }
  xmss        OBJECT IDENTIFIER ::= { publicKey 8 }

  symmetricKey OBJECT IDENTIFIER ::= { randombit 3 }

  ocbModes OBJECT IDENTIFIER ::= { symmetricKey 2 }

  aes-128-ocb      OBJECT IDENTIFIER ::= { ocbModes 1 }
  aes-192-ocb      OBJECT IDENTIFIER ::= { ocbModes 2 }
  aes-256-ocb      OBJECT IDENTIFIER ::= { ocbModes 3 }
  serpent-256-ocb  OBJECT IDENTIFIER ::= { ocbModes 4 }
  twofish-256-ocb  OBJECT IDENTIFIER ::= { ocbModes 5 }
  camellia-128-ocb OBJECT IDENTIFIER ::= { ocbModes 6 }
  camellia-192-ocb OBJECT IDENTIFIER ::= { ocbModes 7 }
  camellia-256-ocb OBJECT IDENTIFIER ::= { ocbModes 8 }

  sivModes OBJECT IDENTIFIER ::= { symmetricKey 4 }

  aes-128-siv      OBJECT IDENTIFIER ::= { sivModes 1 }
  aes-192-siv      OBJECT IDENTIFIER ::= { sivModes 2 }
  aes-256-siv      OBJECT IDENTIFIER ::= { sivModes 3 }
  serpent-256-siv  OBJECT IDENTIFIER ::= { sivModes 4 }
  twofish-256-siv  OBJECT IDENTIFIER ::= { sivModes 5 }
  camellia-128-siv OBJECT IDENTIFIER ::= { sivModes 6 }
  camellia-192-siv OBJECT IDENTIFIER ::= { sivModes 7 }
  camellia-256-siv OBJECT IDENTIFIER ::= { sivModes 8 }
  sm4-128-siv      OBJECT IDENTIFIER ::= { sivModes 9 }
