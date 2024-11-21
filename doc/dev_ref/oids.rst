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

  frodokem-shake  OBJECT IDENTIFIER ::= { publicKey 14 }
  efrodokem-shake OBJECT IDENTIFIER ::= { publicKey 16 }
  frodokem-aes    OBJECT IDENTIFIER ::= { publicKey 15 }
  efrodokem-aes   OBJECT IDENTIFIER ::= { publicKey 17 }

  frodokem-640-shake   OBJECT_IDENTIFIER : { frodokem-shake  1  }
  frodokem-976-shake   OBJECT_IDENTIFIER : { frodokem-shake  2  }
  frodokem-1344-shake  OBJECT_IDENTIFIER : { frodokem-shake  3  }
  frodokem-640-aes     OBJECT_IDENTIFIER : { frodokem-aes    1  }
  frodokem-976-aes     OBJECT_IDENTIFIER : { frodokem-aes    2  }
  frodokem-1344-aes    OBJECT_IDENTIFIER : { frodokem-aes    3  }
  efrodokem-640-shake  OBJECT_IDENTIFIER : { efrodokem-shake 1  }
  efrodokem-976-shake  OBJECT_IDENTIFIER : { efrodokem-shake 2  }
  efrodokem-1344-shake OBJECT_IDENTIFIER : { efrodokem-shake 3  }
  efrodokem-640-aes    OBJECT_IDENTIFIER : { efrodokem-aes   1  }
  efrodokem-976-aes    OBJECT_IDENTIFIER : { efrodokem-aes   2  }
  efrodokem-1344-aes   OBJECT_IDENTIFIER : { efrodokem-aes   3  }

  kyber       OBJECT IDENTIFIER ::= { publicKey 7 }
  kyber-90s   OBJECT IDENTIFIER ::= { publicKey 11 }

  kyber-512      OBJECT IDENTIFIER ::= { kyber 1 }
  kyber-768      OBJECT IDENTIFIER ::= { kyber 2 }
  kyber-1024     OBJECT IDENTIFIER ::= { kyber 3 }
  kyber-512-90s  OBJECT IDENTIFIER ::= { kyber-90s 1 }
  kyber-768-90s  OBJECT IDENTIFIER ::= { kyber-90s 2 }
  kyber-1024-90s OBJECT IDENTIFIER ::= { kyber-90s 3 }

  xmss        OBJECT IDENTIFIER ::= { publicKey 8 }

  -- The current dilithium implementation is compatible with the reference
  -- implementation commit 3e9b9f1412f6c7435dbeb4e10692ea58f181ee51
  dilithium     OBJECT IDENTIFIER ::= { publicKey 9 }
  dilithium-aes OBJECT IDENTIFIER ::= { publicKey 10 }

  dilithium-4x4     OBJECT IDENTIFIER ::= { dilithium 1 }
  dilithium-6x5     OBJECT IDENTIFIER ::= { dilithium 2 }
  dilithium-8x7     OBJECT IDENTIFIER ::= { dilithium 3 }
  dilithium-aes-4x4 OBJECT IDENTIFIER ::= { dilithium-aes 1 }
  dilithium-aes-6x5 OBJECT IDENTIFIER ::= { dilithium-aes 2 }
  dilithium-aes-8x7 OBJECT IDENTIFIER ::= { dilithium-aes 3 }

  SphincsPlus OBJECT IDENTIFIER ::= { publicKey 12 }

  SphincsPlus-shake  OBJECT IDENTIFIER ::= { SphincsPlus 1 }
  SphincsPlus-sha2   OBJECT IDENTIFIER ::= { SphincsPlus 2 }
  SphincsPlus-haraka OBJECT IDENTIFIER ::= { SphincsPlus 3 }

  SphincsPlus-shake-128s-r3.1 OBJECT IDENTIFIER ::= { SphincsPlus-shake256 1 }
  SphincsPlus-shake-128f-r3.1  OBJECT IDENTIFIER ::= { SphincsPlus-shake256 2 }
  SphincsPlus-shake-192s-r3.1 OBJECT IDENTIFIER ::= { SphincsPlus-shake256 3 }
  SphincsPlus-shake-192f-r3.1  OBJECT IDENTIFIER ::= { SphincsPlus-shake256 4 }
  SphincsPlus-shake-256s-r3.1 OBJECT IDENTIFIER ::= { SphincsPlus-shake256 5 }
  SphincsPlus-shake-256f-r3.1  OBJECT IDENTIFIER ::= { SphincsPlus-shake256 6 }

  SphincsPlus-sha2-128s-r3.1 OBJECT IDENTIFIER ::= { SphincsPlus-sha256 1 }
  SphincsPlus-sha2-128f-r3.1  OBJECT IDENTIFIER ::= { SphincsPlus-sha256 2 }
  SphincsPlus-sha2-192s-r3.1 OBJECT IDENTIFIER ::= { SphincsPlus-sha256 3 }
  SphincsPlus-sha2-192f-r3.1  OBJECT IDENTIFIER ::= { SphincsPlus-sha256 4 }
  SphincsPlus-sha2-256s-r3.1 OBJECT IDENTIFIER ::= { SphincsPlus-sha256 5 }
  SphincsPlus-sha2-256f-r3.1  OBJECT IDENTIFIER ::= { SphincsPlus-sha256 6 }

  SphincsPlus-haraka-128s-r3.1 OBJECT IDENTIFIER ::= { SphincsPlus-haraka 1 }
  SphincsPlus-haraka-128f-r3.1  OBJECT IDENTIFIER ::= { SphincsPlus-haraka 2 }
  SphincsPlus-haraka-192s-r3.1 OBJECT IDENTIFIER ::= { SphincsPlus-haraka 3 }
  SphincsPlus-haraka-192f-r3.1  OBJECT IDENTIFIER ::= { SphincsPlus-haraka 4 }
  SphincsPlus-haraka-256s-r3.1 OBJECT IDENTIFIER ::= { SphincsPlus-haraka 5 }
  SphincsPlus-haraka-256f-r3.1  OBJECT IDENTIFIER ::= { SphincsPlus-haraka 6 }

  HSS-LMS-Private-Key OBJECT IDENTIFIER ::= { publicKey 13 }

  mceliece OBJECT IDENTIFIER ::= { publicKey 18 }

  mceliece6688128pc   OBJECT IDENTIFIER ::= { mceliece 1 }
  mceliece6688128pcf  OBJECT IDENTIFIER ::= { mceliece 2 }
  mceliece6960119pc   OBJECT IDENTIFIER ::= { mceliece 3 }
  mceliece6960119pcf  OBJECT IDENTIFIER ::= { mceliece 4 }
  mceliece8192128pc   OBJECT IDENTIFIER ::= { mceliece 5 }
  mceliece8192128pcf  OBJECT IDENTIFIER ::= { mceliece 6 }

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

  ellipticCurve OBJECT IDENTIFIER ::= { randombit 4 }

  numsp256d1     OBJECT IDENTIFIER ::= { ellipticCurve 1 }
  numsp384d1     OBJECT IDENTIFIER ::= { ellipticCurve 2 }
  numsp512d1     OBJECT IDENTIFIER ::= { ellipticCurve 3 }

  -- These are just for testing purposes internally in the library
  -- and are not included in oids.txt
  sm2test     OBJECT IDENTIFIER ::= { ellipticCurve 5459250 }
  iso18003    OBJECT IDENTIFIER ::= { ellipticCurve 18003 }
