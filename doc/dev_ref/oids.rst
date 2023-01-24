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
