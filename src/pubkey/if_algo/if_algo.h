/*
* IF Scheme
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_IF_ALGO_H__
#define BOTAN_IF_ALGO_H__

#include <botan/if_core.h>
#include <botan/x509_key.h>
#include <botan/pkcs8.h>

namespace Botan {

/**
* This class represents public keys
* of integer factorization based (IF) public key schemes.
*/
class BOTAN_DLL IF_Scheme_PublicKey : public virtual Public_Key
   {
   public:
      bool check_key(RandomNumberGenerator& rng, bool) const;

      /**
      * Get n = p * q.
      * @return n
      */
      const BigInt& get_n() const { return n; }

      /**
      * Get the public exponent used by the key.
      * @return the public exponent
      */
      const BigInt& get_e() const { return e; }

      u32bit max_input_bits() const { return (n.bits() - 1); }

      X509_Encoder* x509_encoder() const;
      X509_Decoder* x509_decoder();
   protected:
      virtual void X509_load_hook();
      BigInt n, e;
      IF_Core core;
   };

/**
* This class represents public keys
* of integer factorization based (IF) public key schemes.
*/
class BOTAN_DLL IF_Scheme_PrivateKey : public virtual IF_Scheme_PublicKey,
                                       public virtual Private_Key
   {
   public:
      bool check_key(RandomNumberGenerator& rng, bool) const;

      /**
      * Get the first prime p.
      * @return the prime p
      */
      const BigInt& get_p() const { return p; }

      /**
      * Get the second prime q.
      * @return the prime q
      */
      const BigInt& get_q() const { return q; }

      /**
      * Get d with exp * d = 1 mod (p - 1, q - 1).
      * @return d
      */
      const BigInt& get_d() const { return d; }

      PKCS8_Encoder* pkcs8_encoder() const;
      PKCS8_Decoder* pkcs8_decoder(RandomNumberGenerator&);
   protected:
      virtual void PKCS8_load_hook(RandomNumberGenerator&, bool = false);
      BigInt d, p, q, d1, d2, c;
   };

}

#endif
