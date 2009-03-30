/*
* DL Scheme
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_DL_ALGO_H__
#define BOTAN_DL_ALGO_H__

#include <botan/dl_group.h>
#include <botan/x509_key.h>
#include <botan/pkcs8.h>
#include <botan/rng.h>

namespace Botan {

/**
* This class represents discrete logarithm (DL) public keys.
*/
class BOTAN_DLL DL_Scheme_PublicKey : public virtual Public_Key
   {
   public:
      bool check_key(RandomNumberGenerator& rng, bool) const;

      /**
      * Get the DL domain parameters of this key.
      * @return the DL domain parameters of this key
      */
      const DL_Group& get_domain() const { return group; }

      /**
      * Get the public value y with y = g^x mod p where x is the secret key.
      */
      const BigInt& get_y() const { return y; }

      /**
      * Get the prime p of the underlying DL group.
      * @return the prime p
      */
      const BigInt& group_p() const { return group.get_p(); }

      /**
      * Get the prime q of the underlying DL group.
      * @return the prime q
      */
      const BigInt& group_q() const { return group.get_q(); }

      /**
      * Get the generator g of the underlying DL group.
      * @return the generator g
      */
      const BigInt& group_g() const { return group.get_g(); }

      /**
      * Get the underlying groups encoding format.
      * @return the encoding format
      */
      virtual DL_Group::Format group_format() const = 0;

      /**
      * Get an X509 encoder for this key.
      * @return an encoder usable to encode this key.
      */
      X509_Encoder* x509_encoder() const;

      /**
      * Get an X509 decoder for this key.
      * @return an decoder usable to decode a DL key and store the
      * values in this instance.
      */
      X509_Decoder* x509_decoder();
   protected:
      BigInt y;
      DL_Group group;
   private:
      virtual void X509_load_hook() {}
   };

/**
* This class represents discrete logarithm (DL) private keys.
*/
class BOTAN_DLL DL_Scheme_PrivateKey : public virtual DL_Scheme_PublicKey,
                                       public virtual Private_Key
   {
   public:
      bool check_key(RandomNumberGenerator& rng, bool) const;

      /**
      * Get the secret key x.
      * @return the secret key
      */
      const BigInt& get_x() const { return x; }

      /**
      * Get an PKCS#8 encoder for this key.
      * @return an encoder usable to encode this key.
      */
      PKCS8_Encoder* pkcs8_encoder() const;

      /**
      * Get an PKCS#8 decoder for this key.
      * @param rng the rng to use
      * @return an decoder usable to decode a DL key and store the
      * values in this instance.
      */
      PKCS8_Decoder* pkcs8_decoder(RandomNumberGenerator& rng);
   protected:
      BigInt x;
   private:
      virtual void PKCS8_load_hook(RandomNumberGenerator&, bool = false) {}
   };

}

#endif
