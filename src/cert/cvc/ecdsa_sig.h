/*
* ECDSA
* (C) 2007 Falko Strenzke, FlexSecure GmbH
* (C) 2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_ECDSA_SIGNATURE_H__
#define BOTAN_ECDSA_SIGNATURE_H__

#include <botan/bigint.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>

namespace Botan {

class BOTAN_DLL ECDSA_Signature
   {
   public:
      friend class ECDSA_Signature_Decoder;

      ECDSA_Signature() {}
      ECDSA_Signature(const BigInt& r, const BigInt& s);
      ECDSA_Signature(ECDSA_Signature const& other);
      ECDSA_Signature const& operator=(ECDSA_Signature const& other);

      const BigInt& get_r() const { return m_r; }
      const BigInt& get_s() const { return m_s; }

      /**
      * return the r||s
      */
      SecureVector<byte> const get_concatenation() const;
   private:
      BigInt m_r;
      BigInt m_s;
   };

/* Equality of ECDSA_Signature */
bool operator==(const ECDSA_Signature& lhs, const ECDSA_Signature& rhs);
inline bool operator!=(const ECDSA_Signature& lhs, const ECDSA_Signature& rhs)
   {
   return !(lhs == rhs);
   }

class BOTAN_DLL ECDSA_Signature_Decoder
   {
   public:
      void signature_bits(const MemoryRegion<byte>& bits)
         {
         BER_Decoder(bits)
            .start_cons(SEQUENCE)
            .decode(m_signature->m_r)
            .decode(m_signature->m_s)
            .verify_end()
            .end_cons();
         }
      ECDSA_Signature_Decoder(ECDSA_Signature* signature) : m_signature(signature)
         {}
   private:
      ECDSA_Signature* m_signature;
   };

class BOTAN_DLL ECDSA_Signature_Encoder
   {
   public:
      MemoryVector<byte> signature_bits() const
         {
         return DER_Encoder()
            .start_cons(SEQUENCE)
            .encode(m_signature->get_r())
            .encode(m_signature->get_s())
            .end_cons()
            .get_contents();
         }
      ECDSA_Signature_Encoder(const ECDSA_Signature* signature) : m_signature(signature)
         {}
   private:
      const ECDSA_Signature* m_signature;
   };

ECDSA_Signature const decode_seq(MemoryRegion<byte> const& seq);
ECDSA_Signature const decode_concatenation(MemoryRegion<byte> const& concatenation);

}

#endif
