/*************************************************
* ECDSA Header File                              *
* (C) 2007 Falko Strenzke, FlexSecure GmbH       *
* Defines classes ECDSA_Signature  and           *
* ECDSA_Signature_De/Encoder,                    *
*************************************************/

#ifndef BOTAN_ECDSA_H__
#define BOTAN_ECDSA_H__


#include <botan/bigint.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <iostream>


namespace Botan
  {

  class ECDSA_Signature_Decoder;
  class ECDSA_Signature_Encoder;

  class ECDSA_Signature
    {
      friend class ECDSA_Signature_Decoder;
      friend class ECDSA_Signature_Encoder;
    public:
		ECDSA_Signature(BigInt const& r, BigInt const& s);
      ECDSA_Signature()
      {}
      ;
      ECDSA_Signature(ECDSA_Signature const& other);
      ECDSA_Signature const& operator=(ECDSA_Signature const& other);

      BigInt const get_r() const
        {
          return m_r;
        }
      BigInt const get_s() const
        {
          return m_s;
        }
      /**
       * return the r||s
       */
      SecureVector<byte> const get_concatenation() const;


      std::auto_ptr<ECDSA_Signature_Encoder> x509_encoder() const;
      std::auto_ptr<ECDSA_Signature_Decoder> x509_decoder();
    private:
      BigInt m_r;
      BigInt m_s;
    };

  bool operator== ( ECDSA_Signature const& lhs, ECDSA_Signature const& rhs );
  inline bool operator!= ( ECDSA_Signature const& lhs, ECDSA_Signature const& rhs )
  {
    return !operator== ( lhs, rhs );
  }
  /*SecureVector<byte> ecdsa_signature_to_bytes(ECDSA_Signature const& sig);
  ECDSA_Signature bytes_to_ecdsa_signature(SecureVector<byte> const& sig_bytes);*/



  class ECDSA_Signature_Decoder
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
  class ECDSA_Signature_Encoder
    {
    public:
      MemoryVector<byte> signature_bits() const
        {
          return DER_Encoder()
                 .start_cons(SEQUENCE)
                 .encode(m_signature->m_r)
                 .encode(m_signature->m_s)
                 .end_cons()
                 .get_contents();
        }
      ECDSA_Signature_Encoder(const ECDSA_Signature* signature) : m_signature(signature)
      {}
    private:
      const ECDSA_Signature* m_signature;
    };
  namespace ecdsa
    {
    ECDSA_Signature const decode_seq(MemoryRegion<byte> const& seq);
    ECDSA_Signature const decode_concatenation(MemoryRegion<byte> const& concatenation);
  }
}
#endif
