
#include <botan/ecdsa_sig.h>
#include <memory>

namespace Botan {

ECDSA_Signature::ECDSA_Signature(const BigInt& r, const BigInt& s)
   : m_r(r),
     m_s(s)
   {}

ECDSA_Signature::ECDSA_Signature(ECDSA_Signature const& other)
   : m_r(other.m_r),
     m_s(other.m_s)
   {}

ECDSA_Signature const& ECDSA_Signature::operator=(ECDSA_Signature const& other)
   {
   m_r = other.m_r;
   m_s = other.m_s;
   return *this;
   }

bool operator== ( ECDSA_Signature const& lhs, ECDSA_Signature const& rhs )
   {
   return (lhs.get_r() == rhs.get_r() && lhs.get_s() == rhs.get_s());
   }

ECDSA_Signature_Decoder* ECDSA_Signature::x509_decoder()
   {
   return new ECDSA_Signature_Decoder(this);
   }

ECDSA_Signature_Encoder* ECDSA_Signature::x509_encoder() const
   {
   return new ECDSA_Signature_Encoder(this);
   }
SecureVector<byte> const ECDSA_Signature::get_concatenation() const
   {
   u32bit enc_len = m_r > m_s ? m_r.bytes() : m_s.bytes(); // use the larger
   SecureVector<byte> sv_r = BigInt::encode_1363 ( m_r, enc_len );
   SecureVector<byte> sv_s = BigInt::encode_1363 ( m_s, enc_len );
   SecureVector<byte> result(sv_r);
   result.append(sv_s);
   return result;
   }

ECDSA_Signature const decode_seq(MemoryRegion<byte> const& seq)
   {
   ECDSA_Signature sig;
   std::auto_ptr<ECDSA_Signature_Decoder> dec(sig.x509_decoder());
   dec->signature_bits(seq);
   return sig;
   }

ECDSA_Signature const decode_concatenation(MemoryRegion<byte> const& concatenation)
   {
   if(concatenation.size() % 2 != 0)
      {
      throw Invalid_Argument("Erroneous length of signature");
      }
   u32bit rs_len = concatenation.size()/2;
   SecureVector<byte> sv_r;
   SecureVector<byte> sv_s;
   sv_r.set(concatenation.begin(), rs_len);
   sv_s.set(&concatenation[rs_len], rs_len);
   BigInt r = BigInt::decode ( sv_r, sv_r.size());
   BigInt s = BigInt::decode (sv_s, sv_s.size());
   return ECDSA_Signature(r, s);
   }

}
