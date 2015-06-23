/**
 * (C) Copyright Projet SECRET, INRIA, Rocquencourt
 * (C) Bhaskar Biswas and  Nicolas Sendrier
 *
 * (C) 2014 cryptosource GmbH
 * (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 *
 */

#include <botan/mceliece_key.h>
#include <botan/internal/bit_ops.h>
#include <botan/gf2m_small_m.h>
#include <botan/mceliece.h>
#include <botan/internal/code_based_key_gen.h>
#include <botan/code_based_util.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/workfactor.h>

namespace Botan {

McEliece_PrivateKey::McEliece_PrivateKey(polyn_gf2m const& goppa_polyn,
                                         std::vector<u32bit> const& parity_check_matrix_coeffs,
                                         std::vector<polyn_gf2m> const& square_root_matrix,
                                         std::vector<gf2m> const& inverse_support,
                                         std::vector<byte> const& public_matrix) :
   McEliece_PublicKey(public_matrix, goppa_polyn.get_degree(), inverse_support.size()),
   m_g(goppa_polyn),
   m_sqrtmod(square_root_matrix),
   m_Linv(inverse_support),
   m_coeffs(parity_check_matrix_coeffs),
   m_codimension(ceil_log2(inverse_support.size()) * goppa_polyn.get_degree()),
   m_dimension(inverse_support.size() - m_codimension)
   {
   };

McEliece_PrivateKey::McEliece_PrivateKey(RandomNumberGenerator& rng, size_t code_length, size_t t)
   {
   u32bit ext_deg = ceil_log2(code_length);
   *this = generate_mceliece_key(rng, ext_deg, code_length, t);
   }

unsigned McEliece_PublicKey::get_message_word_bit_length() const
   {
   u32bit codimension = ceil_log2(m_code_length) * m_t;
   return m_code_length - codimension;
   }

AlgorithmIdentifier McEliece_PublicKey::algorithm_identifier() const
   {
   return AlgorithmIdentifier(get_oid(), std::vector<byte>());
   }

std::vector<byte> McEliece_PublicKey::x509_subject_public_key() const
   {
   // encode the public key
   return unlock(DER_Encoder()
                 .start_cons(SEQUENCE)
                 .start_cons(SEQUENCE)
                 .encode(static_cast<size_t>(get_code_length()))
                 .encode(static_cast<size_t>(get_t()))
                 .end_cons()
                 .encode(m_public_matrix, OCTET_STRING)
                 .end_cons()
                 .get_contents());
   }

McEliece_PublicKey::McEliece_PublicKey(const McEliece_PublicKey & other) :
   m_public_matrix(other.m_public_matrix),
   m_t(other.m_t),
   m_code_length(other.m_code_length)
   {
   }

size_t McEliece_PublicKey::estimated_strength() const
   {
   const u32bit ext_deg = ceil_log2(m_code_length);
   const size_t k = m_code_length - ext_deg * m_t;
   return mceliece_work_factor(m_code_length, k, m_t);
   }

McEliece_PublicKey::McEliece_PublicKey(const std::vector<byte>& key_bits)
   {
   BER_Decoder dec(key_bits);
   size_t n;
   size_t t;
   dec.start_cons(SEQUENCE)
      .start_cons(SEQUENCE)
      .decode(n)
      .decode(t)
      .end_cons()
      .decode(m_public_matrix, OCTET_STRING)
      .end_cons();
   m_t = t;
   m_code_length = n;
   }

secure_vector<byte> McEliece_PrivateKey::pkcs8_private_key() const
   {
   DER_Encoder enc;
   enc.start_cons(SEQUENCE)
      .start_cons(SEQUENCE)
      .encode(static_cast<size_t>(get_code_length()))
      .encode(static_cast<size_t>(get_t()))
      .end_cons()
      .encode(m_public_matrix, OCTET_STRING)
      .encode(m_g.encode(), OCTET_STRING); // g as octet string
   enc.start_cons(SEQUENCE);
   for(u32bit i = 0; i < m_sqrtmod.size(); i++)
      {
      enc.encode(m_sqrtmod[i].encode(), OCTET_STRING);
      }
   enc.end_cons();
   secure_vector<byte> enc_support;
   for(u32bit i = 0; i < m_Linv.size(); i++)
      {
      enc_support.push_back(m_Linv[i] >> 8);
      enc_support.push_back(m_Linv[i]);
      }
   enc.encode(enc_support, OCTET_STRING);
   secure_vector<byte> enc_H;
   for(u32bit i = 0; i < m_coeffs.size(); i++)
      {
      enc_H.push_back(m_coeffs[i] >> 24);
      enc_H.push_back(m_coeffs[i] >> 16);
      enc_H.push_back(m_coeffs[i] >> 8);
      enc_H.push_back(m_coeffs[i]);
      }
   enc.encode(enc_H, OCTET_STRING);
   enc.end_cons();
   return enc.get_contents();
   }

bool McEliece_PrivateKey::check_key(RandomNumberGenerator& rng, bool) const
   {
   McEliece_Private_Operation priv_op(*this);
   McEliece_Public_Operation pub_op(*this, get_code_length());

   secure_vector<byte> plaintext((this->get_message_word_bit_length()+7)/8);
   rng.randomize(plaintext.data(), plaintext.size() - 1);
   const secure_vector<gf2m> err_pos = create_random_error_positions(this->get_code_length(), this->get_t(), rng);

   mceliece_message_parts parts(err_pos, plaintext, this->get_code_length());
   secure_vector<byte> message_and_error_input = parts.get_concat();
   secure_vector<byte> ciphertext = pub_op.encrypt(message_and_error_input.data(), message_and_error_input.size(), rng);
   secure_vector<byte> message_and_error_output = priv_op.decrypt(ciphertext.data(), ciphertext.size());

   return (message_and_error_input == message_and_error_output);
   }

McEliece_PrivateKey::McEliece_PrivateKey(const secure_vector<byte>& key_bits)
   {
   size_t n, t;
   secure_vector<byte> g_enc;
   BER_Decoder dec_base(key_bits);
   BER_Decoder dec = dec_base.start_cons(SEQUENCE)
      .start_cons(SEQUENCE)
      .decode(n)
      .decode(t)
      .end_cons()
      .decode(m_public_matrix, OCTET_STRING)
      .decode(g_enc, OCTET_STRING);

   if(t == 0 || n == 0)
      throw Decoding_Error("invalid McEliece parameters");

   u32bit ext_deg = ceil_log2(n);
   m_code_length = n;
   m_t = t;
   m_codimension = (ext_deg * t);
   m_dimension = (n - m_codimension);

   std::shared_ptr<gf2m_small_m::Gf2m_Field> sp_field(new gf2m_small_m::Gf2m_Field(ext_deg));
   m_g = polyn_gf2m(g_enc, sp_field);
   if(m_g.get_degree() != static_cast<int>(t))
      {
      throw Decoding_Error("degree of decoded Goppa polynomial is incorrect");
      }
   BER_Decoder dec2 = dec.start_cons(SEQUENCE);
   for(u32bit i = 0; i < t/2; i++)
      {
      secure_vector<byte> sqrt_enc;
      dec2.decode(sqrt_enc, OCTET_STRING);
      while(sqrt_enc.size() < (t*2))
         {
         // ensure that the length is always t
         sqrt_enc.push_back(0);
         sqrt_enc.push_back(0);
         }
      if(sqrt_enc.size() != t*2)
         {
         throw Decoding_Error("length of square root polynomial entry is too large");
         }
      m_sqrtmod.push_back(polyn_gf2m(sqrt_enc, sp_field));
      }
   secure_vector<byte> enc_support;
   BER_Decoder dec3 = dec2.end_cons()
      .decode(enc_support, OCTET_STRING);
   if(enc_support.size() % 2)
      {
      throw Decoding_Error("encoded support has odd length");
      }
   if(enc_support.size() / 2 != n)
      {
      throw Decoding_Error("encoded support has length different from code length");
      }
   for(u32bit i = 0; i < n*2; i+=2)
      {
      gf2m el = (enc_support[i] << 8) |  enc_support[i+1];
      m_Linv.push_back(el);
      }
   secure_vector<byte> enc_H;
   dec3.decode(enc_H, OCTET_STRING)
      .end_cons();
   if(enc_H.size() % 4)
      {
      throw Decoding_Error("encoded parity check matrix has length which is not a multiple of four");
      }
   if(enc_H.size()/4 != bit_size_to_32bit_size(m_codimension) * m_code_length )
      {
      throw Decoding_Error("encoded parity check matrix has wrong length");
      }

   for(u32bit i = 0; i < enc_H.size(); i+=4)
      {
      u32bit coeff = (enc_H[i] << 24) | (enc_H[i+1] << 16) | (enc_H[i+2] << 8) | enc_H[i+3];
      m_coeffs.push_back(coeff);
      }

   }


bool McEliece_PrivateKey::operator==(const McEliece_PrivateKey & other) const
   {
   if(*static_cast<const McEliece_PublicKey*>(this) != *static_cast<const McEliece_PublicKey*>(&other))
      {
      return false;
      }
   if(m_g != other.m_g)
      {
      return false;
      }

   if( m_sqrtmod != other.m_sqrtmod)
      {
      return false;
      }
   if( m_Linv != other.m_Linv)
      {
      return false;
      }
   if( m_coeffs != other.m_coeffs)
      {
      return false;
      }

   if(m_codimension != other.m_codimension || m_dimension != other.m_dimension)
      {
      return false;
      }

   return true;
   }

bool McEliece_PublicKey::operator==(const McEliece_PublicKey& other) const
   {
   if(m_public_matrix != other.m_public_matrix)
      {
      return false;
      }
   if(m_t != other.m_t )
      {
      return false;
      }
   if( m_code_length != other.m_code_length)
      {
      return false;
      }
   return true;
   }

}


