/*
 * (C) Copyright Projet SECRET, INRIA, Rocquencourt
 * (C) Bhaskar Biswas and  Nicolas Sendrier
 *
 * (C) 2014 cryptosource GmbH
 * (C) 2014 Falko Strenzke fstrenzke@cryptosource.de
 * (C) 2015 Jack Lloyd
 *
 * Botan is released under the Simplified BSD License (see license.txt)
 *
 */

#include <botan/mceliece.h>
#include <botan/polyn_gf2m.h>
#include <botan/internal/mce_internal.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/code_based_util.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/loadstor.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/rng.h>

namespace Botan {

McEliece_PrivateKey::McEliece_PrivateKey(polyn_gf2m const& goppa_polyn,
                                         std::vector<uint32_t> const& parity_check_matrix_coeffs,
                                         std::vector<polyn_gf2m> const& square_root_matrix,
                                         std::vector<gf2m> const& inverse_support,
                                         std::vector<uint8_t> const& public_matrix) :
   McEliece_PublicKey(public_matrix, goppa_polyn.get_degree(), inverse_support.size()),
   m_g{goppa_polyn},
   m_sqrtmod(square_root_matrix),
   m_Linv(inverse_support),
   m_coeffs(parity_check_matrix_coeffs),
   m_codimension(static_cast<size_t>(ceil_log2(inverse_support.size())) * goppa_polyn.get_degree()),
   m_dimension(inverse_support.size() - m_codimension)
   {
   }

McEliece_PrivateKey::McEliece_PrivateKey(RandomNumberGenerator& rng, size_t code_length, size_t t)
   {
   uint32_t ext_deg = ceil_log2(code_length);
   *this = generate_mceliece_key(rng, ext_deg, code_length, t);
   }

McEliece_PrivateKey::~McEliece_PrivateKey() = default;

const polyn_gf2m& McEliece_PrivateKey::get_goppa_polyn() const
   {
   return m_g[0];
   }

size_t McEliece_PublicKey::get_message_word_bit_length() const
   {
   size_t codimension = ceil_log2(m_code_length) * m_t;
   return m_code_length - codimension;
   }

secure_vector<uint8_t> McEliece_PublicKey::random_plaintext_element(RandomNumberGenerator& rng) const
   {
   const size_t bits = get_message_word_bit_length();

   secure_vector<uint8_t> plaintext((bits+7)/8);
   rng.randomize(plaintext.data(), plaintext.size());

   // unset unused bits in the last plaintext byte
   if(uint32_t used = bits % 8)
      {
      const uint8_t mask = (1 << used) - 1;
      plaintext[plaintext.size() - 1] &= mask;
      }

   return plaintext;
   }

AlgorithmIdentifier McEliece_PublicKey::algorithm_identifier() const
   {
   return AlgorithmIdentifier(get_oid(), AlgorithmIdentifier::USE_EMPTY_PARAM);
   }

std::vector<uint8_t> McEliece_PublicKey::public_key_bits() const
   {
   std::vector<uint8_t> output;
   DER_Encoder(output)
      .start_cons(SEQUENCE)
         .start_cons(SEQUENCE)
         .encode(static_cast<size_t>(get_code_length()))
         .encode(static_cast<size_t>(get_t()))
         .end_cons()
      .encode(m_public_matrix, OCTET_STRING)
      .end_cons();
   return output;
   }

size_t McEliece_PublicKey::key_length() const
   {
   return m_code_length;
   }

size_t McEliece_PublicKey::estimated_strength() const
   {
   return mceliece_work_factor(m_code_length, m_t);
   }

McEliece_PublicKey::McEliece_PublicKey(const std::vector<uint8_t>& key_bits)
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

secure_vector<uint8_t> McEliece_PrivateKey::private_key_bits() const
   {
   DER_Encoder enc;
   enc.start_cons(SEQUENCE)
      .start_cons(SEQUENCE)
      .encode(static_cast<size_t>(get_code_length()))
      .encode(static_cast<size_t>(get_t()))
      .end_cons()
      .encode(m_public_matrix, OCTET_STRING)
      .encode(m_g[0].encode(), OCTET_STRING); // g as octet string
   enc.start_cons(SEQUENCE);
   for(size_t i = 0; i < m_sqrtmod.size(); i++)
      {
      enc.encode(m_sqrtmod[i].encode(), OCTET_STRING);
      }
   enc.end_cons();
   secure_vector<uint8_t> enc_support;

   for(uint16_t Linv : m_Linv)
      {
      enc_support.push_back(get_byte(0, Linv));
      enc_support.push_back(get_byte(1, Linv));
      }
   enc.encode(enc_support, OCTET_STRING);
   secure_vector<uint8_t> enc_H;
   for(uint32_t coef : m_coeffs)
      {
      enc_H.push_back(get_byte(0, coef));
      enc_H.push_back(get_byte(1, coef));
      enc_H.push_back(get_byte(2, coef));
      enc_H.push_back(get_byte(3, coef));
      }
   enc.encode(enc_H, OCTET_STRING);
   enc.end_cons();
   return enc.get_contents();
   }

bool McEliece_PrivateKey::check_key(RandomNumberGenerator& rng, bool) const
   {
   const secure_vector<uint8_t> plaintext = this->random_plaintext_element(rng);

   secure_vector<uint8_t> ciphertext;
   secure_vector<uint8_t> errors;
   mceliece_encrypt(ciphertext, errors, plaintext, *this, rng);

   secure_vector<uint8_t> plaintext_out;
   secure_vector<uint8_t> errors_out;
   mceliece_decrypt(plaintext_out, errors_out, ciphertext, *this);

   if(errors != errors_out || plaintext != plaintext_out)
      return false;

   return true;
   }

McEliece_PrivateKey::McEliece_PrivateKey(const secure_vector<uint8_t>& key_bits)
   {
   size_t n, t;
   secure_vector<uint8_t> enc_g;
   BER_Decoder dec_base(key_bits);
   BER_Decoder dec = dec_base.start_cons(SEQUENCE)
      .start_cons(SEQUENCE)
      .decode(n)
      .decode(t)
      .end_cons()
      .decode(m_public_matrix, OCTET_STRING)
      .decode(enc_g, OCTET_STRING);

   if(t == 0 || n == 0)
      throw Decoding_Error("invalid McEliece parameters");

   uint32_t ext_deg = ceil_log2(n);
   m_code_length = n;
   m_t = t;
   m_codimension = (ext_deg * t);
   m_dimension = (n - m_codimension);

   std::shared_ptr<GF2m_Field> sp_field(new GF2m_Field(ext_deg));
   m_g = { polyn_gf2m(enc_g, sp_field) };
   if(m_g[0].get_degree() != static_cast<int>(t))
      {
      throw Decoding_Error("degree of decoded Goppa polynomial is incorrect");
      }
   BER_Decoder dec2 = dec.start_cons(SEQUENCE);
   for(uint32_t i = 0; i < t/2; i++)
      {
      secure_vector<uint8_t> sqrt_enc;
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
   secure_vector<uint8_t> enc_support;
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
   for(uint32_t i = 0; i < n*2; i+=2)
      {
      gf2m el = (enc_support[i] << 8) |  enc_support[i+1];
      m_Linv.push_back(el);
      }
   secure_vector<uint8_t> enc_H;
   dec3.decode(enc_H, OCTET_STRING)
      .end_cons();
   if(enc_H.size() % 4)
      {
      throw Decoding_Error("encoded parity check matrix has length which is not a multiple of four");
      }
   if(enc_H.size() / 4 != bit_size_to_32bit_size(m_codimension) * m_code_length)
      {
      throw Decoding_Error("encoded parity check matrix has wrong length");
      }

   for(uint32_t i = 0; i < enc_H.size(); i+=4)
      {
      uint32_t coeff = (enc_H[i] << 24) | (enc_H[i+1] << 16) | (enc_H[i+2] << 8) | enc_H[i+3];
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
   if(m_t != other.m_t)
      {
      return false;
      }
   if( m_code_length != other.m_code_length)
      {
      return false;
      }
   return true;
   }

namespace {

class MCE_KEM_Encryptor final : public PK_Ops::KEM_Encryption_with_KDF
   {
   public:

      MCE_KEM_Encryptor(const McEliece_PublicKey& key,
                        const std::string& kdf) :
         KEM_Encryption_with_KDF(kdf), m_key(key) {}

   private:
      void raw_kem_encrypt(secure_vector<uint8_t>& out_encapsulated_key,
                           secure_vector<uint8_t>& raw_shared_key,
                           Botan::RandomNumberGenerator& rng) override
         {
         secure_vector<uint8_t> plaintext = m_key.random_plaintext_element(rng);

         secure_vector<uint8_t> ciphertext, error_mask;
         mceliece_encrypt(ciphertext, error_mask, plaintext, m_key, rng);

         raw_shared_key.clear();
         raw_shared_key += plaintext;
         raw_shared_key += error_mask;

         out_encapsulated_key.swap(ciphertext);
         }

      const McEliece_PublicKey& m_key;
   };

class MCE_KEM_Decryptor final : public PK_Ops::KEM_Decryption_with_KDF
   {
   public:

      MCE_KEM_Decryptor(const McEliece_PrivateKey& key,
                        const std::string& kdf) :
         KEM_Decryption_with_KDF(kdf), m_key(key) {}

   private:
      secure_vector<uint8_t>
      raw_kem_decrypt(const uint8_t encap_key[], size_t len) override
         {
         secure_vector<uint8_t> plaintext, error_mask;
         mceliece_decrypt(plaintext, error_mask, encap_key, len, m_key);

         secure_vector<uint8_t> output;
         output.reserve(plaintext.size() + error_mask.size());
         output.insert(output.end(), plaintext.begin(), plaintext.end());
         output.insert(output.end(), error_mask.begin(), error_mask.end());
         return output;
         }

      const McEliece_PrivateKey& m_key;
   };

}

std::unique_ptr<PK_Ops::KEM_Encryption>
McEliece_PublicKey::create_kem_encryption_op(RandomNumberGenerator& /*rng*/,
                                             const std::string& params,
                                             const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::KEM_Encryption>(new MCE_KEM_Encryptor(*this, params));
   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::KEM_Decryption>
McEliece_PrivateKey::create_kem_decryption_op(RandomNumberGenerator& /*rng*/,
                                              const std::string& params,
                                              const std::string& provider) const
   {
   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::KEM_Decryption>(new MCE_KEM_Decryptor(*this, params));
   throw Provider_Not_Found(algo_name(), provider);
   }

}


