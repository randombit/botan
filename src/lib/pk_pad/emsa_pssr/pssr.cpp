/*
* PSSR
* (C) 1999-2007,2017 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/pssr.h>
#include <botan/exceptn.h>
#include <botan/rng.h>
#include <botan/mgf1.h>
#include <botan/internal/bit_ops.h>
#include <botan/der_enc.h>
#include <botan/pk_keys.h>
#include <botan/internal/padding.h>

namespace Botan {

namespace {

/*
* PSSR Encode Operation
*/
secure_vector<uint8_t> pss_encode(HashFunction& hash,
                                  const secure_vector<uint8_t>& msg,
                                  const secure_vector<uint8_t>& salt,
                                  size_t output_bits)
   {
   const size_t HASH_SIZE = hash.output_length();
   const size_t SALT_SIZE = salt.size();

   if(msg.size() != HASH_SIZE)
      throw Encoding_Error("Cannot encode PSS string, input length invalid for hash");
   if(output_bits < 8*HASH_SIZE + 8*SALT_SIZE + 9)
      throw Encoding_Error("Cannot encode PSS string, output length too small");

   const size_t output_length = (output_bits + 7) / 8;

   for(size_t i = 0; i != 8; ++i)
      hash.update(0);
   hash.update(msg);
   hash.update(salt);
   secure_vector<uint8_t> H = hash.final();

   secure_vector<uint8_t> EM(output_length);

   EM[output_length - HASH_SIZE - SALT_SIZE - 2] = 0x01;
   buffer_insert(EM, output_length - 1 - HASH_SIZE - SALT_SIZE, salt);
   mgf1_mask(hash, H.data(), HASH_SIZE, EM.data(), output_length - HASH_SIZE - 1);
   EM[0] &= 0xFF >> (8 * ((output_bits + 7) / 8) - output_bits);
   buffer_insert(EM, output_length - 1 - HASH_SIZE, H);
   EM[output_length-1] = 0xBC;
   return EM;
   }

bool pss_verify(HashFunction& hash,
                const secure_vector<uint8_t>& pss_repr,
                const secure_vector<uint8_t>& message_hash,
                size_t key_bits,
                size_t* out_salt_size)
   {
   const size_t HASH_SIZE = hash.output_length();
   const size_t KEY_BYTES = (key_bits + 7) / 8;

   if(key_bits < 8*HASH_SIZE + 9)
      return false;

   if(message_hash.size() != HASH_SIZE)
      return false;

   if(pss_repr.size() > KEY_BYTES || pss_repr.size() <= 1)
      return false;

   if(pss_repr[pss_repr.size()-1] != 0xBC)
      return false;

   secure_vector<uint8_t> coded = pss_repr;
   if(coded.size() < KEY_BYTES)
      {
      secure_vector<uint8_t> temp(KEY_BYTES);
      buffer_insert(temp, KEY_BYTES - coded.size(), coded);
      coded = temp;
      }

   const size_t TOP_BITS = 8 * ((key_bits + 7) / 8) - key_bits;
   if(TOP_BITS > 8 - high_bit(coded[0]))
      return false;

   uint8_t* DB = coded.data();
   const size_t DB_size = coded.size() - HASH_SIZE - 1;

   const uint8_t* H = &coded[DB_size];
   const size_t H_size = HASH_SIZE;

   mgf1_mask(hash, H, H_size, DB, DB_size);
   DB[0] &= 0xFF >> TOP_BITS;

   size_t salt_offset = 0;
   for(size_t j = 0; j != DB_size; ++j)
      {
      if(DB[j] == 0x01)
         { salt_offset = j + 1; break; }
      if(DB[j])
         return false;
      }
   if(salt_offset == 0)
      return false;

   const size_t salt_size = DB_size - salt_offset;

   for(size_t j = 0; j != 8; ++j)
      hash.update(0);
   hash.update(message_hash);
   hash.update(&DB[salt_offset], salt_size);

   const secure_vector<uint8_t> H2 = hash.final();

   const bool ok = constant_time_compare(H, H2.data(), HASH_SIZE);

   if(out_salt_size && ok)
      *out_salt_size = salt_size;

   return ok;
   }

}

PSSR::PSSR(HashFunction* h) :
   m_hash(h),
   m_salt_size(m_hash->output_length()),
   m_required_salt_len(false)
   {
   }

PSSR::PSSR(HashFunction* h, size_t salt_size) :
   m_hash(h),
   m_salt_size(salt_size),
   m_required_salt_len(true)
   {
   }

/*
* PSSR Update Operation
*/
void PSSR::update(const uint8_t input[], size_t length)
   {
   m_hash->update(input, length);
   }

/*
* Return the raw (unencoded) data
*/
secure_vector<uint8_t> PSSR::raw_data()
   {
   return m_hash->final();
   }

secure_vector<uint8_t> PSSR::encoding_of(const secure_vector<uint8_t>& msg,
                                         size_t output_bits,
                                         RandomNumberGenerator& rng)
   {
   const secure_vector<uint8_t> salt = rng.random_vec(m_salt_size);
   return pss_encode(*m_hash, msg, salt, output_bits);
   }

/*
* PSSR Decode/Verify Operation
*/
bool PSSR::verify(const secure_vector<uint8_t>& coded,
                  const secure_vector<uint8_t>& raw,
                  size_t key_bits)
   {
   size_t salt_size = 0;
   const bool ok = pss_verify(*m_hash, coded, raw, key_bits, &salt_size);

   if(m_required_salt_len && salt_size != m_salt_size)
      return false;

   return ok;
   }

EMSA* PSSR::clone()
   {
   return new PSSR(m_hash->clone(), m_salt_size);
   }

std::string PSSR::name() const
   {
   return "EMSA4(" + m_hash->name() + ",MGF1," + std::to_string(m_salt_size) + ")";
   }

AlgorithmIdentifier PSSR::config_for_x509(const Private_Key& key,
                                          const std::string& cert_hash_name) const
   {
   if(cert_hash_name != m_hash->name())
      throw Invalid_Argument("Hash function from opts and hash_fn argument"
         " need to be identical");
   // check that the signature algorithm and the padding scheme fit
   if(!sig_algo_and_pad_ok(key.algo_name(), "EMSA4"))
      {
      throw Invalid_Argument("Encoding scheme with canonical name EMSA4"
         " not supported for signature algorithm " + key.algo_name());
      }

   const AlgorithmIdentifier hash_id(cert_hash_name, AlgorithmIdentifier::USE_NULL_PARAM);
   const AlgorithmIdentifier mgf_id("MGF1", hash_id.BER_encode());

   std::vector<uint8_t> parameters;
   DER_Encoder(parameters)
      .start_cons(SEQUENCE)
      .start_cons(ASN1_Tag(0), CONTEXT_SPECIFIC).encode(hash_id).end_cons()
      .start_cons(ASN1_Tag(1), CONTEXT_SPECIFIC).encode(mgf_id).end_cons()
      .start_cons(ASN1_Tag(2), CONTEXT_SPECIFIC).encode(m_salt_size).end_cons()
      .start_cons(ASN1_Tag(3), CONTEXT_SPECIFIC).encode(size_t(1)).end_cons() // trailer field
      .end_cons();

   // hardcoded as RSA is the only valid algorithm for EMSA4 at the moment
   return AlgorithmIdentifier("RSA/EMSA4", parameters);
   }

PSSR_Raw::PSSR_Raw(HashFunction* h) :
   m_hash(h),
   m_salt_size(m_hash->output_length()),
   m_required_salt_len(false)
   {
   }

PSSR_Raw::PSSR_Raw(HashFunction* h, size_t salt_size) :
   m_hash(h),
   m_salt_size(salt_size),
   m_required_salt_len(true)
   {
   }

/*
* PSSR_Raw Update Operation
*/
void PSSR_Raw::update(const uint8_t input[], size_t length)
   {
   m_msg.insert(m_msg.end(), input, input + length);
   }

/*
* Return the raw (unencoded) data
*/
secure_vector<uint8_t> PSSR_Raw::raw_data()
   {
   secure_vector<uint8_t> ret;
   std::swap(ret, m_msg);

   if(ret.size() != m_hash->output_length())
      throw Encoding_Error("PSSR_Raw Bad input length, did not match hash");

   return ret;
   }

secure_vector<uint8_t> PSSR_Raw::encoding_of(const secure_vector<uint8_t>& msg,
                                             size_t output_bits,
                                             RandomNumberGenerator& rng)
   {
   secure_vector<uint8_t> salt = rng.random_vec(m_salt_size);
   return pss_encode(*m_hash, msg, salt, output_bits);
   }

/*
* PSSR_Raw Decode/Verify Operation
*/
bool PSSR_Raw::verify(const secure_vector<uint8_t>& coded,
                      const secure_vector<uint8_t>& raw,
                      size_t key_bits)
   {
   size_t salt_size = 0;
   const bool ok = pss_verify(*m_hash, coded, raw, key_bits, &salt_size);

   if(m_required_salt_len && salt_size != m_salt_size)
      return false;

   return ok;
   }

EMSA* PSSR_Raw::clone()
   {
   return new PSSR_Raw(m_hash->clone(), m_salt_size);
   }

std::string PSSR_Raw::name() const
   {
   return "PSSR_Raw(" + m_hash->name() + ",MGF1," + std::to_string(m_salt_size) + ")";
   }

}
