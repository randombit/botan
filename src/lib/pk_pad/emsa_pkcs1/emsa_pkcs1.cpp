/*
* PKCS #1 v1.5 signature padding
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/emsa_pkcs1.h>
#include <botan/hash_id.h>
#include <botan/exceptn.h>
#include <botan/pk_keys.h>
#include <botan/internal/padding.h>

namespace Botan {

namespace {

secure_vector<uint8_t> emsa3_encoding(const secure_vector<uint8_t>& msg,
                                   size_t output_bits,
                                   const uint8_t hash_id[],
                                   size_t hash_id_length)
   {
   size_t output_length = output_bits / 8;
   if(output_length < hash_id_length + msg.size() + 10)
      throw Encoding_Error("emsa3_encoding: Output length is too small");

   secure_vector<uint8_t> T(output_length);
   const size_t P_LENGTH = output_length - msg.size() - hash_id_length - 2;

   T[0] = 0x01;
   set_mem(&T[1], P_LENGTH, 0xFF);
   T[P_LENGTH+1] = 0x00;

   if(hash_id_length > 0)
      {
      BOTAN_ASSERT_NONNULL(hash_id);
      buffer_insert(T, P_LENGTH+2, hash_id, hash_id_length);
      }

   buffer_insert(T, output_length-msg.size(), msg.data(), msg.size());
   return T;
   }

}

void EMSA_PKCS1v15::update(const uint8_t input[], size_t length)
   {
   m_hash->update(input, length);
   }

secure_vector<uint8_t> EMSA_PKCS1v15::raw_data()
   {
   return m_hash->final();
   }

secure_vector<uint8_t>
EMSA_PKCS1v15::encoding_of(const secure_vector<uint8_t>& msg,
                           size_t output_bits,
                           RandomNumberGenerator&)
   {
   if(msg.size() != m_hash->output_length())
      throw Encoding_Error("EMSA_PKCS1v15::encoding_of: Bad input length");

   return emsa3_encoding(msg, output_bits,
                         m_hash_id.data(), m_hash_id.size());
   }

bool EMSA_PKCS1v15::verify(const secure_vector<uint8_t>& coded,
                           const secure_vector<uint8_t>& raw,
                           size_t key_bits)
   {
   if(raw.size() != m_hash->output_length())
      return false;

   try
      {
      return (coded == emsa3_encoding(raw, key_bits,
                                      m_hash_id.data(), m_hash_id.size()));
      }
   catch(...)
      {
      return false;
      }
   }

AlgorithmIdentifier EMSA_PKCS1v15::config_for_x509(const Private_Key& key,
                                    const std::string& cert_hash_name) const
   {
   if(cert_hash_name != m_hash->name())
      throw Invalid_Argument("Hash function from opts and hash_fn argument"
         " need to be identical");
   // check that the signature algorithm and the padding scheme fit
   if(!sig_algo_and_pad_ok(key.algo_name(), "EMSA3"))
      {
      throw Invalid_Argument("Encoding scheme with canonical name EMSA3"
         " not supported for signature algorithm " + key.algo_name());
      }

   // for RSA PKCSv1.5 parameters "SHALL" be NULL

   const OID oid = OID::from_string(key.algo_name() + "/" + name());
   return AlgorithmIdentifier(oid, AlgorithmIdentifier::USE_NULL_PARAM);
   }

EMSA_PKCS1v15::EMSA_PKCS1v15(HashFunction* hash) : m_hash(hash)
   {
   m_hash_id = pkcs_hash_id(m_hash->name());
   }

EMSA_PKCS1v15_Raw::EMSA_PKCS1v15_Raw(const std::string& hash_algo)
   {
   if(!hash_algo.empty())
      {
      m_hash_id = pkcs_hash_id(hash_algo);
      std::unique_ptr<HashFunction> hash(HashFunction::create_or_throw(hash_algo));
      m_hash_name = hash->name();
      m_hash_output_len = hash->output_length();
      }
   else
      {
      m_hash_output_len = 0;
      }
   }

void EMSA_PKCS1v15_Raw::update(const uint8_t input[], size_t length)
   {
   m_message += std::make_pair(input, length);
   }

secure_vector<uint8_t> EMSA_PKCS1v15_Raw::raw_data()
   {
   secure_vector<uint8_t> ret;
   std::swap(ret, m_message);

   if(m_hash_output_len > 0 && ret.size() != m_hash_output_len)
      throw Encoding_Error("EMSA_PKCS1v15_Raw::encoding_of: Bad input length");

   return ret;
   }

secure_vector<uint8_t>
EMSA_PKCS1v15_Raw::encoding_of(const secure_vector<uint8_t>& msg,
                               size_t output_bits,
                               RandomNumberGenerator&)
   {
   return emsa3_encoding(msg, output_bits, m_hash_id.data(), m_hash_id.size());
   }

bool EMSA_PKCS1v15_Raw::verify(const secure_vector<uint8_t>& coded,
                               const secure_vector<uint8_t>& raw,
                               size_t key_bits)
   {
   if(m_hash_output_len > 0 && raw.size() != m_hash_output_len)
      return false;

   try
      {
      return (coded == emsa3_encoding(raw, key_bits, m_hash_id.data(), m_hash_id.size()));
      }
   catch(...)
      {
      return false;
      }
   }

}
