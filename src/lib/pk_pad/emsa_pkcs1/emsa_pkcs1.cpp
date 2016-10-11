/*
* PKCS #1 v1.5 signature padding
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/emsa_pkcs1.h>
#include <botan/hash_id.h>

namespace Botan {

namespace {

secure_vector<byte> emsa3_encoding(const secure_vector<byte>& msg,
                                   size_t output_bits,
                                   const byte hash_id[],
                                   size_t hash_id_length)
   {
   size_t output_length = output_bits / 8;
   if(output_length < hash_id_length + msg.size() + 10)
      throw Encoding_Error("emsa3_encoding: Output length is too small");

   secure_vector<byte> T(output_length);
   const size_t P_LENGTH = output_length - msg.size() - hash_id_length - 2;

   T[0] = 0x01;
   set_mem(&T[1], P_LENGTH, 0xFF);
   T[P_LENGTH+1] = 0x00;
   buffer_insert(T, P_LENGTH+2, hash_id, hash_id_length);
   buffer_insert(T, output_length-msg.size(), msg.data(), msg.size());
   return T;
   }

}

void EMSA_PKCS1v15::update(const byte input[], size_t length)
   {
   m_hash->update(input, length);
   }

secure_vector<byte> EMSA_PKCS1v15::raw_data()
   {
   return m_hash->final();
   }

secure_vector<byte>
EMSA_PKCS1v15::encoding_of(const secure_vector<byte>& msg,
                           size_t output_bits,
                           RandomNumberGenerator&)
   {
   if(msg.size() != m_hash->output_length())
      throw Encoding_Error("EMSA_PKCS1v15::encoding_of: Bad input length");

   return emsa3_encoding(msg, output_bits,
                         m_hash_id.data(), m_hash_id.size());
   }

bool EMSA_PKCS1v15::verify(const secure_vector<byte>& coded,
                           const secure_vector<byte>& raw,
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

EMSA_PKCS1v15::EMSA_PKCS1v15(HashFunction* hash) : m_hash(hash)
   {
   m_hash_id = pkcs_hash_id(m_hash->name());
   }

void EMSA_PKCS1v15_Raw::update(const byte input[], size_t length)
   {
   m_message += std::make_pair(input, length);
   }

secure_vector<byte> EMSA_PKCS1v15_Raw::raw_data()
   {
   secure_vector<byte> ret;
   std::swap(ret, m_message);
   return ret;
   }

secure_vector<byte>
EMSA_PKCS1v15_Raw::encoding_of(const secure_vector<byte>& msg,
                               size_t output_bits,
                               RandomNumberGenerator&)
   {
   return emsa3_encoding(msg, output_bits, nullptr, 0);
   }

bool EMSA_PKCS1v15_Raw::verify(const secure_vector<byte>& coded,
                               const secure_vector<byte>& raw,
                               size_t key_bits)
   {
   try
      {
      return (coded == emsa3_encoding(raw, key_bits, nullptr, 0));
      }
   catch(...)
      {
      return false;
      }
   }

}
