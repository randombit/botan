/*
* EMSA3 and EMSA3_Raw
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/emsa3.h>
#include <botan/hash_id.h>

namespace Botan {

namespace {

/*
* EMSA3 Encode Operation
*/
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
   buffer_insert(T, output_length-msg.size(), &msg[0], msg.size());
   return T;
   }

}

/*
* EMSA3 Update Operation
*/
void EMSA3::update(const byte input[], size_t length)
   {
   hash->update(input, length);
   }

/*
* Return the raw (unencoded) data
*/
secure_vector<byte> EMSA3::raw_data()
   {
   return hash->final();
   }

/*
* EMSA3 Encode Operation
*/
secure_vector<byte> EMSA3::encoding_of(const secure_vector<byte>& msg,
                                      size_t output_bits,
                                      RandomNumberGenerator&)
   {
   if(msg.size() != hash->output_length())
      throw Encoding_Error("EMSA3::encoding_of: Bad input length");

   return emsa3_encoding(msg, output_bits,
                         &hash_id[0], hash_id.size());
   }

/*
* Default signature decoding
*/
bool EMSA3::verify(const secure_vector<byte>& coded,
                   const secure_vector<byte>& raw,
                   size_t key_bits)
   {
   if(raw.size() != hash->output_length())
      return false;

   try
      {
      return (coded == emsa3_encoding(raw, key_bits,
                                      &hash_id[0], hash_id.size()));
      }
   catch(...)
      {
      return false;
      }
   }

/*
* EMSA3 Constructor
*/
EMSA3::EMSA3(HashFunction* hash_in) : hash(hash_in)
   {
   hash_id = pkcs_hash_id(hash->name());
   }

/*
* EMSA3 Destructor
*/
EMSA3::~EMSA3()
   {
   delete hash;
   }

/*
* EMSA3_Raw Update Operation
*/
void EMSA3_Raw::update(const byte input[], size_t length)
   {
   message += std::make_pair(input, length);
   }

/*
* Return the raw (unencoded) data
*/
secure_vector<byte> EMSA3_Raw::raw_data()
   {
   secure_vector<byte> ret;
   std::swap(ret, message);
   return ret;
   }

/*
* EMSA3_Raw Encode Operation
*/
secure_vector<byte> EMSA3_Raw::encoding_of(const secure_vector<byte>& msg,
                                          size_t output_bits,
                                          RandomNumberGenerator&)
   {
   return emsa3_encoding(msg, output_bits, nullptr, 0);
   }

/*
* Default signature decoding
*/
bool EMSA3_Raw::verify(const secure_vector<byte>& coded,
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
