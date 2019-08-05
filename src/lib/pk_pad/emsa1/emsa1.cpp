/*
* EMSA1
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/emsa1.h>
#include <botan/exceptn.h>
#include <botan/pk_keys.h>
#include <botan/internal/padding.h>

namespace Botan {

namespace {

secure_vector<uint8_t> emsa1_encoding(const secure_vector<uint8_t>& msg,
                                  size_t output_bits)
   {
   if(8*msg.size() <= output_bits)
      return msg;

   size_t shift = 8*msg.size() - output_bits;

   size_t byte_shift = shift / 8, bit_shift = shift % 8;
   secure_vector<uint8_t> digest(msg.size() - byte_shift);

   for(size_t j = 0; j != msg.size() - byte_shift; ++j)
      digest[j] = msg[j];

   if(bit_shift)
      {
      uint8_t carry = 0;
      for(size_t j = 0; j != digest.size(); ++j)
         {
         uint8_t temp = digest[j];
         digest[j] = (temp >> bit_shift) | carry;
         carry = (temp << (8 - bit_shift));
         }
      }
   return digest;
   }

}

std::string EMSA1::name() const
   {
   return "EMSA1(" + m_hash->name() + ")";
   }

EMSA* EMSA1::clone()
   {
   return new EMSA1(m_hash->clone());
   }

void EMSA1::update(const uint8_t input[], size_t length)
   {
   m_hash->update(input, length);
   }

secure_vector<uint8_t> EMSA1::raw_data()
   {
   return m_hash->final();
   }

secure_vector<uint8_t> EMSA1::encoding_of(const secure_vector<uint8_t>& msg,
                                       size_t output_bits,
                                       RandomNumberGenerator&)
   {
   if(msg.size() != hash_output_length())
      throw Encoding_Error("EMSA1::encoding_of: Invalid size for input");
   return emsa1_encoding(msg, output_bits);
   }

bool EMSA1::verify(const secure_vector<uint8_t>& input,
                   const secure_vector<uint8_t>& raw,
                   size_t key_bits)
   {
   if(raw.size() != m_hash->output_length())
      return false;

   // Call emsa1_encoding to handle any required bit shifting
   const secure_vector<uint8_t> our_coding = emsa1_encoding(raw, key_bits);

   if(our_coding.size() < input.size())
      return false;

   const size_t offset = our_coding.size() - input.size(); // must be >= 0 per check above

   // If our encoding is longer, all the bytes in it must be zero
   for(size_t i = 0; i != offset; ++i)
      if(our_coding[i] != 0)
            return false;

   return constant_time_compare(input.data(), &our_coding[offset], input.size());
   }

AlgorithmIdentifier EMSA1::config_for_x509(const Private_Key& key,
                                           const std::string& cert_hash_name) const
   {
   if(cert_hash_name != m_hash->name())
      throw Invalid_Argument("Hash function from opts and hash_fn argument"
         " need to be identical");
   // check that the signature algorithm and the padding scheme fit
   if(!sig_algo_and_pad_ok(key.algo_name(), "EMSA1"))
      {
      throw Invalid_Argument("Encoding scheme with canonical name EMSA1"
         " not supported for signature algorithm " + key.algo_name());
      }

   const OID oid = OID::from_string(key.algo_name() + "/" + name());

   const std::string algo_name = key.algo_name();
   std::vector<uint8_t> parameters;
   if(algo_name == "DSA" ||
      algo_name == "ECDSA" ||
      algo_name == "ECGDSA" ||
      algo_name == "ECKCDSA" ||
      algo_name == "GOST-34.10" ||
      algo_name == "GOST-34.10-2012-256" ||
      algo_name == "GOST-34.10-2012-512")
      {
      // for DSA, ECDSA, GOST parameters "SHALL" be empty
      }
   else
      {
      parameters = key.algorithm_identifier().get_parameters();
      }

   return AlgorithmIdentifier(oid, parameters);
   }

}
