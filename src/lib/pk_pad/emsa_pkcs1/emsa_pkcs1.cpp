/*
* PKCS #1 v1.5 signature padding
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/emsa_pkcs1.h>

#include <botan/exceptn.h>
#include <botan/internal/hash_id.h>
#include <botan/internal/stl_util.h>

namespace Botan {

namespace {

std::vector<uint8_t> pkcs1v15_sig_encoding(const std::vector<uint8_t>& msg,
                                           size_t output_bits,
                                           std::span<const uint8_t> hash_id) {
   const size_t output_length = output_bits / 8;

   if(output_length < hash_id.size() + msg.size() + 2 + 8) {
      throw Encoding_Error("pkcs1v15_sig_encoding: Output length is too small");
   }

   std::vector<uint8_t> padded(output_length);
   BufferStuffer stuffer(padded);

   stuffer.append(0x01);
   stuffer.append(0xFF, stuffer.remaining_capacity() - (1 + hash_id.size() + msg.size()));
   stuffer.append(0x00);
   stuffer.append(hash_id);
   stuffer.append(msg);
   BOTAN_ASSERT_NOMSG(stuffer.full());

   return padded;
}

}  // namespace

void EMSA_PKCS1v15::update(const uint8_t input[], size_t length) {
   m_hash->update(input, length);
}

std::vector<uint8_t> EMSA_PKCS1v15::raw_data() {
   return m_hash->final_stdvec();
}

std::vector<uint8_t> EMSA_PKCS1v15::encoding_of(const std::vector<uint8_t>& msg,
                                                size_t output_bits,
                                                RandomNumberGenerator& /*rng*/) {
   if(msg.size() != m_hash->output_length()) {
      throw Encoding_Error("EMSA_PKCS1v15::encoding_of: Bad input length");
   }

   return pkcs1v15_sig_encoding(msg, output_bits, m_hash_id);
}

bool EMSA_PKCS1v15::verify(const std::vector<uint8_t>& coded, const std::vector<uint8_t>& raw, size_t key_bits) {
   if(raw.size() != m_hash->output_length()) {
      return false;
   }

   try {
      return coded == pkcs1v15_sig_encoding(raw, key_bits, m_hash_id);
   } catch(...) {
      return false;
   }
}

EMSA_PKCS1v15::EMSA_PKCS1v15(std::unique_ptr<HashFunction> hash) : m_hash(std::move(hash)) {
   m_hash_id = pkcs_hash_id(m_hash->name());
}

EMSA_PKCS1v15_Raw::EMSA_PKCS1v15_Raw(const std::optional<std::string>& hash_algo) {
   if(hash_algo) {
      std::unique_ptr<HashFunction> hash(HashFunction::create_or_throw(hash_algo.value()));
      m_hash_id = pkcs_hash_id(hash->name());
      m_hash_name = hash->name();
      m_hash_output_len = hash->output_length();
   } else {
      m_hash_output_len = 0;
      // m_hash_id, m_hash_name left empty
   }
}

void EMSA_PKCS1v15_Raw::update(const uint8_t input[], size_t length) {
   m_message += std::make_pair(input, length);
}

std::vector<uint8_t> EMSA_PKCS1v15_Raw::raw_data() {
   std::vector<uint8_t> ret;
   std::swap(ret, m_message);

   if(m_hash_output_len > 0 && ret.size() != m_hash_output_len) {
      throw Encoding_Error("EMSA_PKCS1v15_Raw::encoding_of: Bad input length");
   }

   return ret;
}

std::vector<uint8_t> EMSA_PKCS1v15_Raw::encoding_of(const std::vector<uint8_t>& msg,
                                                    size_t output_bits,
                                                    RandomNumberGenerator& /*rng*/) {
   return pkcs1v15_sig_encoding(msg, output_bits, m_hash_id);
}

bool EMSA_PKCS1v15_Raw::verify(const std::vector<uint8_t>& coded, const std::vector<uint8_t>& raw, size_t key_bits) {
   if(m_hash_output_len > 0 && raw.size() != m_hash_output_len) {
      return false;
   }

   try {
      return coded == pkcs1v15_sig_encoding(raw, key_bits, m_hash_id);
   } catch(...) {
      return false;
   }
}

}  // namespace Botan
