/*
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/x931_sig_padding.h>

#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/mem_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/hash_id.h>
#include <botan/internal/stl_util.h>

namespace Botan {

namespace {

std::vector<uint8_t> x931_encoding(std::span<const uint8_t> msg,
                                   size_t output_bits,
                                   std::span<const uint8_t> empty_hash,
                                   uint8_t hash_id) {
   const size_t HASH_SIZE = empty_hash.size();

   const size_t output_length = (output_bits + 1) / 8;

   if(msg.size() != HASH_SIZE) {
      throw Encoding_Error("X931_SignaturePadding::encoding_of: Bad input length");
   }
   if(output_length < HASH_SIZE + 4) {
      throw Encoding_Error("X931_SignaturePadding::encoding_of: Output length is too small");
   }

   const bool empty_input = constant_time_compare(msg, empty_hash);

   std::vector<uint8_t> output(output_length);
   BufferStuffer stuffer(output);

   stuffer.append(empty_input ? 0x4B : 0x6B);
   stuffer.append(0xBB, stuffer.remaining_capacity() - (1 + msg.size() + 2));
   stuffer.append(0xBA);
   stuffer.append(msg);
   stuffer.append(hash_id);
   stuffer.append(0xCC);
   BOTAN_ASSERT_NOMSG(stuffer.full());

   return output;
}

}  // namespace

std::string X931_SignaturePadding::hash_function() const {
   return m_hash->name();
}

std::string X931_SignaturePadding::name() const {
   return fmt("X9.31({})", m_hash->name());
}

void X931_SignaturePadding::update(const uint8_t input[], size_t length) {
   m_hash->update(input, length);
}

std::vector<uint8_t> X931_SignaturePadding::raw_data() {
   return m_hash->final_stdvec();
}

/*
* X931_SignaturePadding Encode Operation
*/
std::vector<uint8_t> X931_SignaturePadding::encoding_of(std::span<const uint8_t> msg,
                                                        size_t output_bits,
                                                        RandomNumberGenerator& /*rng*/) {
   return x931_encoding(msg, output_bits, m_empty_hash, m_hash_id);
}

/*
* X931_SignaturePadding Verify Operation
*/
bool X931_SignaturePadding::verify(std::span<const uint8_t> coded, std::span<const uint8_t> raw, size_t key_bits) {
   try {
      const auto x931 = x931_encoding(raw, key_bits, m_empty_hash, m_hash_id);
      return constant_time_compare(coded, x931);
   } catch(...) {
      return false;
   }
}

/*
* X931_SignaturePadding Constructor
*/
X931_SignaturePadding::X931_SignaturePadding(std::unique_ptr<HashFunction> hash) : m_hash(std::move(hash)) {
   m_empty_hash = m_hash->final_stdvec();

   m_hash_id = ieee1363_hash_id(m_hash->name());

   if(m_hash_id == 0) {
      throw Encoding_Error("X931_SignaturePadding no hash identifier for " + m_hash->name());
   }
}

}  // namespace Botan
