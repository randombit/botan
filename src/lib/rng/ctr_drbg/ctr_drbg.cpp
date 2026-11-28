/*
* CTR_DRBG
* (C) 2023,2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ctr_drbg.h>

#include <botan/assert.h>
#include <botan/block_cipher.h>
#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/ctr_drbg_nodf.h>
#include <botan/internal/fmt.h>
#include <botan/internal/int_utils.h>
#include <botan/internal/loadstor.h>
#include <algorithm>
#include <array>
#include <limits>

namespace Botan {

namespace {

constexpr size_t CTR_DRBG_BlockSize = 16;

// Largest seedlen, used by AES-256
constexpr size_t CTR_DRBG_MaxSeedLength = 32 + CTR_DRBG_BlockSize;

std::unique_ptr<BlockCipher> check_cipher(std::unique_ptr<BlockCipher> cipher) {
   BOTAN_ARG_CHECK(cipher != nullptr, "Argument must not be null");

   if(cipher->block_size() != CTR_DRBG_BlockSize) {
      throw Invalid_Argument(fmt("CTR_DRBG requires a 128-bit block cipher, {} is not", cipher->name()));
   }

   const size_t key_length = cipher->maximum_keylength();
   if(key_length != 16 && key_length != 24 && key_length != 32) {
      throw Invalid_Argument(fmt("CTR_DRBG does not support the key length of {}", cipher->name()));
   }

   return cipher;
}

void check_ctr_drbg_limits(size_t reseed_interval, size_t max_number_of_bytes_per_request) {
   // SP800-90A permits up to 2^48, but it is not usable on 32 bit
   // platforms, so we only allow up to 2^24, which is still reasonably high
   if(reseed_interval == 0 || reseed_interval > static_cast<size_t>(1) << 24) {
      throw Invalid_Argument("Invalid value for reseed_interval");
   }

   if(max_number_of_bytes_per_request == 0 || max_number_of_bytes_per_request > 64 * 1024) {
      throw Invalid_Argument("Invalid value for max_number_of_bytes_per_request");
   }
}

/*
* SP800-90A section 8.6.8: "When a DRBG's maximum seedlife is reached, the
* DRBG shall not generate outputs until it has been reseeded."
*
* Table 3 gives the "Maximum number of requests between reseeds" as 2^48
*/
size_t max_reseed_interval() {
   return static_cast<size_t>(std::min<uint64_t>(static_cast<uint64_t>(1) << 48, std::numeric_limits<size_t>::max()));
}

/*
* Block_Cipher_df uses a fixed key for BCC, so that cipher is keyed once
* K = leftmost(0x00010203...1D1E1F, keylen)
*/
std::unique_ptr<BlockCipher> keyed_bcc_cipher(const BlockCipher& cipher) {
   auto bcc = cipher.new_object();

   std::array<uint8_t, 32> K{};
   for(size_t i = 0; i != K.size(); ++i) {
      K[i] = static_cast<uint8_t>(i);
   }
   bcc->set_key(std::span{K}.first(cipher.maximum_keylength()));

   return bcc;
}

}  // namespace

CTR_DRBG::~CTR_DRBG() {
   secure_scrub_memory(&m_V_hi, sizeof(m_V_hi));
   secure_scrub_memory(&m_V_lo, sizeof(m_V_lo));
}

CTR_DRBG::CTR_DRBG(std::unique_ptr<BlockCipher> cipher, DerivationFunction df) :
      Stateful_RNG(max_reseed_interval()),
      m_cipher(check_cipher(std::move(cipher))),
      m_bcc_cipher(df == DerivationFunction::Enabled ? keyed_bcc_cipher(*m_cipher) : nullptr),
      m_df_cipher(df == DerivationFunction::Enabled ? m_cipher->new_object() : nullptr),
      m_key_length(m_cipher->maximum_keylength()),
      m_max_number_of_bytes_per_request(64 * 1024) {
   clear();
}

CTR_DRBG::CTR_DRBG(std::unique_ptr<BlockCipher> cipher) : CTR_DRBG(std::move(cipher), DerivationFunction::Enabled) {}

CTR_DRBG::CTR_DRBG(std::string_view cipher) : CTR_DRBG(BlockCipher::create_or_throw(cipher)) {}

CTR_DRBG::CTR_DRBG(std::unique_ptr<BlockCipher> cipher,
                   RandomNumberGenerator& underlying_rng,
                   size_t reseed_interval,
                   size_t max_number_of_bytes_per_request) :
      Stateful_RNG(underlying_rng, reseed_interval),
      m_cipher(check_cipher(std::move(cipher))),
      m_bcc_cipher(keyed_bcc_cipher(*m_cipher)),
      m_df_cipher(m_cipher->new_object()),
      m_key_length(m_cipher->maximum_keylength()),
      m_max_number_of_bytes_per_request(max_number_of_bytes_per_request) {
   check_ctr_drbg_limits(reseed_interval, max_number_of_bytes_per_request);

   clear();
}

CTR_DRBG::CTR_DRBG(std::unique_ptr<BlockCipher> cipher,
                   Entropy_Sources& entropy_sources,
                   size_t reseed_interval,
                   size_t max_number_of_bytes_per_request) :
      Stateful_RNG(entropy_sources, reseed_interval),
      m_cipher(check_cipher(std::move(cipher))),
      m_bcc_cipher(keyed_bcc_cipher(*m_cipher)),
      m_df_cipher(m_cipher->new_object()),
      m_key_length(m_cipher->maximum_keylength()),
      m_max_number_of_bytes_per_request(max_number_of_bytes_per_request) {
   check_ctr_drbg_limits(reseed_interval, max_number_of_bytes_per_request);

   clear();
}

CTR_DRBG::CTR_DRBG(std::unique_ptr<BlockCipher> cipher,
                   RandomNumberGenerator& underlying_rng,
                   Entropy_Sources& entropy_sources,
                   size_t reseed_interval,
                   size_t max_number_of_bytes_per_request) :
      Stateful_RNG(underlying_rng, entropy_sources, reseed_interval),
      m_cipher(check_cipher(std::move(cipher))),
      m_bcc_cipher(keyed_bcc_cipher(*m_cipher)),
      m_df_cipher(m_cipher->new_object()),
      m_key_length(m_cipher->maximum_keylength()),
      m_max_number_of_bytes_per_request(max_number_of_bytes_per_request) {
   check_ctr_drbg_limits(reseed_interval, max_number_of_bytes_per_request);

   clear();
}

std::unique_ptr<CTR_DRBG> CTR_DRBG_Without_DF::create(std::unique_ptr<BlockCipher> cipher) {
   return std::unique_ptr<CTR_DRBG>(new CTR_DRBG(std::move(cipher), CTR_DRBG::DerivationFunction::Disabled));
}

std::unique_ptr<CTR_DRBG> CTR_DRBG_Without_DF::create(std::string_view cipher) {
   return create(BlockCipher::create_or_throw(cipher));
}

/*
* Reset to the state used by the instantiate function, where Key and V are both zero
* See NIST SP800-90A sections 10.2.1.3.1 and 10.2.1.3.2
*/
void CTR_DRBG::clear_state() {
   const std::array<uint8_t, 32> zero_key = {0};
   m_cipher->set_key(std::span{zero_key}.first(key_length()));
   m_V_hi = 0;
   m_V_lo = 0;

   if(m_df_cipher) {
      m_df_cipher->clear();
   }
}

std::string CTR_DRBG::name() const {
   if(m_df_cipher) {
      return fmt("CTR_DRBG({})", m_cipher->name());
   } else {
      return fmt("CTR_DRBG({},NoDF)", m_cipher->name());
   }
}

size_t CTR_DRBG::security_level() const {
   return 8 * key_length();
}

size_t CTR_DRBG::required_seed_bits() const {
   if(m_df_cipher) {
      /*
      * The nonce is taken from the same input as the entropy, which per
      * SP800-90A section 8.6.7 requires that "the entropy for the entropy
      * input is equal to or greater than (3/2 security_strength) bits"
      */
      return security_level() + security_level() / 2;
   } else {
      // Without the derivation function the entropy input must be exactly seedlen bits
      return 8 * seed_length();
   }
}

/*
* Increment V and write each new value of V to buf, which must be a
* multiple of the block size
*/
void CTR_DRBG::next_counters(std::span<uint8_t> buf) {
   for(size_t i = 0; i != buf.size(); i += CTR_DRBG_BlockSize) {
      m_V_lo += 1;
      m_V_hi += (m_V_lo == 0) ? 1 : 0;
      store_be(&buf[i], m_V_hi, m_V_lo);
   }
}

/*
* Write E(Key, V+1) || E(Key, V+2) || ... to output, truncating the final
* block if required. See NIST SP800-90A section 10.2.1.5.1 steps 4 and 5
*
* The counter blocks are secret, so they are built in a local buffer
* rather than in the output
*/
void CTR_DRBG::generate_blocks(std::span<uint8_t> output) {
   constexpr size_t BatchBlocks = 32;
   std::array<uint8_t, BatchBlocks * CTR_DRBG_BlockSize> buf;  // NOLINT(*-member-init)

   const size_t total_blocks = (output.size() + CTR_DRBG_BlockSize - 1) / CTR_DRBG_BlockSize;
   const size_t buf_used = std::min(total_blocks, BatchBlocks) * CTR_DRBG_BlockSize;

   while(!output.empty()) {
      const size_t blocks = std::min((output.size() + CTR_DRBG_BlockSize - 1) / CTR_DRBG_BlockSize, BatchBlocks);
      const size_t bytes = blocks * CTR_DRBG_BlockSize;

      next_counters(std::span{buf}.first(bytes));

      if(output.size() >= bytes) {
         m_cipher->encrypt_n(buf.data(), output.data(), blocks);
         output = output.subspan(bytes);
      } else {
         m_cipher->encrypt_n(buf.data(), buf.data(), blocks);
         copy_mem(output, std::span{buf}.first(output.size()));
         output = {};
      }
   }

   secure_scrub_memory(std::span{buf}.first(buf_used));
}

/*
* CTR_DRBG_Update
* See NIST SP800-90A section 10.2.1.2
*/
void CTR_DRBG::ctr_drbg_update(std::span<const uint8_t> provided_data) {
   BOTAN_ASSERT_NOMSG(provided_data.size() == seed_length());

   // Rounded up to a whole number of blocks, which always fits in buf
   const size_t blocks = (seed_length() + CTR_DRBG_BlockSize - 1) / CTR_DRBG_BlockSize;

   std::array<uint8_t, CTR_DRBG_MaxSeedLength> buf{};
   next_counters(std::span{buf}.first(blocks * CTR_DRBG_BlockSize));
   m_cipher->encrypt_n(buf.data(), buf.data(), blocks);

   const auto temp = std::span{buf}.first(seed_length());
   xor_buf(temp, provided_data);

   m_cipher->set_key(temp.first(key_length()));
   m_V_hi = load_be<uint64_t>(temp.last(CTR_DRBG_BlockSize).data(), 0);
   m_V_lo = load_be<uint64_t>(temp.last(CTR_DRBG_BlockSize).data(), 1);

   secure_scrub_memory(buf);
}

/*
* Block_Cipher_df
* See NIST SP800-90A section 10.3.2
*/
void CTR_DRBG::block_cipher_df(std::span<uint8_t> output, std::span<const uint8_t> input) {
   BOTAN_ASSERT_NOMSG(output.size() == seed_length());

   const uint32_t L = checked_cast_to_or_throw<uint32_t, Invalid_Argument>(input.size(), "CTR_DRBG input too long");
   const uint32_t N = static_cast<uint32_t>(output.size());

   const size_t key_len = key_length();

   /*
   * Compute each BCC(K, IV_i || S) in parallel, where IV_i is i encoded
   * as a 32-bit integer then zero padded to the block size
   */
   const size_t chains = (key_len + CTR_DRBG_BlockSize + CTR_DRBG_BlockSize - 1) / CTR_DRBG_BlockSize;
   std::array<uint8_t, 3 * CTR_DRBG_BlockSize> temp{};
   BOTAN_ASSERT_NOMSG(chains * CTR_DRBG_BlockSize <= temp.size());

   for(size_t i = 0; i != chains; ++i) {
      store_be(&temp[i * CTR_DRBG_BlockSize], static_cast<uint32_t>(i));
   }
   m_bcc_cipher->encrypt_n(temp.data(), temp.data(), chains);

   const auto bcc_block = [&](const std::array<uint8_t, CTR_DRBG_BlockSize>& S_j) {
      for(size_t i = 0; i != chains; ++i) {
         xor_buf(std::span{temp}.subspan(i * CTR_DRBG_BlockSize, CTR_DRBG_BlockSize), S_j);
      }
      m_bcc_cipher->encrypt_n(temp.data(), temp.data(), chains);
   };

   // S = L || N || input_string || 0x80 || zero padding, absorbed one block at a time
   std::array<uint8_t, CTR_DRBG_BlockSize> block{};
   size_t block_pos = 0;

   const auto absorb = [&](std::span<const uint8_t> bytes) {
      while(!bytes.empty()) {
         // Help the optimizer
         BOTAN_ASSERT_NOMSG(block_pos < block.size());
         const size_t take = std::min(bytes.size(), block.size() - block_pos);
         copy_mem(std::span{block}.subspan(block_pos, take), bytes.first(take));
         block_pos += take;
         bytes = bytes.subspan(take);

         if(block_pos == block.size()) {
            bcc_block(block);
            block_pos = 0;
         }
      }
   };

   std::array<uint8_t, 8> header{};
   store_be(header.data(), L, N);
   absorb(header);
   absorb(input);
   const uint8_t terminator = 0x80;
   absorb(std::span{&terminator, 1});

   if(block_pos > 0) {
      clear_mem(std::span{block}.subspan(block_pos));
      bcc_block(block);
   }

   // K = leftmost(temp, keylen), X = the following block
   std::array<uint8_t, CTR_DRBG_BlockSize> X{};
   m_df_cipher->set_key(std::span{temp}.first(key_len));
   copy_mem(X, std::span{temp}.subspan(key_len, CTR_DRBG_BlockSize));

   for(size_t i = 0; i < output.size(); i += CTR_DRBG_BlockSize) {
      m_df_cipher->encrypt(X);
      const size_t to_copy = std::min(CTR_DRBG_BlockSize, output.size() - i);
      copy_mem(output.subspan(i, to_copy), std::span{X}.first(to_copy));
   }

   secure_scrub_memory(block);
   secure_scrub_memory(temp);
   secure_scrub_memory(X);
}

void CTR_DRBG::derive_seed_material(std::span<uint8_t> seed_material, std::span<const uint8_t> input) {
   BOTAN_ASSERT_NOMSG(seed_material.size() == seed_length());

   if(m_df_cipher) {
      block_cipher_df(seed_material, input);
   } else {
      if(input.size() > seed_material.size()) {
         throw Invalid_Argument(
            fmt("{} accepts inputs of at most {} bytes but was given {}", name(), seed_material.size(), input.size()));
      }

      clear_mem(seed_material);
      copy_mem(seed_material.first(input.size()), input);
   }
}

/*
* CTR_DRBG reseed (or instantiate, if following clear)
* See NIST SP800-90A sections 10.2.1.4.1 and 10.2.1.4.2
*/
void CTR_DRBG::update(std::span<const uint8_t> input) {
   std::array<uint8_t, CTR_DRBG_MaxSeedLength> buf{};
   const auto seed_material = std::span{buf}.first(seed_length());

   derive_seed_material(seed_material, input);
   ctr_drbg_update(seed_material);

   secure_scrub_memory(buf);
}

/*
* CTR_DRBG generation
* See NIST SP800-90A sections 10.2.1.5.1 and 10.2.1.5.2
*/
void CTR_DRBG::generate_output(std::span<uint8_t> output, std::span<const uint8_t> input) {
   // This is an internal function, callers should have validated this beforehand
   BOTAN_ASSERT_NOMSG(!output.empty());

   // If no additional input is provided, a string of zeros is used instead
   std::array<uint8_t, CTR_DRBG_MaxSeedLength> buf{};
   const auto additional_input = std::span{buf}.first(seed_length());

   if(!input.empty()) {
      derive_seed_material(additional_input, input);
      ctr_drbg_update(additional_input);
   }

   generate_blocks(output);

   ctr_drbg_update(additional_input);

   secure_scrub_memory(buf);
}

}  // namespace Botan
