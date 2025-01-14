/*
* KDFs defined in NIST SP 800-108
* (C) 2016 Kai Michaelis
* (C) 2024 René Meusel, Rohde & Schwarz Cybersecurity
* (C) 2025 René Meusel, Amos Treiber, Rohde & Schwarz Cybersecurity
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/sp800_108.h>

#include <botan/exceptn.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/stl_util.h>

#include <limits>

namespace Botan {

namespace {

class CounterParams {
   public:
      constexpr static void validate_bit_lengths(size_t counter_bits, size_t output_length_bits) {
         BOTAN_ARG_CHECK(counter_bits % 8 == 0 && counter_bits <= 32,
                         "SP.800-108 counter length may be one of {8, 16, 24, 32} only");
         BOTAN_ARG_CHECK(output_length_bits % 8 == 0 && output_length_bits <= 32,
                         "SP.800-108 output length encoding may be one of {8, 16, 24, 32} only");
      }

      constexpr static CounterParams create_or_throw(size_t output_bytes,
                                                     size_t output_length_bits,
                                                     size_t counter_bits,
                                                     size_t prf_output_bytes) {
         // The maximum legal output bit length is limited by the requested encoding
         // bit length of the "L" field.
         BOTAN_ARG_CHECK(static_cast<uint64_t>(output_bytes) * 8 <= std::numeric_limits<uint32_t>::max(),
                         "SP.800-108 output size in bits does not fit into 32-bits");
         const auto output_bits = static_cast<uint32_t>(output_bytes * 8);
         const auto max_output_bits = (uint64_t(1) << output_length_bits) - 1;
         BOTAN_ARG_CHECK(output_bits <= max_output_bits,
                         "SP.800-108 output size does not fit into the requested field length");

         // Calculate the number of blocks needed to serve the requested bytes
         const auto blocks_required = ceil_division<uint64_t /* for 32bit systems */>(output_bytes, prf_output_bytes);

         // The maximal legal invocation count of the PRF is limited by the requested
         // encoding bit length of the counter ("r"). The counter starts at "1", so the
         // maximum number of usable blocks is 2^r - 1.
         const auto max_blocks = (uint64_t(1) << counter_bits) - 1;
         BOTAN_ARG_CHECK(blocks_required < max_blocks, "SP.800-108 output size too large");

         CounterParams out;
         out.m_output_length_bits = output_bits;
         out.m_output_length_encoding_bytes = output_length_bits / 8;
         out.m_counter_bytes = counter_bits / 8;
         out.m_blocks_required = static_cast<uint32_t>(blocks_required);
         return out;
      }

      template <std::invocable<std::span<const uint8_t>, std::span<const uint8_t>> Fn>
      constexpr void generate_blocks(Fn fn) const {
         const auto outlen_encoded = store_be(m_output_length_bits);
         for(uint32_t counter = 1; counter <= m_blocks_required; ++counter) {
            const auto counter_encoded = store_be(counter);
            fn(std::span{counter_encoded}.last(m_counter_bytes),
               std::span{outlen_encoded}.last(m_output_length_encoding_bytes));
         }
      }

   private:
      constexpr CounterParams() = default;

   private:
      uint32_t m_output_length_bits;
      size_t m_output_length_encoding_bytes;
      size_t m_counter_bytes;
      uint32_t m_blocks_required;
};

}  // namespace

SP800_108_Counter::SP800_108_Counter(std::unique_ptr<MessageAuthenticationCode> mac, size_t r, size_t L) :
      m_prf(std::move(mac)), m_counter_bits(r), m_output_length_bits(L) {
   CounterParams::validate_bit_lengths(m_counter_bits, m_output_length_bits);
}

std::string SP800_108_Counter::name() const {
   // TODO(Botan4): make this always return the explicit lengths
   return (m_counter_bits == 32 && m_output_length_bits == 32)
             ? fmt("SP800-108-Counter({})", m_prf->name())  // keep the name consistent with previous versions
             : fmt("SP800-108-Counter({},{},{})", m_prf->name(), m_counter_bits, m_output_length_bits);
}

std::unique_ptr<KDF> SP800_108_Counter::new_object() const {
   return std::make_unique<SP800_108_Counter>(m_prf->new_object(), m_counter_bits, m_output_length_bits);
}

void SP800_108_Counter::perform_kdf(std::span<uint8_t> key,
                                    std::span<const uint8_t> secret,
                                    std::span<const uint8_t> salt,
                                    std::span<const uint8_t> label) const {
   if(key.empty()) {
      return;
   }

   const auto prf_len = m_prf->output_length();
   const auto params = CounterParams::create_or_throw(key.size(), m_output_length_bits, m_counter_bits, prf_len);

   constexpr uint8_t delim = 0;

   BufferStuffer k(key);
   m_prf->set_key(secret);

   params.generate_blocks([&](auto counter_encoded, auto outlen_encoded) {
      m_prf->update(counter_encoded);
      m_prf->update(label);
      m_prf->update(delim);
      m_prf->update(salt);
      m_prf->update(outlen_encoded);

      // Write straight into the output buffer, except if the PRF output needs
      // a truncation in the final iteration.
      if(k.remaining_capacity() >= prf_len) {
         m_prf->final(k.next(prf_len));
      } else {
         const auto h = m_prf->final();
         k.append(std::span{h}.first(k.remaining_capacity()));
      }
   });

   BOTAN_ASSERT_NOMSG(k.full());
}

SP800_108_Feedback::SP800_108_Feedback(std::unique_ptr<MessageAuthenticationCode> mac, size_t r, size_t L) :
      m_prf(std::move(mac)), m_counter_bits(r), m_output_length_bits(L) {
   CounterParams::validate_bit_lengths(m_counter_bits, m_output_length_bits);
}

std::string SP800_108_Feedback::name() const {
   // TODO(Botan4): make this always return the explicit lengths
   return (m_counter_bits == 32 && m_output_length_bits == 32)
             ? fmt("SP800-108-Feedback({})", m_prf->name())  // keep the name consistent with previous versions
             : fmt("SP800-108-Feedback({},{},{})", m_prf->name(), m_counter_bits, m_output_length_bits);
}

std::unique_ptr<KDF> SP800_108_Feedback::new_object() const {
   return std::make_unique<SP800_108_Feedback>(m_prf->new_object(), m_counter_bits, m_output_length_bits);
}

void SP800_108_Feedback::perform_kdf(std::span<uint8_t> key,
                                     std::span<const uint8_t> secret,
                                     std::span<const uint8_t> salt,
                                     std::span<const uint8_t> label) const {
   if(key.empty()) {
      return;
   }

   const auto prf_len = m_prf->output_length();
   const auto iv_len = (salt.size() >= prf_len ? prf_len : 0);
   constexpr uint8_t delim = 0;
   const auto params = CounterParams::create_or_throw(key.size(), m_output_length_bits, m_counter_bits, prf_len);

   BufferSlicer s(salt);
   auto prev = s.copy_as_secure_vector(iv_len);
   const auto ctx = s.take(s.remaining());
   BOTAN_ASSERT_NOMSG(s.empty());

   BufferStuffer k(key);
   m_prf->set_key(secret);

   params.generate_blocks([&](auto counter_encoded, auto outlen_encoded) {
      m_prf->update(prev);
      m_prf->update(counter_encoded);
      m_prf->update(label);
      m_prf->update(delim);
      m_prf->update(ctx);
      m_prf->update(outlen_encoded);
      m_prf->final(prev);

      const auto bytes_to_write = std::min(prev.size(), k.remaining_capacity());
      k.append(std::span{prev}.first(bytes_to_write));
   });

   BOTAN_ASSERT_NOMSG(k.full());
}

SP800_108_Pipeline::SP800_108_Pipeline(std::unique_ptr<MessageAuthenticationCode> mac, size_t r, size_t L) :
      m_prf(std::move(mac)), m_counter_bits(r), m_output_length_bits(L) {
   CounterParams::validate_bit_lengths(m_counter_bits, m_output_length_bits);
}

std::string SP800_108_Pipeline::name() const {
   // TODO(Botan4): make this always return the explicit lengths
   return (m_counter_bits == 32 && m_output_length_bits == 32)
             ? fmt("SP800-108-Pipeline({})", m_prf->name())  // keep the name consistent with previous versions
             : fmt("SP800-108-Pipeline({},{},{})", m_prf->name(), m_counter_bits, m_output_length_bits);
}

std::unique_ptr<KDF> SP800_108_Pipeline::new_object() const {
   return std::make_unique<SP800_108_Pipeline>(m_prf->new_object(), m_counter_bits, m_output_length_bits);
}

void SP800_108_Pipeline::perform_kdf(std::span<uint8_t> key,
                                     std::span<const uint8_t> secret,
                                     std::span<const uint8_t> salt,
                                     std::span<const uint8_t> label) const {
   if(key.empty()) {
      return;
   }

   const auto prf_len = m_prf->output_length();
   constexpr uint8_t delim = 0;
   const auto params = CounterParams::create_or_throw(key.size(), m_output_length_bits, m_counter_bits, prf_len);

   BufferStuffer k(key);
   m_prf->set_key(secret);
   secure_vector<uint8_t> scratch;

   params.generate_blocks([&](auto counter_encoded, auto outlen_encoded) {
      auto incorporate_constant_input = [label, salt, outlen_encoded](MessageAuthenticationCode* prf) {
         prf->update(label);
         prf->update(delim);
         prf->update(salt);
         prf->update(outlen_encoded);
      };

      if(scratch.empty()) {
         // A(0)
         incorporate_constant_input(m_prf.get());
         scratch = m_prf->final();
      } else {
         // A(i)
         m_prf->update(scratch);
         m_prf->final(scratch);
      }

      m_prf->update(scratch);
      m_prf->update(counter_encoded);
      incorporate_constant_input(m_prf.get());

      // Write straight into the output buffer, except if the PRF output needs
      // a truncation in the final iteration.
      if(k.remaining_capacity() >= prf_len) {
         m_prf->final(k.next(prf_len));
      } else {
         // This must be the final iteration anyway, so we can just reuse the
         // 'ai' scratch space to avoid allocating another short-lived buffer.
         m_prf->final(scratch);
         k.append(std::span{scratch}.first(k.remaining_capacity()));
      }
   });

   BOTAN_ASSERT_NOMSG(k.full());
}

}  // namespace Botan
