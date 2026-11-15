/*
* Format Preserving Encryption (FF1 from NIST SP 800-38G)
* (C) 2026 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/fpe_ff1.h>

#include <botan/block_cipher.h>
#include <botan/exceptn.h>
#include <botan/mem_ops.h>
#include <botan/internal/bit_ops.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>
#include <botan/internal/mp_core.h>
#include <array>
#include <vector>

namespace Botan {

namespace {

constexpr size_t FF1_ROUNDS = 10;
constexpr size_t FF1_BS = 16;
constexpr size_t FF1_MIN_DOMAIN = 1000000;

/*
* Conversions between numeral strings and integers, plus the modular addition
* of the Feistel round.
*
* The integers are fixed length little endian word arrays whose sizes depend
* only on the radix and the length of the string. Everything here runs in
* constant time with respect to the numerals; the radix is public.
*/
class FF1_Arithmetic final {
   public:
      explicit FF1_Arithmetic(size_t radix) :
            m_radix(static_cast<word>(radix)),
            m_powers(powers_fitting_in_word(m_radix)),
            m_div_radix(divide_precomp<word>::setup_vartime(m_radix)),
            m_div_chunk(divide_precomp<word>::setup_vartime(m_powers.back())) {}

      /**
      * Set z to NUM_radix(numerals)
      *
      * z must be large enough to hold the largest possible value
      */
      void num(std::span<word> z, std::span<const uint16_t> numerals) const {
         clear_mem(z);

         const size_t chunk_len = m_powers.size() - 1;

         for(size_t i = 0; i < numerals.size(); i += chunk_len) {
            const size_t take = std::min(chunk_len, numerals.size() - i);

            word chunk = 0;
            for(size_t j = 0; j != take; ++j) {
               chunk = chunk * m_radix + numerals[i + j];
            }

            // z = z * radix^take + chunk
            word carry = chunk;
            for(word& w : z) {
               w = word_madd2(w, m_powers[take], &carry);
            }
         }
      }

      /**
      * Return the number of bytes needed to encode radix^len - 1
      */
      size_t bytes_for(size_t len) const {
         // Each numeral contributes at most 16 bits
         const size_t numerals_per_word = WordInfo<word>::bits / 16;

         std::vector<word> z(ceil_division(len, numerals_per_word));
         const std::vector<uint16_t> max_numerals(len, static_cast<uint16_t>(m_radix - 1));
         this->num(z, max_numerals);

         size_t bits = 0;
         for(size_t i = 0; i != z.size(); ++i) {
            if(z[i] != 0) {
               bits = i * WordInfo<word>::bits + high_bit(z[i]);
            }
         }

         return ceil_division<size_t>(bits, 8);
      }

      /**
      * Set numerals to STR_radix(y mod radix^m) where m is the length of numerals
      *
      * The value of y is destroyed
      */
      void low_numerals(std::span<uint16_t> numerals, std::span<word> y) const {
         const size_t chunk_len = m_powers.size() - 1;

         size_t remaining = numerals.size();

         while(remaining > 0) {
            // y, chunk = divmod(y, radix^chunk_len)
            word chunk = 0;
            for(size_t i = y.size(); i-- > 0;) {
               const auto [q, r] = m_div_chunk.divmod_2to1_vartime(chunk, y[i]);
               y[i] = q;
               chunk = r;
            }

            const size_t take = std::min(chunk_len, remaining);
            for(size_t j = 0; j != take; ++j) {
               const auto [q, r] = m_div_radix.divmod_2to1_vartime(0, chunk);
               remaining -= 1;
               numerals[remaining] = static_cast<uint16_t>(r);
               chunk = q;
            }
         }
      }

      /**
      * Set x to STR_radix((NUM_radix(x) + NUM_radix(y)) mod radix^m)
      */
      void add(std::span<uint16_t> x, std::span<const uint16_t> y) const {
         const uint32_t radix = static_cast<uint32_t>(m_radix);

         uint32_t carry = 0;
         for(size_t i = x.size(); i-- > 0;) {
            const uint32_t sum = static_cast<uint32_t>(x[i]) + y[i] + carry;
            const auto wrapped = CT::Mask<uint32_t>::is_gte(sum, radix);
            x[i] = static_cast<uint16_t>(sum - wrapped.if_set_return(radix));
            carry = wrapped.if_set_return(1);
         }
      }

      /**
      * Set x to STR_radix((NUM_radix(x) - NUM_radix(y)) mod radix^m)
      */
      void sub(std::span<uint16_t> x, std::span<const uint16_t> y) const {
         const uint32_t radix = static_cast<uint32_t>(m_radix);

         uint32_t borrow = 0;
         for(size_t i = x.size(); i-- > 0;) {
            const uint32_t diff = static_cast<uint32_t>(x[i]) - y[i] - borrow;
            const auto wrapped = CT::Mask<uint32_t>::expand_top_bit(diff);
            x[i] = static_cast<uint16_t>(diff + wrapped.if_set_return(radix));
            borrow = wrapped.if_set_return(1);
         }
      }

   private:
      // Returns radix^0, radix^1, ... for all powers that fit into a word
      static std::vector<word> powers_fitting_in_word(word radix) {
         std::vector<word> powers = {1, radix};
         while(powers.back() <= WordInfo<word>::max / radix) {
            powers.push_back(powers.back() * radix);
         }
         return powers;
      }

      word m_radix;
      std::vector<word> m_powers;
      divide_precomp<word> m_div_radix;
      divide_precomp<word> m_div_chunk;
};

size_t ff1_minimum_length(size_t radix) {
   size_t len = 1;
   uint64_t domain = radix;

   while(len < 2 || domain < FF1_MIN_DOMAIN) {
      domain *= radix;
      len += 1;
   }

   return len;
}

}  // namespace

FPE_FF1::FPE_FF1(size_t radix) : m_radix(radix), m_min_length(0) {
   if(radix < 2 || radix > 65536) {
      throw Invalid_Argument("FPE_FF1 radix must be between 2 and 65536");
   }

   m_min_length = ff1_minimum_length(radix);
}

FPE_FF1::~FPE_FF1() = default;

FPE_FF1::FPE_FF1(FPE_FF1&& other) noexcept = default;

Key_Length_Specification FPE_FF1::key_spec() const {
   return Key_Length_Specification(16, 32, 8);
}

bool FPE_FF1::has_keying_material() const {
   return m_cipher != nullptr && m_cipher->has_keying_material();
}

std::string FPE_FF1::name() const {
   return "FF1(AES)";
}

void FPE_FF1::clear() {
   m_cipher.reset();
}

void FPE_FF1::key_schedule(std::span<const uint8_t> key) {
   m_cipher = BlockCipher::create_or_throw(fmt("AES-{}", key.size() * 8));
   m_cipher->set_key(key);
}

void FPE_FF1::encrypt(std::span<uint16_t> x, std::span<const uint8_t> tweak) const {
   crypt(x, tweak, true);
}

void FPE_FF1::decrypt(std::span<uint16_t> x, std::span<const uint8_t> tweak) const {
   crypt(x, tweak, false);
}

void FPE_FF1::crypt(std::span<uint16_t> x, std::span<const uint8_t> tweak, bool encrypting) const {
   assert_key_material_set();

   const size_t n = x.size();
   const size_t t = tweak.size();

   if(n < m_min_length) {
      throw Invalid_Argument("FPE_FF1 input is too short");
   }

   if(static_cast<uint64_t>(n) > 0xFFFFFFFF || static_cast<uint64_t>(t) > 0xFFFFFFFF) {
      throw Invalid_Argument("FPE_FF1 input or tweak is too long");
   }

   auto invalid_numeral = CT::Mask<size_t>::cleared();
   for(const uint16_t numeral : x) {
      invalid_numeral |= CT::Mask<size_t>::is_gte(numeral, m_radix);
   }

   if(invalid_numeral.as_bool()) {
      throw Invalid_Argument("FPE_FF1 input contains a numeral outside the radix");
   }

   const FF1_Arithmetic arith(m_radix);

   const size_t u = n / 2;
   const size_t v = n - u;
   const size_t b = arith.bytes_for(v);
   const size_t d = 4 * ceil_division<size_t>(b, 4) + 4;

   const uint32_t radix32 = static_cast<uint32_t>(m_radix);

   std::array<uint8_t, FF1_BS> P = {1, 2, 1, get_byte<1>(radix32), get_byte<2>(radix32), get_byte<3>(radix32), 10, 0};
   P[7] = static_cast<uint8_t>(u);
   store_be(static_cast<uint32_t>(n), &P[8]);
   store_be(static_cast<uint32_t>(t), &P[12]);

   // Q = T || zero padding || round || NUM_radix(B)
   const size_t round_offset = t + (FF1_BS - (t + b + 1) % FF1_BS) % FF1_BS;
   secure_vector<uint8_t> Q(round_offset + 1 + b);
   std::copy(tweak.begin(), tweak.end(), Q.begin());
   const std::span<uint8_t> num_bytes = std::span(Q).last(b);

   // The blocks of Q preceding the one containing the round number are the same in each round
   const size_t fixed_blocks = round_offset / FF1_BS;
   const std::span<const uint8_t> varying_blocks = std::span(Q).subspan(fixed_blocks * FF1_BS);

   std::array<uint8_t, FF1_BS> prf_prefix{};
   m_cipher->encrypt(P.data(), prf_prefix.data());
   for(size_t i = 0; i != fixed_blocks; ++i) {
      xor_buf(prf_prefix.data(), &Q[i * FF1_BS], FF1_BS);
      m_cipher->encrypt(prf_prefix.data());
   }

   const size_t word_bytes = sizeof(word);

   secure_vector<word> num(ceil_division(b, word_bytes));
   secure_vector<word> y(ceil_division(d, word_bytes));
   secure_vector<uint8_t> S(ceil_division(d, FF1_BS) * FF1_BS);
   secure_vector<uint16_t> y_numerals(v);

   secure_vector<uint16_t> A(x.begin(), x.begin() + u);
   secure_vector<uint16_t> B(x.begin() + u, x.end());

   for(size_t r = 0; r != FF1_ROUNDS; ++r) {
      const size_t round = encrypting ? r : (FF1_ROUNDS - 1 - r);

      // Encryption sets A = A + F(B), decryption sets B = B - F(A)
      const auto& src = encrypting ? B : A;
      auto& dst = encrypting ? A : B;

      Q[round_offset] = static_cast<uint8_t>(round);

      arith.num(num, src);
      for(size_t i = 0; i != b; ++i) {
         num_bytes[b - 1 - i] = static_cast<uint8_t>(num[i / word_bytes] >> (8 * (i % word_bytes)));
      }

      // R = PRF(P || Q)
      copy_mem(S.data(), prf_prefix.data(), FF1_BS);
      for(size_t i = 0; i != varying_blocks.size(); i += FF1_BS) {
         xor_buf(S.data(), &varying_blocks[i], FF1_BS);
         m_cipher->encrypt(S.data());
      }

      // S = R || CIPH(R ^ 1) || CIPH(R ^ 2) ...
      const size_t S_blocks = S.size() / FF1_BS;
      for(size_t i = 1; i != S_blocks; ++i) {
         uint8_t counter[4] = {0};
         store_be(static_cast<uint32_t>(i), counter);
         copy_mem(&S[i * FF1_BS], S.data(), FF1_BS);
         xor_buf(&S[i * FF1_BS + FF1_BS - 4], counter, 4);
      }
      if(S_blocks > 1) {
         m_cipher->encrypt_n(&S[FF1_BS], &S[FF1_BS], S_blocks - 1);
      }

      // y = NUM(first d bytes of S)
      clear_mem(y.data(), y.size());
      for(size_t i = 0; i != d; ++i) {
         y[i / word_bytes] |= static_cast<word>(S[d - 1 - i]) << (8 * (i % word_bytes));
      }

      const auto y_mod = std::span(y_numerals).first(dst.size());
      arith.low_numerals(y_mod, y);

      if(encrypting) {
         arith.add(dst, y_mod);
      } else {
         arith.sub(dst, y_mod);
      }

      std::swap(A, B);
   }

   std::copy(A.begin(), A.end(), x.begin());
   std::copy(B.begin(), B.end(), x.begin() + u);
}

}  // namespace Botan
