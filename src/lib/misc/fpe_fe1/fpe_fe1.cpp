/*
* Format Preserving Encryption (FE1 scheme)
* (C) 2009,2018 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/fpe_fe1.h>

#include <botan/mac.h>
#include <botan/numthry.h>
#include <botan/reducer.h>
#include <botan/internal/divide.h>
#include <botan/internal/fmt.h>
#include <botan/internal/loadstor.h>

namespace Botan {

namespace {

// Normally FPE is for SSNs, CC#s, etc, nothing too big
const size_t MAX_N_BYTES = 128 / 8;

/*
* Factor n into a and b which are as close together as possible.
* Assumes n is composed mostly of small factors which is the case for
* typical uses of FPE (typically, n is a power of 10)
*/
void factor(BigInt n, BigInt& a, BigInt& b) {
   a = BigInt::one();
   b = BigInt::one();

   size_t n_low_zero = low_zero_bits(n);

   a <<= (n_low_zero / 2);
   b <<= n_low_zero - (n_low_zero / 2);
   n >>= n_low_zero;

   for(size_t i = 0; i != PRIME_TABLE_SIZE; ++i) {
      while(n % PRIMES[i] == 0) {
         a *= PRIMES[i];
         if(a > b) {
            std::swap(a, b);
         }
         n /= BigInt::from_word(PRIMES[i]);
      }
   }

   if(a > b) {
      std::swap(a, b);
   }
   a *= n;

   if(a <= 1 || b <= 1) {
      throw Internal_Error("Could not factor n for use in FPE");
   }
}

}  // namespace

FPE_FE1::FPE_FE1(const BigInt& n, size_t rounds, bool compat_mode, std::string_view mac_algo) : m_rounds(rounds) {
   if(m_rounds < 3) {
      throw Invalid_Argument("FPE_FE1 rounds too small");
   }

   m_mac = MessageAuthenticationCode::create_or_throw(mac_algo);

   m_n_bytes = n.serialize();

   if(m_n_bytes.size() > MAX_N_BYTES) {
      throw Invalid_Argument("N is too large for FPE encryption");
   }

   factor(n, m_a, m_b);

   if(compat_mode) {
      if(m_a < m_b) {
         std::swap(m_a, m_b);
      }
   } else {
      if(m_a > m_b) {
         std::swap(m_a, m_b);
      }
   }

   // The modulus is usually a system parameter and anyway is easily deduced from
   // the ciphertexts
   mod_a = std::make_unique<Modular_Reducer>(Modular_Reducer::for_public_modulus(m_a));
}

FPE_FE1::~FPE_FE1() = default;

void FPE_FE1::clear() {
   m_mac->clear();
}

std::string FPE_FE1::name() const {
   return fmt("FPE_FE1({},{})", m_mac->name(), m_rounds);
}

Key_Length_Specification FPE_FE1::key_spec() const {
   return m_mac->key_spec();
}

bool FPE_FE1::has_keying_material() const {
   return m_mac->has_keying_material();
}

void FPE_FE1::key_schedule(std::span<const uint8_t> key) {
   m_mac->set_key(key);
}

BigInt FPE_FE1::F(const BigInt& R,
                  size_t round,
                  const secure_vector<uint8_t>& tweak_mac,
                  secure_vector<uint8_t>& tmp) const {
   tmp = R.serialize<secure_vector<uint8_t>>();

   m_mac->update(tweak_mac);
   m_mac->update_be(static_cast<uint32_t>(round));

   m_mac->update_be(static_cast<uint32_t>(tmp.size()));
   m_mac->update(tmp.data(), tmp.size());

   tmp = m_mac->final();
   return BigInt::from_bytes(tmp);
}

secure_vector<uint8_t> FPE_FE1::compute_tweak_mac(const uint8_t tweak[], size_t tweak_len) const {
   m_mac->update_be(static_cast<uint32_t>(m_n_bytes.size()));
   m_mac->update(m_n_bytes.data(), m_n_bytes.size());

   m_mac->update_be(static_cast<uint32_t>(tweak_len));
   if(tweak_len > 0) {
      m_mac->update(tweak, tweak_len);
   }

   return m_mac->final();
}

BigInt FPE_FE1::encrypt(const BigInt& input, const uint8_t tweak[], size_t tweak_len) const {
   const secure_vector<uint8_t> tweak_mac = compute_tweak_mac(tweak, tweak_len);

   BigInt X = input;

   secure_vector<uint8_t> tmp;

   BigInt L, R, Fi;
   for(size_t i = 0; i != m_rounds; ++i) {
      ct_divide(X, m_b, L, R);
      Fi = F(R, i, tweak_mac, tmp);
      X = m_a * R + mod_a->reduce(L + Fi);
   }

   return X;
}

BigInt FPE_FE1::decrypt(const BigInt& input, const uint8_t tweak[], size_t tweak_len) const {
   const secure_vector<uint8_t> tweak_mac = compute_tweak_mac(tweak, tweak_len);

   BigInt X = input;
   secure_vector<uint8_t> tmp;

   BigInt W, R, Fi;
   for(size_t i = 0; i != m_rounds; ++i) {
      ct_divide(X, m_a, R, W);

      Fi = F(R, m_rounds - i - 1, tweak_mac, tmp);
      X = m_b * mod_a->reduce(W - Fi) + R;
   }

   return X;
}

BigInt FPE_FE1::encrypt(const BigInt& x, uint64_t tweak) const {
   uint8_t tweak8[8];
   store_be(tweak, tweak8);
   return encrypt(x, tweak8, sizeof(tweak8));
}

BigInt FPE_FE1::decrypt(const BigInt& x, uint64_t tweak) const {
   uint8_t tweak8[8];
   store_be(tweak, tweak8);
   return decrypt(x, tweak8, sizeof(tweak8));
}

namespace FPE {

BigInt fe1_encrypt(const BigInt& n, const BigInt& X, const SymmetricKey& key, const std::vector<uint8_t>& tweak) {
   FPE_FE1 fpe(n, 3, true, "HMAC(SHA-256)");
   fpe.set_key(key);
   return fpe.encrypt(X, tweak.data(), tweak.size());
}

BigInt fe1_decrypt(const BigInt& n, const BigInt& X, const SymmetricKey& key, const std::vector<uint8_t>& tweak) {
   FPE_FE1 fpe(n, 3, true, "HMAC(SHA-256)");
   fpe.set_key(key);
   return fpe.decrypt(X, tweak.data(), tweak.size());
}

}  // namespace FPE

}  // namespace Botan
