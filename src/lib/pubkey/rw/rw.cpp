/*
* Rabin-Williams
* (C) 1999-2008 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pk_utils.h>
#include <botan/rw.h>
#include <botan/keypair.h>
#include <botan/parsing.h>
#include <botan/reducer.h>
#include <botan/blinding.h>
#include <algorithm>
#include <future>

namespace Botan {

/*
* Create a Rabin-Williams private key
*/
RW_PrivateKey::RW_PrivateKey(RandomNumberGenerator& rng,
                             size_t bits, size_t exp)
   {
   if(bits < 1024)
      throw Invalid_Argument(algo_name() + ": Can't make a key that is only " +
                             std::to_string(bits) + " bits long");
   if(exp < 2 || exp % 2 == 1)
      throw Invalid_Argument(algo_name() + ": Invalid encryption exponent");

   m_e = exp;

   do
      {
      m_p = random_prime(rng, (bits + 1) / 2, m_e / 2, 3, 4);
      m_q = random_prime(rng, bits - m_p.bits(), m_e / 2, ((m_p % 8 == 3) ? 7 : 3), 8);
      m_n = m_p * m_q;
      } while(m_n.bits() != bits);

   m_d = inverse_mod(m_e, lcm(m_p - 1, m_q - 1) >> 1);
   m_d1 = m_d % (m_p - 1);
   m_d2 = m_d % (m_q - 1);
   m_c = inverse_mod(m_q, m_p);

   gen_check(rng);
   }

/*
* Check Private Rabin-Williams Parameters
*/
bool RW_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const
   {
   if(!IF_Scheme_PrivateKey::check_key(rng, strong))
      return false;

   if(!strong)
      return true;

   if((m_e * m_d) % (lcm(m_p - 1, m_q - 1) / 2) != 1)
      return false;

   return KeyPair::signature_consistency_check(rng, *this, "EMSA2(SHA-1)");
   }

namespace {

/**
* Rabin-Williams Signature Operation
*/
class RW_Signature_Operation : public PK_Ops::Signature_with_EMSA
   {
   public:
      typedef RW_PrivateKey Key_Type;

      RW_Signature_Operation(const RW_PrivateKey& rw,
                             const std::string& emsa) :
         PK_Ops::Signature_with_EMSA(emsa),
         m_n(rw.get_n()),
         m_e(rw.get_e()),
         m_q(rw.get_q()),
         m_c(rw.get_c()),
         m_powermod_d1_p(rw.get_d1(), rw.get_p()),
         m_powermod_d2_q(rw.get_d2(), rw.get_q()),
         m_mod_p(rw.get_p()),
         m_blinder(m_n,
                 [this](const BigInt& k) { return power_mod(k, m_e, m_n); },
                 [this](const BigInt& k) { return inverse_mod(k, m_n); })
         {
         }

      size_t max_input_bits() const override { return (m_n.bits() - 1); }

      secure_vector<byte> raw_sign(const byte msg[], size_t msg_len,
                                   RandomNumberGenerator& rng) override;
   private:
      const BigInt& m_n;
      const BigInt& m_e;
      const BigInt& m_q;
      const BigInt& m_c;

      Fixed_Exponent_Power_Mod m_powermod_d1_p, m_powermod_d2_q;
      Modular_Reducer m_mod_p;
      Blinder m_blinder;
   };

secure_vector<byte>
RW_Signature_Operation::raw_sign(const byte msg[], size_t msg_len,
                                 RandomNumberGenerator&)
   {
   BigInt i(msg, msg_len);

   if(i >= m_n || i % 16 != 12)
      throw Invalid_Argument("Rabin-Williams: invalid input");

   if(jacobi(i, m_n) != 1)
      i >>= 1;

   i = m_blinder.blind(i);

   auto future_j1 = std::async(std::launch::async, m_powermod_d1_p, i);
   const BigInt j2 = m_powermod_d2_q(i);
   BigInt j1 = future_j1.get();

   j1 = m_mod_p.reduce(sub_mul(j1, j2, m_c));

   const BigInt r = m_blinder.unblind(mul_add(j1, m_q, j2));

   return BigInt::encode_1363(std::min(r, m_n - r), m_n.bytes());
   }

/**
* Rabin-Williams Verification Operation
*/
class RW_Verification_Operation : public PK_Ops::Verification_with_EMSA
   {
   public:
      typedef RW_PublicKey Key_Type;

      RW_Verification_Operation(const RW_PublicKey& rw, const std::string& emsa) :
         PK_Ops::Verification_with_EMSA(emsa),
         m_n(rw.get_n()), m_powermod_e_n(rw.get_e(), rw.get_n())
         {}

      size_t max_input_bits() const override { return (m_n.bits() - 1); }
      bool with_recovery() const override { return true; }

      secure_vector<byte> verify_mr(const byte msg[], size_t msg_len) override;

   private:
      const BigInt& m_n;
      Fixed_Exponent_Power_Mod m_powermod_e_n;
   };

secure_vector<byte>
RW_Verification_Operation::verify_mr(const byte msg[], size_t msg_len)
   {
   BigInt m(msg, msg_len);

   if((m > (m_n >> 1)) || m.is_negative())
      throw Invalid_Argument("RW signature verification: m > n / 2 || m < 0");

   BigInt r = m_powermod_e_n(m);
   if(r % 16 == 12)
      return BigInt::encode_locked(r);
   if(r % 8 == 6)
      return BigInt::encode_locked(2*r);

   r = m_n - r;
   if(r % 16 == 12)
      return BigInt::encode_locked(r);
   if(r % 8 == 6)
      return BigInt::encode_locked(2*r);

   throw Invalid_Argument("RW signature verification: Invalid signature");
   }

BOTAN_REGISTER_PK_SIGNATURE_OP("RW", RW_Signature_Operation);
BOTAN_REGISTER_PK_VERIFY_OP("RW", RW_Verification_Operation);

}

}
