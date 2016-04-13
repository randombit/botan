/*
* Nyberg-Rueppel
* (C) 1999-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pk_utils.h>
#include <botan/nr.h>
#include <botan/keypair.h>
#include <botan/reducer.h>
#include <future>

namespace Botan {

NR_PublicKey::NR_PublicKey(const AlgorithmIdentifier& alg_id,
                           const secure_vector<byte>& key_bits) :
   DL_Scheme_PublicKey(alg_id, key_bits, DL_Group::ANSI_X9_57)
   {
   }

/*
* NR_PublicKey Constructor
*/
NR_PublicKey::NR_PublicKey(const DL_Group& grp, const BigInt& y1)
   {
   m_group = grp;
   m_y = y1;
   }

/*
* Create a NR private key
*/
NR_PrivateKey::NR_PrivateKey(RandomNumberGenerator& rng,
                             const DL_Group& grp,
                             const BigInt& x_arg)
   {
   m_group = grp;
   m_x = x_arg;

   if(m_x == 0)
      m_x = BigInt::random_integer(rng, 2, group_q() - 1);

   m_y = power_mod(group_g(), m_x, group_p());

   if(x_arg == 0)
      gen_check(rng);
   else
      load_check(rng);
   }

NR_PrivateKey::NR_PrivateKey(const AlgorithmIdentifier& alg_id,
                             const secure_vector<byte>& key_bits,
                             RandomNumberGenerator& rng) :
   DL_Scheme_PrivateKey(alg_id, key_bits, DL_Group::ANSI_X9_57)
   {
   m_y = power_mod(group_g(), m_x, group_p());

   load_check(rng);
   }

/*
* Check Private Nyberg-Rueppel Parameters
*/
bool NR_PrivateKey::check_key(RandomNumberGenerator& rng, bool strong) const
   {
   if(!DL_Scheme_PrivateKey::check_key(rng, strong) || m_x >= group_q())
      return false;

   if(!strong)
      return true;

   return KeyPair::signature_consistency_check(rng, *this, "EMSA1(SHA-1)");
   }

namespace {

/**
* Nyberg-Rueppel signature operation
*/
class NR_Signature_Operation : public PK_Ops::Signature_with_EMSA
   {
   public:
      typedef NR_PrivateKey Key_Type;
      NR_Signature_Operation(const NR_PrivateKey& nr, const std::string& emsa) :
         PK_Ops::Signature_with_EMSA(emsa),
         m_q(nr.group_q()),
         m_x(nr.get_x()),
         m_powermod_g_p(nr.group_g(), nr.group_p()),
         m_mod_q(nr.group_q())
         {
         }

      size_t message_parts() const override { return 2; }
      size_t message_part_size() const override { return m_q.bytes(); }
      size_t max_input_bits() const override { return (m_q.bits() - 1); }

      secure_vector<byte> raw_sign(const byte msg[], size_t msg_len,
                                   RandomNumberGenerator& rng) override;
   private:
      const BigInt& m_q;
      const BigInt& m_x;
      Fixed_Base_Power_Mod m_powermod_g_p;
      Modular_Reducer m_mod_q;
   };

secure_vector<byte>
NR_Signature_Operation::raw_sign(const byte msg[], size_t msg_len,
                                 RandomNumberGenerator& rng)
   {
   rng.add_entropy(msg, msg_len);

   BigInt f(msg, msg_len);

   if(f >= m_q)
      throw Invalid_Argument("NR_Signature_Operation: Input is out of range");

   BigInt c, d;

   while(c == 0)
      {
      BigInt k;
      do
         k.randomize(rng, m_q.bits());
      while(k >= m_q);

      c = m_mod_q.reduce(m_powermod_g_p(k) + f);
      d = m_mod_q.reduce(k - m_x * c);
      }

   secure_vector<byte> output(2*m_q.bytes());
   c.binary_encode(&output[output.size() / 2 - c.bytes()]);
   d.binary_encode(&output[output.size() - d.bytes()]);
   return output;
   }


/**
* Nyberg-Rueppel verification operation
*/
class NR_Verification_Operation : public PK_Ops::Verification_with_EMSA
   {
   public:
      typedef NR_PublicKey Key_Type;
      NR_Verification_Operation(const NR_PublicKey& nr, const std::string& emsa) :
         PK_Ops::Verification_with_EMSA(emsa),
         m_q(nr.group_q()), m_y(nr.get_y()), m_powermod_g_p{Fixed_Base_Power_Mod(nr.group_g(), nr.group_p())},
         m_powermod_y_p{Fixed_Base_Power_Mod(m_y, nr.group_p())}, m_mod_p{Modular_Reducer(nr.group_p())},
         m_mod_q{Modular_Reducer(nr.group_q())}
         {}

      size_t message_parts() const override { return 2; }
      size_t message_part_size() const override { return m_q.bytes(); }
      size_t max_input_bits() const override { return (m_q.bits() - 1); }

      bool with_recovery() const override { return true; }

      secure_vector<byte> verify_mr(const byte msg[], size_t msg_len) override;
   private:
      const BigInt& m_q;
      const BigInt& m_y;

      Fixed_Base_Power_Mod m_powermod_g_p, m_powermod_y_p;
      Modular_Reducer m_mod_p, m_mod_q;
   };

secure_vector<byte>
NR_Verification_Operation::verify_mr(const byte msg[], size_t msg_len)
   {
   const BigInt& q = m_mod_q.get_modulus();

   if(msg_len != 2*q.bytes())
      throw Invalid_Argument("NR verification: Invalid signature");

   BigInt c(msg, q.bytes());
   BigInt d(msg + q.bytes(), q.bytes());

   if(c.is_zero() || c >= q || d >= q)
      throw Invalid_Argument("NR verification: Invalid signature");

   auto future_y_c = std::async(std::launch::async, m_powermod_y_p, c);
   BigInt g_d = m_powermod_g_p(d);

   BigInt i = m_mod_p.multiply(g_d, future_y_c.get());
   return BigInt::encode_locked(m_mod_q.reduce(c - i));
   }
}

BOTAN_REGISTER_PK_SIGNATURE_OP("NR", NR_Signature_Operation);
BOTAN_REGISTER_PK_VERIFY_OP("NR", NR_Verification_Operation);

}
