/*
* Diffie-Hellman
* (C) 1999-2007 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/pk_utils.h>
#include <botan/dh.h>
#include <botan/workfactor.h>
#include <botan/pow_mod.h>
#include <botan/blinding.h>

namespace Botan {

/*
* DH_PublicKey Constructor
*/
DH_PublicKey::DH_PublicKey(const DL_Group& grp, const BigInt& y1)
   {
   group = grp;
   y = y1;
   }

/*
* Return the public value for key agreement
*/
std::vector<byte> DH_PublicKey::public_value() const
   {
   return unlock(BigInt::encode_1363(y, group_p().bytes()));
   }

/*
* Create a DH private key
*/
DH_PrivateKey::DH_PrivateKey(RandomNumberGenerator& rng,
                             const DL_Group& grp,
                             const BigInt& x_arg)
   {
   group = grp;
   x = x_arg;

   if(x == 0)
      {
      const BigInt& p = group_p();
      x.randomize(rng, 2 * dl_work_factor(p.bits()));
      }

   if(y == 0)
      y = power_mod(group_g(), x, group_p());

   if(x == 0)
      gen_check(rng);
   else
      load_check(rng);
   }

/*
* Load a DH private key
*/
DH_PrivateKey::DH_PrivateKey(const AlgorithmIdentifier& alg_id,
                             const secure_vector<byte>& key_bits,
                             RandomNumberGenerator& rng) :
   DL_Scheme_PrivateKey(alg_id, key_bits, DL_Group::ANSI_X9_42)
   {
   if(y == 0)
      y = power_mod(group_g(), x, group_p());

   load_check(rng);
   }

/*
* Return the public value for key agreement
*/
std::vector<byte> DH_PrivateKey::public_value() const
   {
   return DH_PublicKey::public_value();
   }

namespace {

/**
* DH operation
*/
class DH_KA_Operation : public PK_Ops::Key_Agreement
   {
   public:
      typedef DH_PrivateKey Key_Type;
      DH_KA_Operation(const DH_PrivateKey& key, const std::string&);

      secure_vector<byte> agree(const byte w[], size_t w_len);
   private:
      const BigInt& m_p;

      Fixed_Exponent_Power_Mod m_powermod_x_p;
      Blinder m_blinder;
   };

DH_KA_Operation::DH_KA_Operation(const DH_PrivateKey& dh, const std::string&) :
   m_p(dh.group_p()),
   m_powermod_x_p(dh.get_x(), m_p),
   m_blinder(m_p,
             [](const BigInt& k) { return k; },
             [this](const BigInt& k) { return m_powermod_x_p(inverse_mod(k, m_p)); })
   {
   }

secure_vector<byte> DH_KA_Operation::agree(const byte w[], size_t w_len)
   {
   BigInt input = BigInt::decode(w, w_len);

   if(input <= 1 || input >= m_p - 1)
      throw Invalid_Argument("DH agreement - invalid key provided");

   BigInt r = m_blinder.unblind(m_powermod_x_p(m_blinder.blind(input)));

   return BigInt::encode_1363(r, m_p.bytes());
   }

}

BOTAN_REGISTER_PK_KEY_AGREE_OP("DH", DH_KA_Operation);

}
