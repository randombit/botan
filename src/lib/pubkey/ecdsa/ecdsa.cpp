/*
* ECDSA implemenation
* (C) 2007 Manuel Hartl, FlexSecure GmbH
*     2007 Falko Strenzke, FlexSecure GmbH
*     2008-2010,2015,2016,2018 Jack Lloyd
*     2016 René Korthaus
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/ecdsa.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/point_mul.h>
#include <botan/keypair.h>
#include <botan/reducer.h>
#include <botan/emsa.h>

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
  #include <botan/rfc6979.h>
#endif

#if defined(BOTAN_HAS_OPENSSL)
  #include <botan/internal/openssl.h>
#endif

namespace Botan {

namespace {

PointGFp recover_ecdsa_public_key(const EC_Group& group,
                                  const std::vector<uint8_t>& msg,
                                  const BigInt& r,
                                  const BigInt& s,
                                  uint8_t v)
   {
   if(group.get_cofactor() != 1)
      throw Invalid_Argument("ECDSA public key recovery only supported for prime order groups");

   if(v > 4)
      throw Invalid_Argument("Unexpected v param for ECDSA public key recovery");

   const uint8_t y_odd = v % 2;
   const uint8_t add_order = v >> 1;

   const BigInt& group_order = group.get_order();
   const size_t p_bytes = group.get_p_bytes();

   try
      {
      const BigInt e(msg.data(), msg.size(), group.get_order_bits());
      const BigInt r_inv = group.inverse_mod_order(r);

      BigInt x = r + add_order*group_order;

      std::vector<uint8_t> X(p_bytes + 1);

      X[0] = 0x02 | y_odd;
      BigInt::encode_1363(&X[1], p_bytes, x);

      const PointGFp R = group.OS2ECP(X);

      if((R*group_order).is_zero() == false)
         throw Decoding_Error("Unable to recover ECDSA public key");

      // Compute r_inv * (s*R - eG)
      PointGFp_Multi_Point_Precompute RG_mul(R, group.get_base_point());
      const BigInt ne = group.mod_order(group_order - e);
      return r_inv * RG_mul.multi_exp(s, ne);
      }
   catch(...)
      {
      // continue on and throw
      }

   throw Decoding_Error("Failed to recover ECDSA public key from signature/msg pair");
   }

}

ECDSA_PublicKey::ECDSA_PublicKey(const EC_Group& group,
                                 const std::vector<uint8_t>& msg,
                                 const BigInt& r,
                                 const BigInt& s,
                                 uint8_t v) :
   EC_PublicKey(group, recover_ecdsa_public_key(group, msg, r, s, v)) {}


uint8_t ECDSA_PublicKey::recovery_param(const std::vector<uint8_t>& msg,
                                        const BigInt& r,
                                        const BigInt& s) const
   {
   for(uint8_t v = 0; v != 4; ++v)
      {
      try
         {
         PointGFp R = recover_ecdsa_public_key(this->domain(), msg, r, s, v);

         if(R == this->public_point())
            {
            return v;
            }
         }
      catch(Decoding_Error&)
         {
         // try the next v
         }
      }

   throw Internal_Error("Could not determine ECDSA recovery parameter");
   }

bool ECDSA_PrivateKey::check_key(RandomNumberGenerator& rng,
                                 bool strong) const
   {
   if(!public_point().on_the_curve())
      return false;

   if(!strong)
      return true;

   return KeyPair::signature_consistency_check(rng, *this, "EMSA1(SHA-256)");
   }

namespace {

/**
* ECDSA signature operation
*/
class ECDSA_Signature_Operation final : public PK_Ops::Signature_with_EMSA
   {
   public:

      ECDSA_Signature_Operation(const ECDSA_PrivateKey& ecdsa,
                                const std::string& emsa,
                                RandomNumberGenerator& rng) :
         PK_Ops::Signature_with_EMSA(emsa),
         m_group(ecdsa.domain()),
         m_x(ecdsa.private_value())
         {
#if defined(BOTAN_HAS_RFC6979_GENERATOR)
         m_rfc6979.reset(new RFC6979_Nonce_Generator(hash_for_emsa(emsa), m_group.get_order(), m_x));
#endif

         m_b = m_group.random_scalar(rng);
         m_b_inv = m_group.inverse_mod_order(m_b);
         }

      size_t signature_length() const override { return 2*m_group.get_order_bytes(); }

      size_t max_input_bits() const override { return m_group.get_order_bits(); }

      secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len,
                                      RandomNumberGenerator& rng) override;

   private:
      const EC_Group m_group;
      const BigInt& m_x;

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
      std::unique_ptr<RFC6979_Nonce_Generator> m_rfc6979;
#endif

      std::vector<BigInt> m_ws;

      BigInt m_b, m_b_inv;
   };

secure_vector<uint8_t>
ECDSA_Signature_Operation::raw_sign(const uint8_t msg[], size_t msg_len,
                                    RandomNumberGenerator& rng)
   {
   BigInt m(msg, msg_len, m_group.get_order_bits());

#if defined(BOTAN_HAS_RFC6979_GENERATOR)
   const BigInt k = m_rfc6979->nonce_for(m);
#else
   const BigInt k = m_group.random_scalar(rng);
#endif

   const BigInt r = m_group.mod_order(
      m_group.blinded_base_point_multiply_x(k, rng, m_ws));

   const BigInt k_inv = m_group.inverse_mod_order(k);

   /*
   * Blind the input message and compute x*r+m as (x*r*b + m*b)/b
   */
   m_b = m_group.square_mod_order(m_b);
   m_b_inv = m_group.square_mod_order(m_b_inv);

   m = m_group.multiply_mod_order(m_b, m_group.mod_order(m));
   const BigInt xr_m = m_group.mod_order(m_group.multiply_mod_order(m_x, m_b, r) + m);

   const BigInt s = m_group.multiply_mod_order(k_inv, xr_m, m_b_inv);

   // With overwhelming probability, a bug rather than actual zero r/s
   if(r.is_zero() || s.is_zero())
      throw Internal_Error("During ECDSA signature generated zero r/s");

   return BigInt::encode_fixed_length_int_pair(r, s, m_group.get_order_bytes());
   }

/**
* ECDSA verification operation
*/
class ECDSA_Verification_Operation final : public PK_Ops::Verification_with_EMSA
   {
   public:
      ECDSA_Verification_Operation(const ECDSA_PublicKey& ecdsa,
                                   const std::string& emsa) :
         PK_Ops::Verification_with_EMSA(emsa),
         m_group(ecdsa.domain()),
         m_gy_mul(m_group.get_base_point(), ecdsa.public_point())
         {
         }

      size_t max_input_bits() const override { return m_group.get_order_bits(); }

      bool with_recovery() const override { return false; }

      bool verify(const uint8_t msg[], size_t msg_len,
                  const uint8_t sig[], size_t sig_len) override;
   private:
      const EC_Group m_group;
      const PointGFp_Multi_Point_Precompute m_gy_mul;
   };

bool ECDSA_Verification_Operation::verify(const uint8_t msg[], size_t msg_len,
                                          const uint8_t sig[], size_t sig_len)
   {
   if(sig_len != m_group.get_order_bytes() * 2)
      return false;

   const BigInt e(msg, msg_len, m_group.get_order_bits());

   const BigInt r(sig, sig_len / 2);
   const BigInt s(sig + sig_len / 2, sig_len / 2);

   if(r <= 0 || r >= m_group.get_order() || s <= 0 || s >= m_group.get_order())
      return false;

   const BigInt w = m_group.inverse_mod_order(s);

   const BigInt u1 = m_group.multiply_mod_order(m_group.mod_order(e), w);
   const BigInt u2 = m_group.multiply_mod_order(r, w);
   const PointGFp R = m_gy_mul.multi_exp(u1, u2);

   if(R.is_zero())
      return false;

   const BigInt v = m_group.mod_order(R.get_affine_x());
   return (v == r);
   }

}

std::unique_ptr<PK_Ops::Verification>
ECDSA_PublicKey::create_verification_op(const std::string& params,
                                        const std::string& provider) const
   {
#if defined(BOTAN_HAS_OPENSSL)
   if(provider == "openssl" || provider.empty())
      {
      try
         {
         return make_openssl_ecdsa_ver_op(*this, params);
         }
      catch(Lookup_Error& e)
         {
         if(provider == "openssl")
            throw;
         }
      }
#endif

   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Verification>(new ECDSA_Verification_Operation(*this, params));

   throw Provider_Not_Found(algo_name(), provider);
   }

std::unique_ptr<PK_Ops::Signature>
ECDSA_PrivateKey::create_signature_op(RandomNumberGenerator& rng,
                                      const std::string& params,
                                      const std::string& provider) const
   {
#if defined(BOTAN_HAS_OPENSSL)
   if(provider == "openssl" || provider.empty())
      {
      try
         {
         return make_openssl_ecdsa_sig_op(*this, params);
         }
      catch(Lookup_Error& e)
         {
         if(provider == "openssl")
            throw;
         }
      }
#endif

   if(provider == "base" || provider.empty())
      return std::unique_ptr<PK_Ops::Signature>(new ECDSA_Signature_Operation(*this, params, rng));

   throw Provider_Not_Found(algo_name(), provider);
   }

}
