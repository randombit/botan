/*
* ECDSA via BearSSL
* (C) 2015,2016 Jack Lloyd
* (C) 2017 Patrick Wildt
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/exceptn.h>
#include <botan/hash.h>
#include <botan/scan_name.h>
#include <botan/internal/bearssl.h>

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)
  #include <botan/der_enc.h>
  #include <botan/pkcs8.h>
  #include <botan/oids.h>
  #include <botan/internal/pk_ops_impl.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>
#endif

extern "C" {
  #include <bearssl_hash.h>
  #include <bearssl_ec.h>
}

namespace Botan {

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)

namespace {

int BearSSL_EC_curve_for(const OID& oid)
   {
   if(oid.empty())
      return -1;

   const std::string name = OIDS::lookup(oid);

   if(name == "secp256r1")
      return BR_EC_secp256r1;
   if(name == "secp384r1")
      return BR_EC_secp384r1;
   if(name == "secp521r1")
      return BR_EC_secp521r1;

   return -1;
   }

const br_hash_class *BearSSL_hash_class_for(const std::string& emsa)
   {
   if (emsa == "EMSA1(SHA-1)")
      return &br_sha1_vtable;
   if (emsa == "EMSA1(SHA-224)")
      return &br_sha224_vtable;
   if (emsa == "EMSA1(SHA-256)")
      return &br_sha256_vtable;
   if (emsa == "EMSA1(SHA-384)")
      return &br_sha384_vtable;
   if (emsa == "EMSA1(SHA-512)")
      return &br_sha512_vtable;

   return nullptr;
   }
}

#endif

#if defined(BOTAN_HAS_ECDSA)

namespace {

class BearSSL_ECDSA_Verification_Operation final : public PK_Ops::Verification
   {
   public:
      BearSSL_ECDSA_Verification_Operation(const ECDSA_PublicKey& ecdsa, const std::string& emsa) :
         m_order_bits(ecdsa.domain().get_order().bits())
         {
         const int curve = BearSSL_EC_curve_for(ecdsa.domain().get_oid());
         if (curve < 0)
            throw Lookup_Error("BearSSL ECDSA does not support this curve");

         m_hash = BearSSL_hash_class_for(emsa);
         if (m_hash == nullptr)
            throw Lookup_Error("BearSSL ECDSA does not support EMSA " + emsa);

         const SCAN_Name req(emsa);
         m_hf = make_bearssl_hash(req.arg(0));
         if (m_hf == nullptr)
            throw Lookup_Error("BearSSL ECDSA does not support hash " + req.arg(0));

         m_q_buf = EC2OSP(ecdsa.public_point(), PointGFp::UNCOMPRESSED);

         m_key.qlen = m_q_buf.size();
         m_key.q = m_q_buf.data();
         m_key.curve = curve;
         }

      void update(const uint8_t msg[], size_t msg_len) override
         {
         m_hf->update(msg, msg_len);
         }

      bool is_valid_signature(const uint8_t sig[], size_t sig_len) override
         {
         const size_t order_bytes = (m_order_bits + 7) / 8;
         if (sig_len != 2 * order_bytes)
            return false;
         secure_vector<uint8_t> msg = m_hf->final();

         br_ecdsa_vrfy engine = br_ecdsa_vrfy_raw_get_default();
         if (!engine(&br_ec_prime_i31, msg.data(), msg.size(), &m_key, sig, sig_len))
             return false;

         return true;
         }

      size_t max_input_bits() const { return m_order_bits; }

   private:
      br_ec_public_key m_key;
      std::unique_ptr<HashFunction> m_hf;
      secure_vector<uint8_t> m_q_buf;
      const br_hash_class *m_hash;
      size_t m_order_bits;
   };

class BearSSL_ECDSA_Signing_Operation final : public PK_Ops::Signature
   {
   public:
      BearSSL_ECDSA_Signing_Operation(const ECDSA_PrivateKey& ecdsa, const std::string& emsa) :
         m_order_bits(ecdsa.domain().get_order().bits())
         {
         const int curve = BearSSL_EC_curve_for(ecdsa.domain().get_oid());
         if(curve < 0)
            throw Lookup_Error("BearSSL ECDSA does not support this curve");

         m_hash = BearSSL_hash_class_for(emsa);
         if (m_hash == nullptr)
            throw Lookup_Error("BearSSL ECDSA does not support EMSA " + emsa);

         const SCAN_Name req(emsa);
         m_hf = make_bearssl_hash(req.arg(0));
         if (m_hf == nullptr)
            throw Lookup_Error("BearSSL ECDSA does not support hash " + req.arg(0));

         m_x_buf = BigInt::encode_locked(ecdsa.private_value());

         m_key.xlen = m_x_buf.size();
         m_key.x = m_x_buf.data();
         m_key.curve = curve;
         }

      void update(const uint8_t msg[], size_t msg_len) override
         {
         m_hf->update(msg, msg_len);
         }

      secure_vector<uint8_t> sign(RandomNumberGenerator&) override
         {
         const size_t order_bytes = (m_order_bits + 7) / 8;
         secure_vector<uint8_t> sigval(2*order_bytes);

         br_ecdsa_sign engine = br_ecdsa_sign_raw_get_default();
         size_t sign_len = engine(&br_ec_prime_i31, m_hash, m_hf->final().data(), &m_key, sigval.data());
         if (sign_len == 0)
            throw BearSSL_Error("br_ecdsa_sign");

         sigval.resize(sign_len);
         return sigval;
         }

      size_t max_input_bits() const { return m_order_bits; }

   private:
      br_ec_private_key m_key;
      std::unique_ptr<HashFunction> m_hf;
      secure_vector<uint8_t> m_x_buf;
      const br_hash_class *m_hash;
      size_t m_order_bits;
   };

}

std::unique_ptr<PK_Ops::Verification>
make_bearssl_ecdsa_ver_op(const ECDSA_PublicKey& key, const std::string& params)
   {
   return std::unique_ptr<PK_Ops::Verification>(new BearSSL_ECDSA_Verification_Operation(key, params));
   }

std::unique_ptr<PK_Ops::Signature>
make_bearssl_ecdsa_sig_op(const ECDSA_PrivateKey& key, const std::string& params)
   {
   return std::unique_ptr<PK_Ops::Signature>(new BearSSL_ECDSA_Signing_Operation(key, params));
   }

#endif

}
