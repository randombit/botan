/*
* ECDSA and ECDH via OpenSSL
* (C) 2015,2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/openssl.h>

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)
  #include <botan/der_enc.h>
  #include <botan/pkcs8.h>
  #include <botan/oids.h>
  #include <botan/internal/pk_utils.h>
#endif

#if defined(BOTAN_HAS_ECDSA)
  #include <botan/ecdsa.h>
#endif

#if defined(BOTAN_HAS_ECDH)
  #include <botan/ecdh.h>
#endif

#include <openssl/x509.h>
#include <openssl/objects.h>

#if !defined(OPENSSL_NO_EC)
  #include <openssl/ec.h>
#endif

#if !defined(OPENSSL_NO_ECDSA)
  #include <openssl/ecdsa.h>
#endif

#if !defined(OPENSSL_NO_ECDH)
  #include <openssl/ecdh.h>
#endif

namespace Botan {

namespace {

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)

secure_vector<byte> PKCS8_for_openssl(const EC_PrivateKey& ec)
   {
   const PointGFp& pub_key = ec.public_point();
   const BigInt& priv_key = ec.private_value();

   return DER_Encoder()
     .start_cons(SEQUENCE)
        .encode(static_cast<size_t>(1))
        .encode(BigInt::encode_1363(priv_key, priv_key.bytes()), OCTET_STRING)
      .start_cons(ASN1_Tag(0), PRIVATE)
      .raw_bytes(ec.domain().DER_encode(EC_DOMPAR_ENC_OID))
      .end_cons()
      .start_cons(ASN1_Tag(1), PRIVATE)
      .encode(EC2OSP(pub_key, PointGFp::UNCOMPRESSED), BIT_STRING)
      .end_cons()
      .end_cons()
      .get_contents();
   }

int OpenSSL_EC_nid_for(const OID& oid)
   {
   if(oid.empty())
      return -1;

   static const std::map<std::string, int> nid_map = {
      { "secp192r1", NID_X9_62_prime192v1  },
      { "secp224r1", NID_secp224r1 },
      { "secp256r1", NID_X9_62_prime256v1 },
      { "secp384r1", NID_secp384r1 },
      { "secp521r1", NID_secp521r1 },
      // TODO: OpenSSL 1.0.2 added brainpool curves
   };

   const std::string name = OIDS::lookup(oid);
   auto i = nid_map.find(name);
   if(i != nid_map.end())
      return i->second;

   return -1;
   }

#endif

#if defined(BOTAN_HAS_ECDSA) && !defined(OPENSSL_NO_ECDSA)

class OpenSSL_ECDSA_Verification_Operation : public PK_Ops::Verification_with_EMSA
   {
   public:
      typedef ECDSA_PublicKey Key_Type;

      static OpenSSL_ECDSA_Verification_Operation* make(const Spec& spec)
         {
         if(const ECDSA_PublicKey* ecdsa = dynamic_cast<const ECDSA_PublicKey*>(&spec.key()))
            {
            const int nid = OpenSSL_EC_nid_for(ecdsa->domain().get_oid());
            if(nid > 0)
               return new OpenSSL_ECDSA_Verification_Operation(*ecdsa, spec.padding(), nid);
            }

         return nullptr;
         }

      OpenSSL_ECDSA_Verification_Operation(const ECDSA_PublicKey& ecdsa, const std::string& emsa, int nid) :
         PK_Ops::Verification_with_EMSA(emsa), m_ossl_ec(::EC_KEY_new(), ::EC_KEY_free)
         {
         std::unique_ptr<::EC_GROUP, std::function<void (::EC_GROUP*)>> grp(::EC_GROUP_new_by_curve_name(nid),
                                                                            ::EC_GROUP_free);

         if(!grp)
            throw OpenSSL_Error("EC_GROUP_new_by_curve_name");

         ::EC_KEY_set_group(m_ossl_ec.get(), grp.get());

         const secure_vector<byte> enc = EC2OSP(ecdsa.public_point(), PointGFp::UNCOMPRESSED);
         const byte* enc_ptr = enc.data();
         EC_KEY* key_ptr = m_ossl_ec.get();
         if(!::o2i_ECPublicKey(&key_ptr, &enc_ptr, enc.size()))
            throw OpenSSL_Error("o2i_ECPublicKey");

         const EC_GROUP* group = ::EC_KEY_get0_group(m_ossl_ec.get());
         m_order_bits = ::EC_GROUP_get_degree(group);
         }

      size_t message_parts() const override { return 2; }
      size_t message_part_size() const override { return (m_order_bits + 7) / 8; }
      size_t max_input_bits() const override { return m_order_bits; }

      bool with_recovery() const override { return false; }

      bool verify(const byte msg[], size_t msg_len,
                  const byte sig_bytes[], size_t sig_len) override
         {
         if(sig_len != message_part_size() * message_parts())
            return false;

         std::unique_ptr<ECDSA_SIG, std::function<void (ECDSA_SIG*)>> sig(nullptr, ECDSA_SIG_free);
         sig.reset(::ECDSA_SIG_new());

         sig->r = BN_bin2bn(sig_bytes              , sig_len / 2, nullptr);
         sig->s = BN_bin2bn(sig_bytes + sig_len / 2, sig_len / 2, nullptr);

         const int res = ECDSA_do_verify(msg, msg_len, sig.get(), m_ossl_ec.get());
         if(res < 0)
            throw OpenSSL_Error("ECDSA_do_verify");
         return (res == 1);
         }

   private:
      std::unique_ptr<EC_KEY, std::function<void (EC_KEY*)>> m_ossl_ec;
      size_t m_order_bits = 0;
   };

class OpenSSL_ECDSA_Signing_Operation : public PK_Ops::Signature_with_EMSA
   {
   public:
      typedef ECDSA_PrivateKey Key_Type;

      static OpenSSL_ECDSA_Signing_Operation* make(const Spec& spec)
         {
         if(const ECDSA_PrivateKey* ecdsa = dynamic_cast<const ECDSA_PrivateKey*>(&spec.key()))
            {
            const int nid = OpenSSL_EC_nid_for(ecdsa->domain().get_oid());
            if(nid > 0)
               return new OpenSSL_ECDSA_Signing_Operation(*ecdsa, spec.padding());
            }

         return nullptr;
         }

      OpenSSL_ECDSA_Signing_Operation(const ECDSA_PrivateKey& ecdsa, const std::string& emsa) :
         PK_Ops::Signature_with_EMSA(emsa),
         m_ossl_ec(nullptr, ::EC_KEY_free)
         {
         const secure_vector<byte> der = PKCS8_for_openssl(ecdsa);
         const byte* der_ptr = der.data();
         m_ossl_ec.reset(d2i_ECPrivateKey(nullptr, &der_ptr, der.size()));
         if(!m_ossl_ec)
            throw OpenSSL_Error("d2i_ECPrivateKey");

         const EC_GROUP* group = ::EC_KEY_get0_group(m_ossl_ec.get());
         m_order_bits = ::EC_GROUP_get_degree(group);
         }

      secure_vector<byte> raw_sign(const byte msg[], size_t msg_len,
                                   RandomNumberGenerator&) override
         {
         std::unique_ptr<ECDSA_SIG, std::function<void (ECDSA_SIG*)>> sig(nullptr, ECDSA_SIG_free);
         sig.reset(::ECDSA_do_sign(msg, msg_len, m_ossl_ec.get()));

         if(!sig)
            throw OpenSSL_Error("ECDSA_do_sign");

         const size_t order_bytes = message_part_size();
         const size_t r_bytes = BN_num_bytes(sig->r);
         const size_t s_bytes = BN_num_bytes(sig->s);
         secure_vector<byte> sigval(2*order_bytes);
         BN_bn2bin(sig->r, &sigval[order_bytes - r_bytes]);
         BN_bn2bin(sig->s, &sigval[2*order_bytes - s_bytes]);
         return sigval;
         }

      size_t message_parts() const override { return 2; }
      size_t message_part_size() const override { return (m_order_bits + 7) / 8; }
      size_t max_input_bits() const override { return m_order_bits; }

   private:
      std::unique_ptr<EC_KEY, std::function<void (EC_KEY*)>> m_ossl_ec;
      size_t m_order_bits = 0;
   };

BOTAN_REGISTER_TYPE(PK_Ops::Verification, OpenSSL_ECDSA_Verification_Operation, "ECDSA",
                    OpenSSL_ECDSA_Verification_Operation::make,
                    "openssl", BOTAN_OPENSSL_ECDSA_PRIO);

BOTAN_REGISTER_TYPE(PK_Ops::Signature, OpenSSL_ECDSA_Signing_Operation, "ECDSA",
                    OpenSSL_ECDSA_Signing_Operation::make,
                    "openssl", BOTAN_OPENSSL_ECDSA_PRIO);

#endif

#if defined(BOTAN_HAS_ECDH) && !defined(OPENSSL_NO_ECDH)

class OpenSSL_ECDH_KA_Operation : public PK_Ops::Key_Agreement_with_KDF
   {
   public:
      typedef ECDH_PrivateKey Key_Type;

      static OpenSSL_ECDH_KA_Operation* make(const Spec& spec)
         {
         if(const ECDH_PrivateKey* ecdh = dynamic_cast<const ECDH_PrivateKey*>(&spec.key()))
            {
            const int nid = OpenSSL_EC_nid_for(ecdh->domain().get_oid());
            if(nid > 0)
               return new OpenSSL_ECDH_KA_Operation(*ecdh, spec.padding());
            }

         return nullptr;
         }

      OpenSSL_ECDH_KA_Operation(const ECDH_PrivateKey& ecdh, const std::string& kdf) :
         PK_Ops::Key_Agreement_with_KDF(kdf), m_ossl_ec(::EC_KEY_new(), ::EC_KEY_free)
         {
         const secure_vector<byte> der = PKCS8_for_openssl(ecdh);
         const byte* der_ptr = der.data();
         m_ossl_ec.reset(d2i_ECPrivateKey(nullptr, &der_ptr, der.size()));
         if(!m_ossl_ec)
            throw OpenSSL_Error("d2i_ECPrivateKey");
         }

      secure_vector<byte> raw_agree(const byte w[], size_t w_len) override
         {
         const EC_GROUP* group = ::EC_KEY_get0_group(m_ossl_ec.get());
         const size_t out_len = (::EC_GROUP_get_degree(group) + 7) / 8;
         secure_vector<byte> out(out_len);
         EC_POINT* pub_key = ::EC_POINT_new(group);

         if(!pub_key)
            throw OpenSSL_Error("EC_POINT_new");

         const int os2ecp_rc =
            ::EC_POINT_oct2point(group, pub_key, w, w_len, nullptr);

         if(os2ecp_rc != 1)
            throw OpenSSL_Error("EC_POINT_oct2point");

         const int ecdh_rc = ::ECDH_compute_key(out.data(),
                                                out.size(),
                                                pub_key,
                                                m_ossl_ec.get(),
                                                /*KDF*/nullptr);

         if(ecdh_rc <= 0)
            throw OpenSSL_Error("ECDH_compute_key");

         const size_t ecdh_sz = static_cast<size_t>(ecdh_rc);

         if(ecdh_sz > out.size())
            throw Internal_Error("OpenSSL ECDH returned more than requested");

         out.resize(ecdh_sz);
         return out;
         }

   private:
      std::unique_ptr<EC_KEY, std::function<void (EC_KEY*)>> m_ossl_ec;
      size_t m_order_bits = 0;
   };

BOTAN_REGISTER_TYPE(PK_Ops::Key_Agreement, OpenSSL_ECDH_KA_Operation, "ECDH",
                    OpenSSL_ECDH_KA_Operation::make,
                    "openssl", BOTAN_OPENSSL_ECDH_PRIO);

#endif

}

}

