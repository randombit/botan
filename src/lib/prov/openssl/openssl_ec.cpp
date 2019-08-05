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
  #include <botan/internal/pk_ops_impl.h>
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

#if defined(BOTAN_HAS_ECC_PUBLIC_KEY_CRYPTO)

namespace {

secure_vector<uint8_t> PKCS8_for_openssl(const EC_PrivateKey& ec)
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
      .encode(pub_key.encode(PointGFp::UNCOMPRESSED), BIT_STRING)
      .end_cons()
      .end_cons()
      .get_contents();
   }

int OpenSSL_EC_curve_builtin(int nid)
   {
   // the NID macro is still defined even though the curve may not be
   // supported, so we need to check the list of builtin curves at runtime
   EC_builtin_curve builtin_curves[100];
   size_t num = 0;

   if (!(num = EC_get_builtin_curves(builtin_curves, sizeof(builtin_curves))))
      {
      return -1;
      }

   for(size_t i = 0; i < num; ++i)
      {
      if(builtin_curves[i].nid == nid)
         {
         return nid;
         }
      }

   return -1;
   }

int OpenSSL_EC_nid_for(const OID& oid)
   {
   if(oid.empty())
      return -1;

   const std::string name = oid.to_formatted_string();

   if(name == "secp192r1")
      return OpenSSL_EC_curve_builtin(NID_X9_62_prime192v1);
   if(name == "secp224r1")
      return OpenSSL_EC_curve_builtin(NID_secp224r1);
   if(name == "secp256r1")
      return OpenSSL_EC_curve_builtin(NID_X9_62_prime256v1);
   if(name == "secp384r1")
      return OpenSSL_EC_curve_builtin(NID_secp384r1);
   if(name == "secp521r1")
      return OpenSSL_EC_curve_builtin(NID_secp521r1);

   // OpenSSL 1.0.2 added brainpool curves
#if OPENSSL_VERSION_NUMBER >= 0x1000200fL
   if(name == "brainpool160r1")
      return OpenSSL_EC_curve_builtin(NID_brainpoolP160r1);
   if(name == "brainpool192r1")
      return OpenSSL_EC_curve_builtin(NID_brainpoolP192r1);
   if(name == "brainpool224r1")
      return OpenSSL_EC_curve_builtin(NID_brainpoolP224r1);
   if(name == "brainpool256r1")
      return OpenSSL_EC_curve_builtin(NID_brainpoolP256r1);
   if(name == "brainpool320r1")
      return OpenSSL_EC_curve_builtin(NID_brainpoolP320r1);
   if(name == "brainpool384r1")
      return OpenSSL_EC_curve_builtin(NID_brainpoolP384r1);
   if(name == "brainpool512r1")
      return OpenSSL_EC_curve_builtin(NID_brainpoolP512r1);
#endif

   return -1;
   }

}

#endif

#if defined(BOTAN_HAS_ECDSA) && !defined(OPENSSL_NO_ECDSA)

namespace {

class OpenSSL_ECDSA_Verification_Operation final : public PK_Ops::Verification_with_EMSA
   {
   public:
      OpenSSL_ECDSA_Verification_Operation(const ECDSA_PublicKey& ecdsa, const std::string& emsa, int nid) :
         PK_Ops::Verification_with_EMSA(emsa), m_ossl_ec(::EC_KEY_new(), ::EC_KEY_free)
         {
         std::unique_ptr<::EC_GROUP, std::function<void (::EC_GROUP*)>> grp(::EC_GROUP_new_by_curve_name(nid),
                                                                            ::EC_GROUP_free);

         if(!grp)
            throw OpenSSL_Error("EC_GROUP_new_by_curve_name", ERR_get_error());

         if(!::EC_KEY_set_group(m_ossl_ec.get(), grp.get()))
            throw OpenSSL_Error("EC_KEY_set_group", ERR_get_error());

         const std::vector<uint8_t> enc = ecdsa.public_point().encode(PointGFp::UNCOMPRESSED);
         const uint8_t* enc_ptr = enc.data();
         EC_KEY* key_ptr = m_ossl_ec.get();
         if(!::o2i_ECPublicKey(&key_ptr, &enc_ptr, enc.size()))
            throw OpenSSL_Error("o2i_ECPublicKey", ERR_get_error());

         const EC_GROUP* group = ::EC_KEY_get0_group(m_ossl_ec.get());
         m_order_bits = ::EC_GROUP_get_degree(group);
         }

      size_t max_input_bits() const override { return m_order_bits; }

      bool with_recovery() const override { return false; }

      bool verify(const uint8_t msg[], size_t msg_len,
                  const uint8_t sig_bytes[], size_t sig_len) override
         {
         const size_t order_bytes = (m_order_bits + 7) / 8;
         if(sig_len != 2 * order_bytes)
            return false;

         std::unique_ptr<ECDSA_SIG, std::function<void (ECDSA_SIG*)>> sig(nullptr, ECDSA_SIG_free);
         sig.reset(::ECDSA_SIG_new());

#if OPENSSL_VERSION_NUMBER < 0x10100000L
         sig->r = BN_bin2bn(sig_bytes              , sig_len / 2, sig->r);
         sig->s = BN_bin2bn(sig_bytes + sig_len / 2, sig_len / 2, sig->s);
#else
         BIGNUM* r = BN_bin2bn(sig_bytes              , sig_len / 2, nullptr);
         BIGNUM* s = BN_bin2bn(sig_bytes + sig_len / 2, sig_len / 2, nullptr);
         if(r == nullptr || s == nullptr)
            throw OpenSSL_Error("BN_bin2bn sig s", ERR_get_error());

         ECDSA_SIG_set0(sig.get(), r, s);
#endif

         const int res = ECDSA_do_verify(msg, msg_len, sig.get(), m_ossl_ec.get());
         if(res < 0)
            {
            int err = ERR_get_error();

            bool hard_error = true;

#if defined(EC_R_BAD_SIGNATURE)
            if(ERR_GET_REASON(err) == EC_R_BAD_SIGNATURE)
               hard_error = false;
#endif
#if defined(EC_R_POINT_AT_INFINITY)
            if(ERR_GET_REASON(err) == EC_R_POINT_AT_INFINITY)
               hard_error = false;
#endif
#if defined(ECDSA_R_BAD_SIGNATURE)
            if(ERR_GET_REASON(err) == ECDSA_R_BAD_SIGNATURE)
               hard_error = false;
#endif

            if(hard_error)
               throw OpenSSL_Error("ECDSA_do_verify", err);
            }
         return (res == 1);
         }

   private:
      std::unique_ptr<EC_KEY, std::function<void (EC_KEY*)>> m_ossl_ec;
      size_t m_order_bits = 0;
   };

class OpenSSL_ECDSA_Signing_Operation final : public PK_Ops::Signature_with_EMSA
   {
   public:
      OpenSSL_ECDSA_Signing_Operation(const ECDSA_PrivateKey& ecdsa, const std::string& emsa) :
         PK_Ops::Signature_with_EMSA(emsa),
         m_ossl_ec(nullptr, ::EC_KEY_free)
         {
         const secure_vector<uint8_t> der = PKCS8_for_openssl(ecdsa);
         const uint8_t* der_ptr = der.data();
         m_ossl_ec.reset(d2i_ECPrivateKey(nullptr, &der_ptr, der.size()));
         if(!m_ossl_ec)
            throw OpenSSL_Error("d2i_ECPrivateKey", ERR_get_error());

         const EC_GROUP* group = ::EC_KEY_get0_group(m_ossl_ec.get());
         m_order_bits = ::EC_GROUP_get_degree(group);
         m_order_bytes = (m_order_bits + 7) / 8;
         }

      size_t signature_length() const override { return 2*m_order_bytes; }

      secure_vector<uint8_t> raw_sign(const uint8_t msg[], size_t msg_len,
                                   RandomNumberGenerator&) override
         {
         std::unique_ptr<ECDSA_SIG, std::function<void (ECDSA_SIG*)>> sig(nullptr, ECDSA_SIG_free);
         sig.reset(::ECDSA_do_sign(msg, msg_len, m_ossl_ec.get()));

         if(!sig)
            throw OpenSSL_Error("ECDSA_do_sign", ERR_get_error());

#if OPENSSL_VERSION_NUMBER < 0x10100000L
         const BIGNUM* r = sig->r;
         const BIGNUM* s = sig->s;
#else
         const BIGNUM* r;
         const BIGNUM* s;
         ECDSA_SIG_get0(sig.get(), &r, &s);
#endif

         const size_t r_bytes = BN_num_bytes(r);
         const size_t s_bytes = BN_num_bytes(s);
         secure_vector<uint8_t> sigval(2*m_order_bytes);
         BN_bn2bin(r, &sigval[m_order_bytes - r_bytes]);
         BN_bn2bin(s, &sigval[2*m_order_bytes - s_bytes]);
         return sigval;
         }

      size_t max_input_bits() const override { return m_order_bits; }

   private:
      std::unique_ptr<EC_KEY, std::function<void (EC_KEY*)>> m_ossl_ec;
      size_t m_order_bits;
      size_t m_order_bytes;
   };

}

std::unique_ptr<PK_Ops::Verification>
make_openssl_ecdsa_ver_op(const ECDSA_PublicKey& key, const std::string& params)
   {
   const int nid = OpenSSL_EC_nid_for(key.domain().get_curve_oid());
   if(nid < 0)
      {
      throw Lookup_Error("OpenSSL ECDSA does not support this curve");
      }

   try
      {
      return std::unique_ptr<PK_Ops::Verification>(new OpenSSL_ECDSA_Verification_Operation(key, params, nid));
      }
   catch(OpenSSL_Error&)
      {
      throw Lookup_Error("OpenSSL ECDSA does not support this key");
      }
   }

std::unique_ptr<PK_Ops::Signature>
make_openssl_ecdsa_sig_op(const ECDSA_PrivateKey& key, const std::string& params)
   {
   const int nid = OpenSSL_EC_nid_for(key.domain().get_curve_oid());
   if(nid < 0)
      {
      throw Lookup_Error("OpenSSL ECDSA does not support this curve");
      }
   return std::unique_ptr<PK_Ops::Signature>(new OpenSSL_ECDSA_Signing_Operation(key, params));
   }

#endif

#if defined(BOTAN_HAS_ECDH) && !defined(OPENSSL_NO_ECDH)

namespace {

class OpenSSL_ECDH_KA_Operation final : public PK_Ops::Key_Agreement_with_KDF
   {
   public:

      OpenSSL_ECDH_KA_Operation(const ECDH_PrivateKey& ecdh, const std::string& kdf) :
         PK_Ops::Key_Agreement_with_KDF(kdf), m_ossl_ec(::EC_KEY_new(), ::EC_KEY_free)
         {
         m_value_size = ecdh.domain().get_p_bytes();
         const secure_vector<uint8_t> der = PKCS8_for_openssl(ecdh);
         const uint8_t* der_ptr = der.data();
         m_ossl_ec.reset(d2i_ECPrivateKey(nullptr, &der_ptr, der.size()));
         if(!m_ossl_ec)
            throw OpenSSL_Error("d2i_ECPrivateKey", ERR_get_error());
         }

      size_t agreed_value_size() const override { return m_value_size; }

      secure_vector<uint8_t> raw_agree(const uint8_t w[], size_t w_len) override
         {
         const EC_GROUP* group = ::EC_KEY_get0_group(m_ossl_ec.get());
         const size_t out_len = (::EC_GROUP_get_degree(group) + 7) / 8;
         secure_vector<uint8_t> out(out_len);

         std::unique_ptr<EC_POINT, std::function<void (EC_POINT*)>> pub_key(
            ::EC_POINT_new(group), ::EC_POINT_free);

         if(!pub_key)
            throw OpenSSL_Error("EC_POINT_new", ERR_get_error());

         const int os2ecp_rc =
            ::EC_POINT_oct2point(group, pub_key.get(), w, w_len, nullptr);

         if(os2ecp_rc != 1)
            throw OpenSSL_Error("EC_POINT_oct2point", ERR_get_error());

         const int ecdh_rc = ::ECDH_compute_key(out.data(),
                                                out.size(),
                                                pub_key.get(),
                                                m_ossl_ec.get(),
                                                /*KDF*/nullptr);

         if(ecdh_rc <= 0)
            throw OpenSSL_Error("ECDH_compute_key", ERR_get_error());

         const size_t ecdh_sz = static_cast<size_t>(ecdh_rc);

         if(ecdh_sz > out.size())
            throw Internal_Error("OpenSSL ECDH returned more than requested");

         out.resize(ecdh_sz);
         return out;
         }

   private:
      std::unique_ptr<EC_KEY, std::function<void (EC_KEY*)>> m_ossl_ec;
      size_t m_value_size;
   };

}

std::unique_ptr<PK_Ops::Key_Agreement>
make_openssl_ecdh_ka_op(const ECDH_PrivateKey& key, const std::string& params)
   {
   const int nid = OpenSSL_EC_nid_for(key.domain().get_curve_oid());
   if(nid < 0)
      {
      throw Lookup_Error("OpenSSL ECDH does not support this curve");
      }

   return std::unique_ptr<PK_Ops::Key_Agreement>(new OpenSSL_ECDH_KA_Operation(key, params));
   }

#endif

}

