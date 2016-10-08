/*
* RSA operations provided by OpenSSL
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/openssl.h>

#if defined(BOTAN_HAS_RSA)

#include <botan/rsa.h>
#include <botan/internal/pk_ops_impl.h>
#include <botan/internal/ct_utils.h>

#include <functional>
#include <memory>

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/err.h>

namespace Botan {

namespace {

std::pair<int, size_t> get_openssl_enc_pad(const std::string& eme)
   {
   ERR_load_crypto_strings();
   if(eme == "Raw")
      return std::make_pair(RSA_NO_PADDING, 0);
   else if(eme == "EME-PKCS1-v1_5")
      return std::make_pair(RSA_PKCS1_PADDING, 11);
   else if(eme == "OAEP(SHA-1)" || eme == "EME1(SHA-1)")
      return std::make_pair(RSA_PKCS1_OAEP_PADDING, 41);
   else
      throw Lookup_Error("OpenSSL RSA does not support EME " + eme);
   }

class OpenSSL_RSA_Encryption_Operation : public PK_Ops::Encryption
   {
   public:
      typedef RSA_PublicKey Key_Type;

      OpenSSL_RSA_Encryption_Operation(const RSA_PublicKey& rsa, int pad, size_t pad_overhead) :
         m_openssl_rsa(nullptr, ::RSA_free), m_padding(pad)
         {
         const std::vector<byte> der = rsa.x509_subject_public_key();
         const byte* der_ptr = der.data();
         m_openssl_rsa.reset(::d2i_RSAPublicKey(nullptr, &der_ptr, der.size()));
         if(!m_openssl_rsa)
            throw OpenSSL_Error("d2i_RSAPublicKey");

         m_bits = 8 * (n_size() - pad_overhead) - 1;
         }

      size_t max_input_bits() const override { return m_bits; };

      secure_vector<byte> encrypt(const byte msg[], size_t msg_len,
                                  RandomNumberGenerator&) override
         {
         const size_t mod_sz = n_size();

         if(msg_len > mod_sz)
            throw Invalid_Argument("Input too large for RSA key");

         secure_vector<byte> outbuf(mod_sz);

         secure_vector<byte> inbuf;

         if(m_padding == RSA_NO_PADDING)
            {
            inbuf.resize(mod_sz);
            copy_mem(&inbuf[mod_sz - msg_len], msg, msg_len);
            }
         else
            {
            inbuf.assign(msg, msg + msg_len);
            }

         int rc = ::RSA_public_encrypt(inbuf.size(), inbuf.data(), outbuf.data(),
                                       m_openssl_rsa.get(), m_padding);
         if(rc < 0)
            throw OpenSSL_Error("RSA_public_encrypt");

         return outbuf;
         }

   private:
      size_t n_size() const { return ::RSA_size(m_openssl_rsa.get()); }
      std::unique_ptr<RSA, std::function<void (RSA*)>> m_openssl_rsa;
      size_t m_bits = 0;
      int m_padding = 0;
   };

class OpenSSL_RSA_Decryption_Operation : public PK_Ops::Decryption
   {
   public:
      typedef RSA_PrivateKey Key_Type;

      OpenSSL_RSA_Decryption_Operation(const RSA_PrivateKey& rsa, int pad) :
         m_openssl_rsa(nullptr, ::RSA_free), m_padding(pad)
         {
         const secure_vector<byte> der = rsa.pkcs8_private_key();
         const byte* der_ptr = der.data();
         m_openssl_rsa.reset(d2i_RSAPrivateKey(nullptr, &der_ptr, der.size()));
         if(!m_openssl_rsa)
            throw OpenSSL_Error("d2i_RSAPrivateKey");
         }

      size_t max_input_bits() const override { return ::BN_num_bits(m_openssl_rsa->n) - 1; }

      secure_vector<byte> decrypt(byte& valid_mask,
                                  const byte msg[], size_t msg_len) override
         {
         secure_vector<byte> buf(::RSA_size(m_openssl_rsa.get()));
         int rc = ::RSA_private_decrypt(msg_len, msg, buf.data(), m_openssl_rsa.get(), m_padding);
         if(rc < 0 || static_cast<size_t>(rc) > buf.size())
            {
            valid_mask = 0;
            buf.resize(0);
            }
         else
            {
            valid_mask = 0xFF;
            buf.resize(rc);
            }

         if(m_padding == RSA_NO_PADDING)
            {
            return CT::strip_leading_zeros(buf);
            }

         return buf;
         }

   private:
      std::unique_ptr<RSA, std::function<void (RSA*)>> m_openssl_rsa;
      int m_padding = 0;
   };

class OpenSSL_RSA_Verification_Operation : public PK_Ops::Verification_with_EMSA
   {
   public:
      typedef RSA_PublicKey Key_Type;

      OpenSSL_RSA_Verification_Operation(const RSA_PublicKey& rsa, const std::string& emsa) :
         PK_Ops::Verification_with_EMSA(emsa),
         m_openssl_rsa(nullptr, ::RSA_free)
         {
         const std::vector<byte> der = rsa.x509_subject_public_key();
         const byte* der_ptr = der.data();
         m_openssl_rsa.reset(::d2i_RSAPublicKey(nullptr, &der_ptr, der.size()));
         }

      size_t max_input_bits() const override { return ::BN_num_bits(m_openssl_rsa->n) - 1; }

      bool with_recovery() const override { return true; }

      secure_vector<byte> verify_mr(const byte msg[], size_t msg_len) override
         {
         const size_t mod_sz = ::RSA_size(m_openssl_rsa.get());

         if(msg_len > mod_sz)
            throw Invalid_Argument("OpenSSL RSA verify input too large");

         secure_vector<byte> inbuf(mod_sz);
         copy_mem(&inbuf[mod_sz - msg_len], msg, msg_len);

         secure_vector<byte> outbuf(mod_sz);

         int rc = ::RSA_public_decrypt(inbuf.size(), inbuf.data(), outbuf.data(),
                                       m_openssl_rsa.get(), RSA_NO_PADDING);
         if(rc < 0)
            throw Invalid_Argument("RSA_public_decrypt");

         return CT::strip_leading_zeros(outbuf);
         }
   private:
      std::unique_ptr<RSA, std::function<void (RSA*)>> m_openssl_rsa;
   };

class OpenSSL_RSA_Signing_Operation : public PK_Ops::Signature_with_EMSA
   {
   public:
      typedef RSA_PrivateKey Key_Type;

      OpenSSL_RSA_Signing_Operation(const RSA_PrivateKey& rsa, const std::string& emsa) :
         PK_Ops::Signature_with_EMSA(emsa),
         m_openssl_rsa(nullptr, ::RSA_free)
         {
         const secure_vector<byte> der = rsa.pkcs8_private_key();
         const byte* der_ptr = der.data();
         m_openssl_rsa.reset(d2i_RSAPrivateKey(nullptr, &der_ptr, der.size()));
         if(!m_openssl_rsa)
            throw OpenSSL_Error("d2i_RSAPrivateKey");
         }

      secure_vector<byte> raw_sign(const byte msg[], size_t msg_len,
                                   RandomNumberGenerator&) override
         {
         const size_t mod_sz = ::RSA_size(m_openssl_rsa.get());

         if(msg_len > mod_sz)
            throw Invalid_Argument("OpenSSL RSA sign input too large");

         secure_vector<byte> inbuf(mod_sz);
         copy_mem(&inbuf[mod_sz - msg_len], msg, msg_len);

         secure_vector<byte> outbuf(mod_sz);

         int rc = ::RSA_private_encrypt(inbuf.size(), inbuf.data(), outbuf.data(),
                                        m_openssl_rsa.get(), RSA_NO_PADDING);
         if(rc < 0)
            throw OpenSSL_Error("RSA_private_encrypt");

         return outbuf;
         }

      size_t max_input_bits() const override { return ::BN_num_bits(m_openssl_rsa->n) - 1; }

   private:
      std::unique_ptr<RSA, std::function<void (RSA*)>> m_openssl_rsa;
   };

}

std::unique_ptr<PK_Ops::Encryption>
make_openssl_rsa_enc_op(const RSA_PublicKey& key, const std::string& params)
   {
   auto pad_info = get_openssl_enc_pad(params);
   return std::unique_ptr<PK_Ops::Encryption>(
      new OpenSSL_RSA_Encryption_Operation(key, pad_info.first, pad_info.second));
   }

std::unique_ptr<PK_Ops::Decryption>
make_openssl_rsa_dec_op(const RSA_PrivateKey& key, const std::string& params)
   {
   auto pad_info = get_openssl_enc_pad(params);
   return std::unique_ptr<PK_Ops::Decryption>(new OpenSSL_RSA_Decryption_Operation(key, pad_info.first));
   }

std::unique_ptr<PK_Ops::Verification>
make_openssl_rsa_ver_op(const RSA_PublicKey& key, const std::string& params)
   {
   return std::unique_ptr<PK_Ops::Verification>(new OpenSSL_RSA_Verification_Operation(key, params));
   }

std::unique_ptr<PK_Ops::Signature>
make_openssl_rsa_sig_op(const RSA_PrivateKey& key, const std::string& params)
   {
   return std::unique_ptr<PK_Ops::Signature>(new OpenSSL_RSA_Signing_Operation(key, params));
   }

}

#endif // BOTAN_HAS_RSA
