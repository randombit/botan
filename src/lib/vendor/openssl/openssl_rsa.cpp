/*
* OpenSSL RSA interface
* (C) 2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/openssl.h>

#if defined(BOTAN_HAS_RSA)

#include <botan/rsa.h>
#include <botan/internal/pk_utils.h>
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
   else if(eme == "OAEP(SHA-1)")
      return std::make_pair(RSA_PKCS1_OAEP_PADDING, 41);
   else
      throw Lookup_Error("OpenSSL RSA does not support EME " + eme);
   }

class OpenSSL_RSA_Encryption_Operation : public PK_Ops::Encryption
   {
   public:
      typedef RSA_PublicKey Key_Type;

      static OpenSSL_RSA_Encryption_Operation* make(const Spec& spec)
         {
         try
            {
            if(auto* key = dynamic_cast<const RSA_PublicKey*>(&spec.key()))
               {
               auto pad_info = get_openssl_enc_pad(spec.padding());
               return new OpenSSL_RSA_Encryption_Operation(*key, pad_info.first, pad_info.second);
               }
            }
         catch(...) {}

         return nullptr;
         }

      OpenSSL_RSA_Encryption_Operation(const RSA_PublicKey& rsa, int pad, size_t pad_overhead) :
         m_openssl_rsa(nullptr, ::RSA_free), m_padding(pad)
         {
         const std::vector<byte> der = rsa.x509_subject_public_key();
         const byte* der_ptr = der.data();
         m_openssl_rsa.reset(::d2i_RSAPublicKey(nullptr, &der_ptr, der.size()));
         if(!m_openssl_rsa)
            throw OpenSSL_Error("d2i_RSAPublicKey");

         m_bits = 8 * (n_size() - pad_overhead);
         }

      size_t max_input_bits() const override { return m_bits - 1; };

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

      static OpenSSL_RSA_Decryption_Operation* make(const Spec& spec)
         {
         try
            {
            if(auto* key = dynamic_cast<const RSA_PrivateKey*>(&spec.key()))
               {
               auto pad_info = get_openssl_enc_pad(spec.padding());
               return new OpenSSL_RSA_Decryption_Operation(*key, pad_info.first);
               }
            }
         catch(...) {}

         return nullptr;
         }

      OpenSSL_RSA_Decryption_Operation(const RSA_PrivateKey& rsa, int pad) :
         m_openssl_rsa(nullptr, ::RSA_free), m_padding(pad)
         {
         const secure_vector<byte> der = rsa.pkcs8_private_key();
         const byte* der_ptr = der.data();
         m_openssl_rsa.reset(d2i_RSAPrivateKey(nullptr, &der_ptr, der.size()));
         if(!m_openssl_rsa)
            throw OpenSSL_Error("d2i_RSAPrivateKey");

         m_bits = 8 * ::RSA_size(m_openssl_rsa.get());
         }

      size_t max_input_bits() const override { return m_bits - 1; }

      secure_vector<byte> decrypt(const byte msg[], size_t msg_len) override
         {
         secure_vector<byte> buf(::RSA_size(m_openssl_rsa.get()));
         int rc = ::RSA_private_decrypt(msg_len, msg, buf.data(), m_openssl_rsa.get(), m_padding);
         if(rc < 0 || static_cast<size_t>(rc) > buf.size())
            throw OpenSSL_Error("RSA_private_decrypt");
         buf.resize(rc);

         if(m_padding == RSA_NO_PADDING)
            {
            size_t leading_0s = 0;
            while(leading_0s < buf.size() && buf[leading_0s] == 0)
               leading_0s++;

            if(leading_0s)
               return secure_vector<byte>(&buf[leading_0s], &buf[buf.size()]);
            }

         return buf;
         }

   private:
      std::unique_ptr<RSA, std::function<void (RSA*)>> m_openssl_rsa;
      size_t m_bits = 0;
      int m_padding = 0;
   };

BOTAN_REGISTER_TYPE(PK_Ops::Encryption, OpenSSL_RSA_Encryption_Operation, "RSA",
                    OpenSSL_RSA_Encryption_Operation::make, "openssl", BOTAN_OPENSSL_RSA_PRIO);
BOTAN_REGISTER_TYPE(PK_Ops::Decryption, OpenSSL_RSA_Decryption_Operation, "RSA",
                    OpenSSL_RSA_Decryption_Operation::make, "openssl", BOTAN_OPENSSL_RSA_PRIO);

}

}

#endif // BOTAN_HAS_RSA
