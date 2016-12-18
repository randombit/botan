/*
* OpenSSL Hash Functions
* (C) 1999-2007,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hash.h>
#include <botan/internal/openssl.h>
#include <openssl/evp.h>
#include <unordered_map>

namespace Botan {

namespace {

class OpenSSL_HashFunction : public HashFunction
   {
   public:
      void clear() override
         {
         const EVP_MD* algo = EVP_MD_CTX_md(&m_md);
         EVP_DigestInit_ex(&m_md, algo, nullptr);
         }

      std::string provider() const override { return "openssl"; }
      std::string name() const override { return m_name; }

      HashFunction* clone() const override
         {
         const EVP_MD* algo = EVP_MD_CTX_md(&m_md);
         return new OpenSSL_HashFunction(name(), algo);
         }

      size_t output_length() const override
         {
         return EVP_MD_size(EVP_MD_CTX_md(&m_md));
         }

      size_t hash_block_size() const override
         {
         return EVP_MD_block_size(EVP_MD_CTX_md(&m_md));
         }

      OpenSSL_HashFunction(const std::string& name, const EVP_MD* md) : m_name(name)
         {
         EVP_MD_CTX_init(&m_md);
         EVP_DigestInit_ex(&m_md, md, nullptr);
         }

      ~OpenSSL_HashFunction()
         {
         EVP_MD_CTX_cleanup(&m_md);
         }

   private:
      void add_data(const uint8_t input[], size_t length) override
         {
         EVP_DigestUpdate(&m_md, input, length);
         }

      void final_result(uint8_t output[]) override
         {
         EVP_DigestFinal_ex(&m_md, output, nullptr);
         const EVP_MD* algo = EVP_MD_CTX_md(&m_md);
         EVP_DigestInit_ex(&m_md, algo, nullptr);
         }

      std::string m_name;
      EVP_MD_CTX m_md;
   };

}

std::unique_ptr<HashFunction>
make_openssl_hash(const std::string& name)
   {
#define MAKE_OPENSSL_HASH(fn)                                       \
   std::unique_ptr<HashFunction>(new OpenSSL_HashFunction(name, fn ()))

#if defined(BOTAN_HAS_SHA2_32) && !defined(OPENSSL_NO_SHA256)
   if(name == "SHA-224")
      return MAKE_OPENSSL_HASH(EVP_sha224);
   if(name == "SHA-256")
      return MAKE_OPENSSL_HASH(EVP_sha256);
#endif

#if defined(BOTAN_HAS_SHA2_64) && !defined(OPENSSL_NO_SHA512)
   if(name == "SHA-384")
      return MAKE_OPENSSL_HASH(EVP_sha384);
   if(name == "SHA-512")
      return MAKE_OPENSSL_HASH(EVP_sha512);
#endif

#if defined(BOTAN_HAS_SHA1) && !defined(OPENSSL_NO_SHA)
   if(name == "SHA-160")
      return MAKE_OPENSSL_HASH(EVP_sha1);
#endif

#if defined(BOTAN_HAS_RIPEMD_160) && !defined(OPENSSL_NO_RIPEMD)
   if(name == "RIPEMD-160")
      return MAKE_OPENSSL_HASH(EVP_ripemd160);
#endif

#if defined(BOTAN_HAS_MD5) && !defined(OPENSSL_NO_MD5)
   if(name == "MD5")
      return MAKE_OPENSSL_HASH(EVP_md5);
   #endif

#if defined(BOTAN_HAS_MD4) && !defined(OPENSSL_NO_MD4)
   if(name == "MD4")
      return MAKE_OPENSSL_HASH(EVP_md4);
#endif

   return nullptr;
   }

}
