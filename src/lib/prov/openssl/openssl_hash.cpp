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

class OpenSSL_HashFunction final : public HashFunction
   {
   public:
      void clear() override
         {
         const EVP_MD* algo = EVP_MD_CTX_md(m_md);
         if(!EVP_DigestInit_ex(m_md, algo, nullptr))
            throw OpenSSL_Error("EVP_DigestInit_ex", ERR_get_error());
         }

      std::string provider() const override { return "openssl"; }
      std::string name() const override { return m_name; }

      HashFunction* clone() const override
         {
         const EVP_MD* algo = EVP_MD_CTX_md(m_md);
         return new OpenSSL_HashFunction(name(), algo);
         }

      std::unique_ptr<HashFunction> copy_state() const override
         {
         std::unique_ptr<OpenSSL_HashFunction> copy(new OpenSSL_HashFunction(m_name, nullptr));
         EVP_MD_CTX_copy(copy->m_md, m_md);
         return std::unique_ptr<HashFunction>(copy.release());
         }

      size_t output_length() const override
         {
         return EVP_MD_size(EVP_MD_CTX_md(m_md));
         }

      size_t hash_block_size() const override
         {
         return EVP_MD_block_size(EVP_MD_CTX_md(m_md));
         }

      OpenSSL_HashFunction(const std::string& name, const EVP_MD* md) : m_name(name)
         {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
         m_md = EVP_MD_CTX_create();
#else
         m_md = EVP_MD_CTX_new();
#endif

         if(m_md == nullptr)
            throw OpenSSL_Error("Can't allocate new context", ERR_get_error());
         EVP_MD_CTX_init(m_md);
         if(md && !EVP_DigestInit_ex(m_md, md, nullptr))
            throw OpenSSL_Error("EVP_DigestInit_ex", ERR_get_error());
         }

      OpenSSL_HashFunction(EVP_MD_CTX* ctx) : m_md(ctx)
         {
         }

      ~OpenSSL_HashFunction()
         {
#if OPENSSL_VERSION_NUMBER < 0x10100000L
         EVP_MD_CTX_destroy(m_md);
#else
         EVP_MD_CTX_free(m_md);
#endif
         }

   private:
      void add_data(const uint8_t input[], size_t length) override
         {
         if(!EVP_DigestUpdate(m_md, input, length))
            throw OpenSSL_Error("EVP_DigestUpdate", ERR_get_error());
         }

      void final_result(uint8_t output[]) override
         {
         if(!EVP_DigestFinal_ex(m_md, output, nullptr))
            throw OpenSSL_Error("EVP_DigestFinal_ex", ERR_get_error());
         const EVP_MD* algo = EVP_MD_CTX_md(m_md);
         if(!EVP_DigestInit_ex(m_md, algo, nullptr))
            throw OpenSSL_Error("EVP_DigestInit_ex", ERR_get_error());
         }

      std::string m_name;
      EVP_MD_CTX* m_md;
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
   if(name == "SHA-160" || name == "SHA-1" || name == "SHA1")
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

#if defined(BOTAN_HAS_WHIRLPOOL) && !defined(OPENSSL_NO_WHIRLPOOL)
   if(name == "Whirlpool")
      return MAKE_OPENSSL_HASH(EVP_whirlpool);
#endif

   return nullptr;
   }

}
