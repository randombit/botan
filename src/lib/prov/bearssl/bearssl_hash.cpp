/*
* BearSSL Hash Functions
* (C) 1999-2007,2015 Jack Lloyd
* (C) 2017 Patrick Wildt
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/hash.h>
#include <botan/internal/bearssl.h>
#include <unordered_map>

extern "C" {
  #include <bearssl_hash.h>
}

namespace Botan {

namespace {

class BearSSL_HashFunction final : public HashFunction
   {
   public:
      void clear() override
         {
         m_ctx.vtable->init(&m_ctx.vtable);
         }

      std::string provider() const override { return "bearssl"; }
      std::string name() const override { return m_name; }

      HashFunction* clone() const override
         {
         return new BearSSL_HashFunction(m_ctx.vtable, m_name);
         }

      std::unique_ptr<HashFunction> copy_state() const override
         {
         std::unique_ptr<BearSSL_HashFunction> copy(new BearSSL_HashFunction(m_ctx.vtable, m_name));
         memcpy(&copy->m_ctx, &m_ctx, sizeof(m_ctx));
         return std::move(copy);
         }

      size_t output_length() const override
         {
         return (m_ctx.vtable->desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK;
         }

      size_t hash_block_size() const override
         {
         return 1 << ((m_ctx.vtable->desc >> BR_HASHDESC_LBLEN_OFF) & BR_HASHDESC_LBLEN_MASK);
         }

      BearSSL_HashFunction(const br_hash_class *hash, const std::string name)
         {
         m_name = name;
         hash->init(&m_ctx.vtable);
         }

      ~BearSSL_HashFunction()
         {
         }

   private:
      void add_data(const uint8_t input[], size_t length) override
         {
         m_ctx.vtable->update(&m_ctx.vtable, input, length);
         }

      void final_result(uint8_t output[]) override
         {
         m_ctx.vtable->out(&m_ctx.vtable, output);
         m_ctx.vtable->init(&m_ctx.vtable);
         }

      std::string m_name;
      br_hash_compat_context m_ctx;
   };

}

std::unique_ptr<HashFunction>
make_bearssl_hash(const std::string& name)
   {
#define MAKE_BEARSSL_HASH(vtable) \
   std::unique_ptr<HashFunction>(new BearSSL_HashFunction(vtable, name))

#if defined(BOTAN_HAS_SHA2_32)
   if(name == "SHA-224")
      return MAKE_BEARSSL_HASH(&br_sha224_vtable);
   if(name == "SHA-256")
      return MAKE_BEARSSL_HASH(&br_sha256_vtable);
#endif

#if defined(BOTAN_HAS_SHA2_64)
   if(name == "SHA-384")
      return MAKE_BEARSSL_HASH(&br_sha384_vtable);
   if(name == "SHA-512")
      return MAKE_BEARSSL_HASH(&br_sha512_vtable);
#endif

#if defined(BOTAN_HAS_SHA1)
   if(name == "SHA-160" || name == "SHA-1")
      return MAKE_BEARSSL_HASH(&br_sha1_vtable);
#endif

#if defined(BOTAN_HAS_MD5)
   if(name == "MD5")
      return MAKE_BEARSSL_HASH(&br_md5_vtable);
#endif

#if defined(BOTAN_HAS_PARALLEL_HASH)
   if(name == "Parallel(MD5,SHA-160)")
      return MAKE_BEARSSL_HASH(&br_md5sha1_vtable);
#endif

   return nullptr;
   }

}
