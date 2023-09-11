/*
* CommonCrypto Hash Functions
* (C) 2018 Jose Pereira
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/commoncrypto.h>

#include <botan/hash.h>
#include <botan/internal/stl_util.h>
#include <unordered_map>

#include <CommonCrypto/CommonCrypto.h>

namespace Botan {

namespace {

template <class CTX>
class CommonCrypto_HashFunction final : public HashFunction {
   public:
      struct digest_config_t {
            std::string name;
            size_t digestLength;
            size_t blockSize;
            int (*init)(CTX*);
            int (*update)(CTX*, const void*, CC_LONG len);
            int (*final)(unsigned char*, CTX*);
      };

      void clear() override {
         if(m_info.init(&m_ctx) != 1)
            throw CommonCrypto_Error("CC_" + m_info.name + "_Init");
      }

      std::string provider() const override { return "commoncrypto"; }

      std::string name() const override { return m_info.name; }

      std::unique_ptr<HashFunction> new_object() const override {
         return std::make_unique<CommonCrypto_HashFunction>(m_info);
      }

      std::unique_ptr<HashFunction> copy_state() const override {
         return std::unique_ptr<CommonCrypto_HashFunction>(new CommonCrypto_HashFunction(m_info, m_ctx));
      }

      size_t output_length() const override { return m_info.digestLength; }

      size_t hash_block_size() const override { return m_info.blockSize; }

      CommonCrypto_HashFunction(const digest_config_t& info) : m_info(info) { clear(); }

      CommonCrypto_HashFunction(const digest_config_t& info, const CTX& ctx) : m_ctx(ctx), m_info(info) {}

   private:
      void add_data(std::span<const uint8_t> input) override {
         BufferSlicer in(input);

         /* update len parameter is 32 bit unsigned integer, feed input in parts */
         while(!in.empty()) {
            CC_LONG update_len = (in.remaining() > 0xFFFFFFFFUL) ? 0xFFFFFFFFUL : static_cast<CC_LONG>(in.remaining());
            const auto chunk = in.take(update_len);
            m_info.update(&m_ctx, chunk.data(), static_cast<CC_LONG>(chunk.size()));
         }
      }

      void final_result(std::span<uint8_t> output) override {
         if(m_info.final(output.data(), &m_ctx) != 1)
            throw CommonCrypto_Error("CC_" + m_info.name + "_Final");
         clear();
      }

      CTX m_ctx;
      digest_config_t m_info;
};
}  // namespace

std::unique_ptr<HashFunction> make_commoncrypto_hash(std::string_view name) {
#define MAKE_COMMONCRYPTO_HASH_3(name, hash, ctx)                                                          \
   std::unique_ptr<HashFunction>(new CommonCrypto_HashFunction<CC_##ctx##_CTX>({std::string(name),         \
                                                                                CC_##hash##_DIGEST_LENGTH, \
                                                                                CC_##hash##_BLOCK_BYTES,   \
                                                                                CC_##hash##_Init,          \
                                                                                CC_##hash##_Update,        \
                                                                                CC_##hash##_Final}));

#define MAKE_COMMONCRYPTO_HASH_2(name, id) MAKE_COMMONCRYPTO_HASH_3(name, id, id)

#define MAKE_COMMONCRYPTO_HASH_1(id) MAKE_COMMONCRYPTO_HASH_2(#id, id)

#if defined(BOTAN_HAS_SHA2_32)
   if(name == "SHA-224")
      return MAKE_COMMONCRYPTO_HASH_3(name, SHA224, SHA256);
   if(name == "SHA-256")
      return MAKE_COMMONCRYPTO_HASH_2(name, SHA256);
#endif
#if defined(BOTAN_HAS_SHA2_64)
   if(name == "SHA-384")
      return MAKE_COMMONCRYPTO_HASH_3(name, SHA384, SHA512);
   if(name == "SHA-512")
      return MAKE_COMMONCRYPTO_HASH_2(name, SHA512);
#endif

#if defined(BOTAN_HAS_SHA1)
   if(name == "SHA-1")
      return MAKE_COMMONCRYPTO_HASH_2(name, SHA1);
#endif

   return nullptr;
}

}  // namespace Botan
