/*
* Block Ciphers via OpenSSL
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/block_cipher.h>
#include <botan/internal/openssl.h>
#include <openssl/evp.h>

namespace Botan {

namespace {

class OpenSSL_BlockCipher : public BlockCipher
   {
   public:
      OpenSSL_BlockCipher(const std::string& name,
                          const EVP_CIPHER* cipher);

      OpenSSL_BlockCipher(const std::string& name,
                          const EVP_CIPHER* cipher,
                          size_t kl_min, size_t kl_max, size_t kl_mod);

      ~OpenSSL_BlockCipher();

      void clear() override;
      std::string provider() const override { return "openssl"; }
      std::string name() const override { return m_cipher_name; }
      BlockCipher* clone() const override;

      size_t block_size() const override { return m_block_sz; }

      Key_Length_Specification key_spec() const override { return m_cipher_key_spec; }

      void encrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override
         {
         int out_len = 0;
         EVP_EncryptUpdate(&m_encrypt, out, &out_len, in, blocks * m_block_sz);
         }

      void decrypt_n(const uint8_t in[], uint8_t out[], size_t blocks) const override
         {
         int out_len = 0;
         EVP_DecryptUpdate(&m_decrypt, out, &out_len, in, blocks * m_block_sz);
         }

      void key_schedule(const uint8_t key[], size_t key_len) override;

      size_t m_block_sz;
      Key_Length_Specification m_cipher_key_spec;
      std::string m_cipher_name;
      mutable EVP_CIPHER_CTX m_encrypt, m_decrypt;
   };

OpenSSL_BlockCipher::OpenSSL_BlockCipher(const std::string& algo_name,
                                         const EVP_CIPHER* algo) :
   m_block_sz(EVP_CIPHER_block_size(algo)),
   m_cipher_key_spec(EVP_CIPHER_key_length(algo)),
   m_cipher_name(algo_name)
   {
   if(EVP_CIPHER_mode(algo) != EVP_CIPH_ECB_MODE)
      throw Invalid_Argument("OpenSSL_BlockCipher: Non-ECB EVP was passed in");

   EVP_CIPHER_CTX_init(&m_encrypt);
   EVP_CIPHER_CTX_init(&m_decrypt);

   EVP_EncryptInit_ex(&m_encrypt, algo, nullptr, nullptr, nullptr);
   EVP_DecryptInit_ex(&m_decrypt, algo, nullptr, nullptr, nullptr);

   EVP_CIPHER_CTX_set_padding(&m_encrypt, 0);
   EVP_CIPHER_CTX_set_padding(&m_decrypt, 0);
   }

OpenSSL_BlockCipher::OpenSSL_BlockCipher(const std::string& algo_name,
                                         const EVP_CIPHER* algo,
                                         size_t key_min,
                                         size_t key_max,
                                         size_t key_mod) :
   m_block_sz(EVP_CIPHER_block_size(algo)),
   m_cipher_key_spec(key_min, key_max, key_mod),
   m_cipher_name(algo_name)
   {
   if(EVP_CIPHER_mode(algo) != EVP_CIPH_ECB_MODE)
      throw Invalid_Argument("OpenSSL_BlockCipher: Non-ECB EVP was passed in");

   EVP_CIPHER_CTX_init(&m_encrypt);
   EVP_CIPHER_CTX_init(&m_decrypt);

   EVP_EncryptInit_ex(&m_encrypt, algo, nullptr, nullptr, nullptr);
   EVP_DecryptInit_ex(&m_decrypt, algo, nullptr, nullptr, nullptr);

   EVP_CIPHER_CTX_set_padding(&m_encrypt, 0);
   EVP_CIPHER_CTX_set_padding(&m_decrypt, 0);
   }

OpenSSL_BlockCipher::~OpenSSL_BlockCipher()
   {
   EVP_CIPHER_CTX_cleanup(&m_encrypt);
   EVP_CIPHER_CTX_cleanup(&m_decrypt);
   }

/*
* Set the key
*/
void OpenSSL_BlockCipher::key_schedule(const uint8_t key[], size_t length)
   {
   secure_vector<uint8_t> full_key(key, key + length);

   if(m_cipher_name == "TripleDES" && length == 16)
      {
      full_key += std::make_pair(key, 8);
      }
   else
      if(EVP_CIPHER_CTX_set_key_length(&m_encrypt, length) == 0 ||
         EVP_CIPHER_CTX_set_key_length(&m_decrypt, length) == 0)
         throw Invalid_Argument("OpenSSL_BlockCipher: Bad key length for " +
                                m_cipher_name);

   EVP_EncryptInit_ex(&m_encrypt, nullptr, nullptr, full_key.data(), nullptr);
   EVP_DecryptInit_ex(&m_decrypt, nullptr, nullptr, full_key.data(), nullptr);
   }

/*
* Return a clone of this object
*/
BlockCipher* OpenSSL_BlockCipher::clone() const
   {
   return new OpenSSL_BlockCipher(m_cipher_name,
                                  EVP_CIPHER_CTX_cipher(&m_encrypt),
                                  m_cipher_key_spec.minimum_keylength(),
                                  m_cipher_key_spec.maximum_keylength(),
                                  m_cipher_key_spec.keylength_multiple());
   }

/*
* Clear memory of sensitive data
*/
void OpenSSL_BlockCipher::clear()
   {
   const EVP_CIPHER* algo = EVP_CIPHER_CTX_cipher(&m_encrypt);

   EVP_CIPHER_CTX_cleanup(&m_encrypt);
   EVP_CIPHER_CTX_cleanup(&m_decrypt);
   EVP_CIPHER_CTX_init(&m_encrypt);
   EVP_CIPHER_CTX_init(&m_decrypt);
   EVP_EncryptInit_ex(&m_encrypt, algo, nullptr, nullptr, nullptr);
   EVP_DecryptInit_ex(&m_decrypt, algo, nullptr, nullptr, nullptr);
   EVP_CIPHER_CTX_set_padding(&m_encrypt, 0);
   EVP_CIPHER_CTX_set_padding(&m_decrypt, 0);
   }

}

std::unique_ptr<BlockCipher>
make_openssl_block_cipher(const std::string& name)
   {
#define MAKE_OPENSSL_BLOCK(evp_fn) \
   std::unique_ptr<BlockCipher>(new OpenSSL_BlockCipher(name, evp_fn()))
#define MAKE_OPENSSL_BLOCK_KEYLEN(evp_fn, kl_min, kl_max, kl_mod)       \
   std::unique_ptr<BlockCipher>(new OpenSSL_BlockCipher(name, evp_fn(), kl_min, kl_max, kl_mod))

#if defined(BOTAN_HAS_AES) && !defined(OPENSSL_NO_AES)
   if(name == "AES-128")
      return MAKE_OPENSSL_BLOCK(EVP_aes_128_ecb);
   if(name == "AES-192")
      return MAKE_OPENSSL_BLOCK(EVP_aes_192_ecb);
   if(name == "AES-256")
      return MAKE_OPENSSL_BLOCK(EVP_aes_256_ecb);
#endif

#if defined(BOTAN_HAS_CAMELLIA) && !defined(OPENSSL_NO_CAMELLIA)
   if(name == "Camellia-128")
      return MAKE_OPENSSL_BLOCK(EVP_camellia_128_ecb);
   if(name == "Camellia-192")
      return MAKE_OPENSSL_BLOCK(EVP_camellia_192_ecb);
   if(name == "Camellia-256")
      return MAKE_OPENSSL_BLOCK(EVP_camellia_256_ecb);
#endif

#if defined(BOTAN_HAS_DES) && !defined(OPENSSL_NO_DES)
   if(name == "DES")
      return MAKE_OPENSSL_BLOCK(EVP_des_ecb);
   if(name == "TripleDES")
      return MAKE_OPENSSL_BLOCK_KEYLEN(EVP_des_ede3_ecb, 16, 24, 8);
#endif

#if defined(BOTAN_HAS_BLOWFISH) && !defined(OPENSSL_NO_BF)
   if(name == "Blowfish")
      return MAKE_OPENSSL_BLOCK_KEYLEN(EVP_bf_ecb, 1, 56, 1);
#endif

#if defined(BOTAN_HAS_CAST) && !defined(OPENSSL_NO_CAST)
   if(name == "CAST-128")
      return MAKE_OPENSSL_BLOCK_KEYLEN(EVP_cast5_ecb, 1, 16, 1);
#endif

#if defined(BOTAN_HAS_IDEA) && !defined(OPENSSL_NO_IDEA)
   if(name == "IDEA")
      return MAKE_OPENSSL_BLOCK(EVP_idea_ecb);
#endif

#if defined(BOTAN_HAS_SEED) && !defined(OPENSSL_NO_SEED)
   if(name == "SEED")
      return MAKE_OPENSSL_BLOCK(EVP_seed_ecb);
#endif

   return nullptr;
   }

}

