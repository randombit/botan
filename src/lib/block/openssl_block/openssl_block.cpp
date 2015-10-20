/*
* Block Ciphers via OpenSSL
* (C) 1999-2010,2015 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/block_cipher.h>
#include <botan/internal/algo_registry.h>
#include <botan/internal/openssl.h>
#include <openssl/evp.h>

namespace Botan {

namespace {

class OpenSSL_BlockCipher : public BlockCipher
   {
   public:
      void clear();
      std::string name() const { return cipher_name; }
      BlockCipher* clone() const;

      size_t block_size() const { return block_sz; }

      OpenSSL_BlockCipher(const EVP_CIPHER*, const std::string&);

      OpenSSL_BlockCipher(const EVP_CIPHER*, const std::string&,
                      size_t, size_t, size_t);

      Key_Length_Specification key_spec() const { return cipher_key_spec; }

      ~OpenSSL_BlockCipher();
   private:
      void encrypt_n(const byte in[], byte out[], size_t blocks) const
         {
         int out_len = 0;
         EVP_EncryptUpdate(&encrypt, out, &out_len, in, blocks * block_sz);
         }

      void decrypt_n(const byte in[], byte out[], size_t blocks) const
         {
         int out_len = 0;
         EVP_DecryptUpdate(&decrypt, out, &out_len, in, blocks * block_sz);
         }

      void key_schedule(const byte[], size_t);

      size_t block_sz;
      Key_Length_Specification cipher_key_spec;
      std::string cipher_name;
      mutable EVP_CIPHER_CTX encrypt, decrypt;
   };

OpenSSL_BlockCipher::OpenSSL_BlockCipher(const EVP_CIPHER* algo,
                                         const std::string& algo_name) :
   block_sz(EVP_CIPHER_block_size(algo)),
   cipher_key_spec(EVP_CIPHER_key_length(algo)),
   cipher_name(algo_name)
   {
   if(EVP_CIPHER_mode(algo) != EVP_CIPH_ECB_MODE)
      throw Invalid_Argument("OpenSSL_BlockCipher: Non-ECB EVP was passed in");

   EVP_CIPHER_CTX_init(&encrypt);
   EVP_CIPHER_CTX_init(&decrypt);

   EVP_EncryptInit_ex(&encrypt, algo, nullptr, nullptr, nullptr);
   EVP_DecryptInit_ex(&decrypt, algo, nullptr, nullptr, nullptr);

   EVP_CIPHER_CTX_set_padding(&encrypt, 0);
   EVP_CIPHER_CTX_set_padding(&decrypt, 0);
   }

OpenSSL_BlockCipher::OpenSSL_BlockCipher(const EVP_CIPHER* algo,
                                 const std::string& algo_name,
                                 size_t key_min, size_t key_max,
                                 size_t key_mod) :
   block_sz(EVP_CIPHER_block_size(algo)),
   cipher_key_spec(key_min, key_max, key_mod),
   cipher_name(algo_name)
   {
   if(EVP_CIPHER_mode(algo) != EVP_CIPH_ECB_MODE)
      throw Invalid_Argument("OpenSSL_BlockCipher: Non-ECB EVP was passed in");

   EVP_CIPHER_CTX_init(&encrypt);
   EVP_CIPHER_CTX_init(&decrypt);

   EVP_EncryptInit_ex(&encrypt, algo, nullptr, nullptr, nullptr);
   EVP_DecryptInit_ex(&decrypt, algo, nullptr, nullptr, nullptr);

   EVP_CIPHER_CTX_set_padding(&encrypt, 0);
   EVP_CIPHER_CTX_set_padding(&decrypt, 0);
   }

OpenSSL_BlockCipher::~OpenSSL_BlockCipher()
   {
   EVP_CIPHER_CTX_cleanup(&encrypt);
   EVP_CIPHER_CTX_cleanup(&decrypt);
   }

/*
* Set the key
*/
void OpenSSL_BlockCipher::key_schedule(const byte key[], size_t length)
   {
   secure_vector<byte> full_key(key, key + length);

   if(cipher_name == "TripleDES" && length == 16)
      {
      full_key += std::make_pair(key, 8);
      }
   else
      if(EVP_CIPHER_CTX_set_key_length(&encrypt, length) == 0 ||
         EVP_CIPHER_CTX_set_key_length(&decrypt, length) == 0)
         throw Invalid_Argument("OpenSSL_BlockCipher: Bad key length for " +
                                cipher_name);

   EVP_EncryptInit_ex(&encrypt, nullptr, nullptr, full_key.data(), nullptr);
   EVP_DecryptInit_ex(&decrypt, nullptr, nullptr, full_key.data(), nullptr);
   }

/*
* Return a clone of this object
*/
BlockCipher* OpenSSL_BlockCipher::clone() const
   {
   return new OpenSSL_BlockCipher(EVP_CIPHER_CTX_cipher(&encrypt),
                              cipher_name,
                              cipher_key_spec.minimum_keylength(),
                              cipher_key_spec.maximum_keylength(),
                              cipher_key_spec.keylength_multiple());
   }

/*
* Clear memory of sensitive data
*/
void OpenSSL_BlockCipher::clear()
   {
   const EVP_CIPHER* algo = EVP_CIPHER_CTX_cipher(&encrypt);

   EVP_CIPHER_CTX_cleanup(&encrypt);
   EVP_CIPHER_CTX_cleanup(&decrypt);
   EVP_CIPHER_CTX_init(&encrypt);
   EVP_CIPHER_CTX_init(&decrypt);
   EVP_EncryptInit_ex(&encrypt, algo, nullptr, nullptr, nullptr);
   EVP_DecryptInit_ex(&decrypt, algo, nullptr, nullptr, nullptr);
   EVP_CIPHER_CTX_set_padding(&encrypt, 0);
   EVP_CIPHER_CTX_set_padding(&decrypt, 0);
   }

std::function<BlockCipher* (const BlockCipher::Spec&)>
make_evp_block_maker(const EVP_CIPHER* cipher, const char* algo)
   {
   return [cipher,algo](const BlockCipher::Spec&)
      {
      return new OpenSSL_BlockCipher(cipher, algo);
      };
   }

std::function<BlockCipher* (const BlockCipher::Spec&)>
make_evp_block_maker_keylen(const EVP_CIPHER* cipher, const char* algo,
                            size_t kmin, size_t kmax, size_t kmod)
   {
   return [cipher,algo,kmin,kmax,kmod](const BlockCipher::Spec&)
      {
      return new OpenSSL_BlockCipher(cipher, algo, kmin, kmax, kmod);
      };
   }

#define BOTAN_REGISTER_OPENSSL_EVP_BLOCK(NAME, EVP)                            \
   BOTAN_REGISTER_TYPE(BlockCipher, EVP_BlockCipher ## EVP, NAME,              \
                       make_evp_block_maker(EVP(), NAME), "openssl", BOTAN_OPENSSL_BLOCK_PRIO);

#define BOTAN_REGISTER_OPENSSL_EVP_BLOCK_KEYLEN(NAME, EVP, KMIN, KMAX, KMOD)       \
   BOTAN_REGISTER_TYPE(BlockCipher, OpenSSL_BlockCipher ## EVP, NAME,              \
                       make_evp_block_maker_keylen(EVP(), NAME, KMIN, KMAX, KMOD), \
                       "openssl", BOTAN_OPENSSL_BLOCK_PRIO);

#if !defined(OPENSSL_NO_AES)
   BOTAN_REGISTER_OPENSSL_EVP_BLOCK("AES-128", EVP_aes_128_ecb);
   BOTAN_REGISTER_OPENSSL_EVP_BLOCK("AES-192", EVP_aes_192_ecb);
   BOTAN_REGISTER_OPENSSL_EVP_BLOCK("AES-256", EVP_aes_256_ecb);
#endif

#if !defined(OPENSSL_NO_DES)
   BOTAN_REGISTER_OPENSSL_EVP_BLOCK("DES", EVP_des_ecb);
   BOTAN_REGISTER_OPENSSL_EVP_BLOCK_KEYLEN("TripleDES", EVP_des_ede3_ecb, 16, 24, 8);
#endif

#if !defined(OPENSSL_NO_BF)
   BOTAN_REGISTER_OPENSSL_EVP_BLOCK_KEYLEN("Blowfish", EVP_bf_ecb, 1, 56, 1);
#endif

#if !defined(OPENSSL_NO_CAST)
   BOTAN_REGISTER_OPENSSL_EVP_BLOCK_KEYLEN("CAST-128", EVP_cast5_ecb, 1, 16, 1);
#endif

#if !defined(OPENSSL_NO_CAMELLIA)
   BOTAN_REGISTER_OPENSSL_EVP_BLOCK("Camellia-128", EVP_camellia_128_ecb);
   BOTAN_REGISTER_OPENSSL_EVP_BLOCK("Camellia-192", EVP_camellia_192_ecb);
   BOTAN_REGISTER_OPENSSL_EVP_BLOCK("Camellia-256", EVP_camellia_256_ecb);
#endif

#if !defined(OPENSSL_NO_IDEA)
   BOTAN_REGISTER_OPENSSL_EVP_BLOCK("IDEA", EVP_idea_ecb);
#endif

#if !defined(OPENSSL_NO_SEED)
   BOTAN_REGISTER_OPENSSL_EVP_BLOCK("SEED", EVP_seed_ecb);
#endif

}

}
