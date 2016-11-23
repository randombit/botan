/*
* Cryptobox Message Routines
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/cryptobox.h>
#include <botan/filters.h>
#include <botan/pipe.h>
#include <botan/sha2_64.h>
#include <botan/hmac.h>
#include <botan/pbkdf2.h>
#include <botan/pem.h>
#include <botan/loadstor.h>
#include <botan/mem_ops.h>

namespace Botan {

namespace CryptoBox {

namespace {

/*
First 24 bits of SHA-256("Botan Cryptobox"), followed by 8 0 bits
for later use as flags, etc if needed
*/
const u32bit CRYPTOBOX_VERSION_CODE = 0xEFC22400;

const size_t VERSION_CODE_LEN = 4;
const size_t CIPHER_KEY_LEN = 32;
const size_t CIPHER_IV_LEN = 16;
const size_t MAC_KEY_LEN = 32;
const size_t MAC_OUTPUT_LEN = 20;
const size_t PBKDF_SALT_LEN = 10;
const size_t PBKDF_ITERATIONS = 8 * 1024;

const size_t PBKDF_OUTPUT_LEN = CIPHER_KEY_LEN + CIPHER_IV_LEN + MAC_KEY_LEN;

}

std::string encrypt(const byte input[], size_t input_len,
                    const std::string& passphrase,
                    RandomNumberGenerator& rng)
   {
   secure_vector<byte> pbkdf_salt(PBKDF_SALT_LEN);
   rng.randomize(pbkdf_salt.data(), pbkdf_salt.size());

   PKCS5_PBKDF2 pbkdf(new HMAC(new SHA_512));

   OctetString master_key = pbkdf.derive_key(
      PBKDF_OUTPUT_LEN,
      passphrase,
      pbkdf_salt.data(),
      pbkdf_salt.size(),
      PBKDF_ITERATIONS);

   const byte* mk = master_key.begin();

   SymmetricKey cipher_key(mk, CIPHER_KEY_LEN);
   SymmetricKey mac_key(&mk[CIPHER_KEY_LEN], MAC_KEY_LEN);
   InitializationVector iv(&mk[CIPHER_KEY_LEN + MAC_KEY_LEN], CIPHER_IV_LEN);

   Pipe pipe(get_cipher("Serpent/CTR-BE", cipher_key, iv, ENCRYPTION),
             new Fork(
                nullptr,
                new MAC_Filter(new HMAC(new SHA_512),
                               mac_key, MAC_OUTPUT_LEN)));

   pipe.process_msg(input, input_len);

   /*
   Output format is:
      version # (4 bytes)
      salt (10 bytes)
      mac (20 bytes)
      ciphertext
   */
   const size_t ciphertext_len = pipe.remaining(0);

   std::vector<byte> out_buf(VERSION_CODE_LEN +
                             PBKDF_SALT_LEN +
                             MAC_OUTPUT_LEN +
                             ciphertext_len);

   for(size_t i = 0; i != VERSION_CODE_LEN; ++i)
     out_buf[i] = get_byte(i, CRYPTOBOX_VERSION_CODE);

   copy_mem(&out_buf[VERSION_CODE_LEN], pbkdf_salt.data(), PBKDF_SALT_LEN);

   BOTAN_ASSERT_EQUAL(
      pipe.read(&out_buf[VERSION_CODE_LEN + PBKDF_SALT_LEN], MAC_OUTPUT_LEN, 1),
      MAC_OUTPUT_LEN, "MAC output");
   BOTAN_ASSERT_EQUAL(
      pipe.read(&out_buf[VERSION_CODE_LEN + PBKDF_SALT_LEN + MAC_OUTPUT_LEN],
                ciphertext_len, 0),
      ciphertext_len, "Ciphertext size");

   return PEM_Code::encode(out_buf, "BOTAN CRYPTOBOX MESSAGE");
   }

std::string decrypt(const byte input[], size_t input_len,
                    const std::string& passphrase)
   {
   DataSource_Memory input_src(input, input_len);
   secure_vector<byte> ciphertext =
      PEM_Code::decode_check_label(input_src,
                                   "BOTAN CRYPTOBOX MESSAGE");

   if(ciphertext.size() < (VERSION_CODE_LEN + PBKDF_SALT_LEN + MAC_OUTPUT_LEN))
      throw Decoding_Error("Invalid CryptoBox input");

   for(size_t i = 0; i != VERSION_CODE_LEN; ++i)
      if(ciphertext[i] != get_byte(i, CRYPTOBOX_VERSION_CODE))
         throw Decoding_Error("Bad CryptoBox version");

   const byte* pbkdf_salt = &ciphertext[VERSION_CODE_LEN];

   PKCS5_PBKDF2 pbkdf(new HMAC(new SHA_512));

   OctetString master_key = pbkdf.derive_key(
      PBKDF_OUTPUT_LEN,
      passphrase,
      pbkdf_salt,
      PBKDF_SALT_LEN,
      PBKDF_ITERATIONS);

   const byte* mk = master_key.begin();

   SymmetricKey cipher_key(mk, CIPHER_KEY_LEN);
   SymmetricKey mac_key(&mk[CIPHER_KEY_LEN], MAC_KEY_LEN);
   InitializationVector iv(&mk[CIPHER_KEY_LEN + MAC_KEY_LEN], CIPHER_IV_LEN);

   Pipe pipe(new Fork(
                get_cipher("Serpent/CTR-BE", cipher_key, iv, DECRYPTION),
                new MAC_Filter(new HMAC(new SHA_512),
                               mac_key, MAC_OUTPUT_LEN)));

   const size_t ciphertext_offset =
      VERSION_CODE_LEN + PBKDF_SALT_LEN + MAC_OUTPUT_LEN;

   pipe.process_msg(&ciphertext[ciphertext_offset],
                    ciphertext.size() - ciphertext_offset);

   byte computed_mac[MAC_OUTPUT_LEN];
   BOTAN_ASSERT_EQUAL(MAC_OUTPUT_LEN, pipe.read(computed_mac, MAC_OUTPUT_LEN, 1), "MAC size");

   if(!same_mem(computed_mac,
                &ciphertext[VERSION_CODE_LEN + PBKDF_SALT_LEN],
                MAC_OUTPUT_LEN))
      throw Decoding_Error("CryptoBox integrity failure");

   return pipe.read_all_as_string(0);
   }

std::string decrypt(const std::string& input,
                    const std::string& passphrase)
   {
   return decrypt(reinterpret_cast<const byte*>(input.data()),
                  input.size(),
                  passphrase);
   }

}

}
