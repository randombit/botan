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
const uint32_t CRYPTOBOX_VERSION_CODE = 0xEFC22400;

const size_t VERSION_CODE_LEN = 4;
const size_t CIPHER_KEY_LEN = 32;
const size_t CIPHER_IV_LEN = 16;
const size_t MAC_KEY_LEN = 32;
const size_t MAC_OUTPUT_LEN = 20;
const size_t PBKDF_SALT_LEN = 10;
const size_t PBKDF_ITERATIONS = 8 * 1024;

const size_t PBKDF_OUTPUT_LEN = CIPHER_KEY_LEN + MAC_KEY_LEN + CIPHER_IV_LEN;
const size_t HEADER_LEN = VERSION_CODE_LEN + PBKDF_SALT_LEN + MAC_OUTPUT_LEN;

}

std::string encrypt(const uint8_t input[], size_t input_len,
                    const std::string& passphrase,
                    RandomNumberGenerator& rng)
   {
   /*
   Output format is:
      version # (4 bytes)
      salt (10 bytes)
      mac (20 bytes)
      ciphertext
   */
   secure_vector<uint8_t> out_buf(HEADER_LEN + input_len);
   for(size_t i = 0; i != VERSION_CODE_LEN; ++i)
     out_buf[i] = get_byte(i, CRYPTOBOX_VERSION_CODE);
   rng.randomize(&out_buf[VERSION_CODE_LEN], PBKDF_SALT_LEN);
   // space left for MAC here
   copy_mem(&out_buf[HEADER_LEN], input, input_len);

   // Generate the keys and IV

   std::unique_ptr<PBKDF> pbkdf(PBKDF::create_or_throw("PBKDF2(HMAC(SHA-512))"));

   OctetString master_key = pbkdf->derive_key(
      CIPHER_KEY_LEN + MAC_KEY_LEN + CIPHER_IV_LEN,
      passphrase,
      &out_buf[VERSION_CODE_LEN],
      PBKDF_SALT_LEN,
      PBKDF_ITERATIONS);

   const uint8_t* mk = master_key.begin();
   const uint8_t* cipher_key = mk;
   const uint8_t* mac_key = mk + CIPHER_KEY_LEN;
   const uint8_t* iv = mk + CIPHER_KEY_LEN + MAC_KEY_LEN;

   // Now encrypt and authenticate
   std::unique_ptr<Cipher_Mode> ctr(get_cipher_mode("Serpent/CTR-BE", ENCRYPTION));
   ctr->set_key(cipher_key, CIPHER_KEY_LEN);
   ctr->start(iv, CIPHER_IV_LEN);
   ctr->finish(out_buf, HEADER_LEN);

   std::unique_ptr<MessageAuthenticationCode> hmac =
      MessageAuthenticationCode::create_or_throw("HMAC(SHA-512)");
   hmac->set_key(mac_key, MAC_KEY_LEN);
   hmac->update(&out_buf[HEADER_LEN], input_len);

   // Can't write directly because of MAC truncation
   secure_vector<uint8_t> mac = hmac->final();
   copy_mem(&out_buf[VERSION_CODE_LEN + PBKDF_SALT_LEN], mac.data(), MAC_OUTPUT_LEN);

   return PEM_Code::encode(out_buf, "BOTAN CRYPTOBOX MESSAGE");
   }

std::string decrypt(const uint8_t input[], size_t input_len,
                    const std::string& passphrase)
   {
   DataSource_Memory input_src(input, input_len);
   secure_vector<uint8_t> ciphertext =
      PEM_Code::decode_check_label(input_src,
                                   "BOTAN CRYPTOBOX MESSAGE");

   if(ciphertext.size() < (VERSION_CODE_LEN + PBKDF_SALT_LEN + MAC_OUTPUT_LEN))
      throw Decoding_Error("Invalid CryptoBox input");

   for(size_t i = 0; i != VERSION_CODE_LEN; ++i)
      if(ciphertext[i] != get_byte(i, CRYPTOBOX_VERSION_CODE))
         throw Decoding_Error("Bad CryptoBox version");

   const uint8_t* pbkdf_salt = &ciphertext[VERSION_CODE_LEN];

   PKCS5_PBKDF2 pbkdf(new HMAC(new SHA_512));

   OctetString master_key = pbkdf.derive_key(
      PBKDF_OUTPUT_LEN,
      passphrase,
      pbkdf_salt,
      PBKDF_SALT_LEN,
      PBKDF_ITERATIONS);

   const uint8_t* mk = master_key.begin();

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

   uint8_t computed_mac[MAC_OUTPUT_LEN];
   BOTAN_ASSERT_EQUAL(MAC_OUTPUT_LEN, pipe.read(computed_mac, MAC_OUTPUT_LEN, 1), "MAC size");

   if(!constant_time_compare(computed_mac,
                &ciphertext[VERSION_CODE_LEN + PBKDF_SALT_LEN],
                MAC_OUTPUT_LEN))
      throw Decoding_Error("CryptoBox integrity failure");

   return pipe.read_all_as_string(0);
   }

std::string decrypt(const std::string& input,
                    const std::string& passphrase)
   {
   return decrypt(reinterpret_cast<const uint8_t*>(input.data()),
                  input.size(),
                  passphrase);
   }

}

}
