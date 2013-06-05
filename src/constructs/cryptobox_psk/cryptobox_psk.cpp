/*
* Cryptobox Message Routines
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cryptobox.h>
#include <botan/pipe.h>
#include <botan/lookup.h>
#include <botan/loadstor.h>
#include <memory>

namespace Botan {

namespace CryptoBox {

namespace {

const u32bit CRYPTOBOX_MAGIC = 0x571B0E4F;
const std::string CRYPTOBOX_CIPHER = "AES-256/CBC";
const std::string CRYPTOBOX_MAC = "HMAC(SHA-256)";
const std::string CRYPTOBOX_KDF = "KDF2(SHA-256)";

const size_t MAGIC_LENGTH = 4;
const size_t KEY_KDF_SALT_LENGTH = 10;
const size_t MAC_KEY_LENGTH = 32;
const size_t CIPHER_KEY_LENGTH = 32;
const size_t CIPHER_IV_LENGTH = 16;
const size_t MAC_OUTPUT_LENGTH = 32;

}

std::vector<byte> encrypt(const byte input[], size_t input_len,
                          const SymmetricKey& master_key,
                          RandomNumberGenerator& rng)
   {
   std::unique_ptr<KDF> kdf(get_kdf(CRYPTOBOX_KDF));

   const secure_vector<byte> cipher_key_salt =
      rng.random_vec(KEY_KDF_SALT_LENGTH);

   const secure_vector<byte> mac_key_salt =
      rng.random_vec(KEY_KDF_SALT_LENGTH);

   SymmetricKey cipher_key =
      kdf->derive_key(CIPHER_KEY_LENGTH,
                      master_key.bits_of(),
                      cipher_key_salt);

   SymmetricKey mac_key =
      kdf->derive_key(MAC_KEY_LENGTH,
                      master_key.bits_of(),
                      mac_key_salt);

   InitializationVector cipher_iv(rng, 16);

   std::unique_ptr<MessageAuthenticationCode> mac(get_mac(CRYPTOBOX_MAC));
   mac->set_key(mac_key);

   Pipe pipe(get_cipher(CRYPTOBOX_CIPHER, cipher_key, cipher_iv, ENCRYPTION));
   pipe.process_msg(input, input_len);
   secure_vector<byte> ctext = pipe.read_all(0);

   std::vector<byte> out(MAGIC_LENGTH);
   store_be(CRYPTOBOX_MAGIC, &out[0]);
   out += cipher_key_salt;
   out += mac_key_salt;
   out += cipher_iv.bits_of();
   out += ctext;

   mac->update(out);

   out += mac->final();
   return out;
   }

secure_vector<byte> decrypt(const byte input[], size_t input_len,
                            const SymmetricKey& master_key)
   {
   const size_t MIN_CTEXT_SIZE = 16; // due to using CBC with padding

   const size_t MIN_POSSIBLE_LENGTH =
      MAGIC_LENGTH +
      2 * KEY_KDF_SALT_LENGTH +
      CIPHER_IV_LENGTH +
      MIN_CTEXT_SIZE +
      MAC_OUTPUT_LENGTH;

   if(input_len < MIN_POSSIBLE_LENGTH)
      throw Decoding_Error("Encrypted input too short to be valid");

   if(load_be<u32bit>(input, 0) != CRYPTOBOX_MAGIC)
      throw Decoding_Error("Unknown header value in cryptobox");

   std::unique_ptr<KDF> kdf(get_kdf(CRYPTOBOX_KDF));

   const byte* cipher_key_salt = &input[MAGIC_LENGTH];

   const byte* mac_key_salt = &input[MAGIC_LENGTH + KEY_KDF_SALT_LENGTH];

   SymmetricKey mac_key = kdf->derive_key(MAC_KEY_LENGTH,
                                          master_key.bits_of(),
                                          mac_key_salt,
                                          KEY_KDF_SALT_LENGTH);

   std::unique_ptr<MessageAuthenticationCode> mac(get_mac(CRYPTOBOX_MAC));
   mac->set_key(mac_key);

   mac->update(&input[0], input_len - MAC_OUTPUT_LENGTH);
   secure_vector<byte> computed_mac = mac->final();

   if(!same_mem(&input[input_len - MAC_OUTPUT_LENGTH], &computed_mac[0], computed_mac.size()))
      throw Decoding_Error("MAC verification failed");

   SymmetricKey cipher_key =
      kdf->derive_key(CIPHER_KEY_LENGTH,
                      master_key.bits_of(),
                      cipher_key_salt, KEY_KDF_SALT_LENGTH);

   InitializationVector cipher_iv(&input[MAGIC_LENGTH+2*KEY_KDF_SALT_LENGTH],
                                  CIPHER_IV_LENGTH);

   const size_t CTEXT_OFFSET = MAGIC_LENGTH + 2 * KEY_KDF_SALT_LENGTH + CIPHER_IV_LENGTH;

   Pipe pipe(get_cipher(CRYPTOBOX_CIPHER, cipher_key, cipher_iv, DECRYPTION));
   pipe.process_msg(&input[CTEXT_OFFSET],
                    input_len - (MAC_OUTPUT_LENGTH + CTEXT_OFFSET));
   return pipe.read_all();
   }

}

}
