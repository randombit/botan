/*
* Cryptobox Message Routines
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/cryptobox.h>
#include <botan/filters.h>
#include <botan/pipe.h>
#include <botan/serpent.h>
#include <botan/sha2_64.h>
#include <botan/ctr.h>
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

const u32bit VERSION_CODE_LEN = 4;
const u32bit CIPHER_KEY_LEN = 32;
const u32bit CIPHER_IV_LEN = 16;
const u32bit MAC_KEY_LEN = 32;
const u32bit MAC_OUTPUT_LEN = 20;
const u32bit PBKDF_SALT_LEN = 10;
const u32bit PBKDF_ITERATIONS = 8 * 1024;

const u32bit PBKDF_OUTPUT_LEN = CIPHER_KEY_LEN + CIPHER_IV_LEN + MAC_KEY_LEN;

}

std::string encrypt(const byte input[], u32bit input_len,
                    const std::string& passphrase,
                    RandomNumberGenerator& rng)
   {
   SecureVector<byte> pbkdf_salt(PBKDF_SALT_LEN);
   rng.randomize(pbkdf_salt.begin(), pbkdf_salt.size());

   PKCS5_PBKDF2 pbkdf(new HMAC(new SHA_512));
   pbkdf.change_salt(pbkdf_salt.begin(), pbkdf_salt.size());
   pbkdf.set_iterations(PBKDF_ITERATIONS);

   OctetString mk = pbkdf.derive_key(PBKDF_OUTPUT_LEN, passphrase);

   SymmetricKey cipher_key(mk.begin(), CIPHER_KEY_LEN);
   SymmetricKey mac_key(mk.begin() + CIPHER_KEY_LEN, MAC_KEY_LEN);
   InitializationVector iv(mk.begin() + CIPHER_KEY_LEN + MAC_KEY_LEN,
                           CIPHER_IV_LEN);

   Pipe pipe(new CTR_BE(new Serpent, cipher_key, iv),
             new Fork(
                0,
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
   u32bit ciphertext_len = pipe.remaining(0);

   SecureVector<byte> out_buf;

   for(u32bit i = 0; i != VERSION_CODE_LEN; ++i)
      out_buf.append(get_byte(i, CRYPTOBOX_VERSION_CODE));

   out_buf.append(pbkdf_salt.begin(), pbkdf_salt.size());

   out_buf.grow_to(out_buf.size() + MAC_OUTPUT_LEN + ciphertext_len);
   pipe.read(out_buf + VERSION_CODE_LEN + PBKDF_SALT_LEN, MAC_OUTPUT_LEN, 1);
   pipe.read(out_buf + VERSION_CODE_LEN + PBKDF_SALT_LEN + MAC_OUTPUT_LEN,
             ciphertext_len, 0);

   return PEM_Code::encode(out_buf.begin(), out_buf.size(),
                           "BOTAN CRYPTOBOX MESSAGE");
   }

std::string decrypt(const byte input[], u32bit input_len,
                    const std::string& passphrase)
   {
   DataSource_Memory input_src(input, input_len);
   SecureVector<byte> ciphertext =
      PEM_Code::decode_check_label(input_src,
                                   "BOTAN CRYPTOBOX MESSAGE");

   if(ciphertext.size() < (VERSION_CODE_LEN + PBKDF_SALT_LEN + MAC_OUTPUT_LEN))
      throw Decoding_Error("Invalid CryptoBox input");

   for(u32bit i = 0; i != VERSION_CODE_LEN; ++i)
      if(ciphertext[i] != get_byte(i, CRYPTOBOX_VERSION_CODE))
         throw Decoding_Error("Bad CryptoBox version");

   SecureVector<byte> pbkdf_salt(ciphertext + VERSION_CODE_LEN, PBKDF_SALT_LEN);

   PKCS5_PBKDF2 pbkdf(new HMAC(new SHA_512));
   pbkdf.change_salt(pbkdf_salt.begin(), pbkdf_salt.size());
   pbkdf.set_iterations(PBKDF_ITERATIONS);

   OctetString mk = pbkdf.derive_key(PBKDF_OUTPUT_LEN, passphrase);

   SymmetricKey cipher_key(mk.begin(), CIPHER_KEY_LEN);
   SymmetricKey mac_key(mk.begin() + CIPHER_KEY_LEN, MAC_KEY_LEN);
   InitializationVector iv(mk.begin() + CIPHER_KEY_LEN + MAC_KEY_LEN,
                           CIPHER_IV_LEN);

   Pipe pipe(new Fork(
                new CTR_BE(new Serpent, cipher_key, iv),
                new MAC_Filter(new HMAC(new SHA_512),
                               mac_key, MAC_OUTPUT_LEN)));

   const u32bit ciphertext_offset =
      VERSION_CODE_LEN + PBKDF_SALT_LEN + MAC_OUTPUT_LEN;

   pipe.process_msg(ciphertext + ciphertext_offset,
                    ciphertext.size() - ciphertext_offset);

   byte computed_mac[MAC_OUTPUT_LEN];
   pipe.read(computed_mac, MAC_OUTPUT_LEN, 1);

   if(!same_mem(computed_mac, ciphertext + VERSION_CODE_LEN + PBKDF_SALT_LEN,
                MAC_OUTPUT_LEN))
      throw Integrity_Failure("CryptoBox integrity failure");

   return pipe.read_all_as_string(0);
   }

}

}
