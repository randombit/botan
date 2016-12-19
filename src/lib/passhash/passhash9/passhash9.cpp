/*
* Passhash9 Password Hashing
* (C) 2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/passhash9.h>
#include <botan/loadstor.h>
#include <botan/pbkdf2.h>
#include <botan/base64.h>

namespace Botan {

namespace {

const std::string MAGIC_PREFIX = "$9$";

const size_t WORKFACTOR_BYTES = 2;
const size_t ALGID_BYTES = 1;
const size_t SALT_BYTES = 12; // 96 bits of salt
const size_t PASSHASH9_PBKDF_OUTPUT_LEN = 24; // 192 bits output

const size_t WORK_FACTOR_SCALE = 10000;

std::unique_ptr<MessageAuthenticationCode> get_pbkdf_prf(uint8_t alg_id) {
  if (alg_id == 0) {
    return MessageAuthenticationCode::create("HMAC(SHA-1)");
  }
  else if (alg_id == 1) {
    return MessageAuthenticationCode::create("HMAC(SHA-256)");
  }
  else if (alg_id == 2) {
    return MessageAuthenticationCode::create("CMAC(Blowfish)");
  }
  else if (alg_id == 3) {
    return MessageAuthenticationCode::create("HMAC(SHA-384)");
  }
  else if (alg_id == 4) {
    return MessageAuthenticationCode::create("HMAC(SHA-512)");
  }
  return nullptr;
}

}

std::string generate_passhash9(const std::string& pass,
                               RandomNumberGenerator& rng,
                               uint16_t work_factor,
                               uint8_t alg_id) {
  std::unique_ptr<MessageAuthenticationCode> prf = get_pbkdf_prf(alg_id);

  if (!prf)
    throw Invalid_Argument("Passhash9: Algorithm id " +
                           std::to_string(alg_id) +
                           " is not defined");

  PKCS5_PBKDF2 kdf(prf.release()); // takes ownership of pointer

  secure_vector<uint8_t> salt(SALT_BYTES);
  rng.randomize(salt.data(), salt.size());

  const size_t kdf_iterations = WORK_FACTOR_SCALE * work_factor;

  secure_vector<uint8_t> blob;
  blob.push_back(alg_id);
  blob.push_back(get_byte(0, work_factor));
  blob.push_back(get_byte(1, work_factor));
  blob += salt;
  blob += kdf.derive_key(PASSHASH9_PBKDF_OUTPUT_LEN,
                         pass,
                         salt.data(), salt.size(),
                         kdf_iterations).bits_of();

  return MAGIC_PREFIX + base64_encode(blob);
}

bool check_passhash9(const std::string& pass, const std::string& hash) {
  const size_t BINARY_LENGTH =
    ALGID_BYTES +
    WORKFACTOR_BYTES +
    PASSHASH9_PBKDF_OUTPUT_LEN +
    SALT_BYTES;

  const size_t BASE64_LENGTH =
    MAGIC_PREFIX.size() + (BINARY_LENGTH * 8) / 6;

  if (hash.size() != BASE64_LENGTH) {
    return false;
  }

  for (size_t i = 0; i != MAGIC_PREFIX.size(); ++i)
    if (hash[i] != MAGIC_PREFIX[i]) {
      return false;
    }

  secure_vector<uint8_t> bin = base64_decode(hash.c_str() + MAGIC_PREFIX.size());

  if (bin.size() != BINARY_LENGTH) {
    return false;
  }

  uint8_t alg_id = bin[0];

  const size_t work_factor = load_be<uint16_t>(&bin[ALGID_BYTES], 0);

  // Bug in the format, bad states shouldn't be representable, but are...
  if (work_factor == 0) {
    return false;
  }

  if (work_factor > 512)
    throw Invalid_Argument("Requested Bcrypt work factor " +
                           std::to_string(work_factor) + " too large");

  const size_t kdf_iterations = WORK_FACTOR_SCALE * work_factor;

  std::unique_ptr<MessageAuthenticationCode> pbkdf_prf = get_pbkdf_prf(alg_id);

  if (!pbkdf_prf) {
    return false;  // unknown algorithm, reject
  }

  PKCS5_PBKDF2 kdf(pbkdf_prf.release()); // takes ownership of pointer

  secure_vector<uint8_t> cmp = kdf.derive_key(
                                 PASSHASH9_PBKDF_OUTPUT_LEN,
                                 pass,
                                 &bin[ALGID_BYTES + WORKFACTOR_BYTES], SALT_BYTES,
                                 kdf_iterations).bits_of();

  return same_mem(cmp.data(),
                  &bin[ALGID_BYTES + WORKFACTOR_BYTES + SALT_BYTES],
                  PASSHASH9_PBKDF_OUTPUT_LEN);
}

}
