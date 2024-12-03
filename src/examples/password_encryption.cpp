#include <botan/aead.h>
#include <botan/assert.h>
#include <botan/auto_rng.h>
#include <botan/hex.h>
#include <botan/pwdhash.h>

#include <iostream>

namespace {

template <typename OutT = std::vector<uint8_t>, typename... Ts>
OutT concat(const Ts&... buffers) {
   OutT out;
   out.reserve((buffers.size() + ... + 0));
   (out.insert(out.end(), buffers.begin(), buffers.end()), ...);
   return out;
}

template <typename Out, typename In>
Out as(const In& data) {
   return Out(data.data(), data.data() + data.size());
}

constexpr size_t salt_length = 16;

Botan::secure_vector<uint8_t> derive_key_material(std::string_view password,
                                                  std::span<const uint8_t> salt,
                                                  size_t output_length) {
   // Here, we use statically defined password hash parameters. Alternatively
   // you could use Botan::PasswordHashFamily::tune() to automatically select
   // parameters based on your desired runtime and memory usage.
   //
   // Defining those parameters highly depends on your use case and the
   // available compute and memory resources on your target platform.
   const std::string pbkdf_algo = "Argon2id";
   constexpr size_t M = 256 * 1024;  // kiB
   constexpr size_t t = 4;           // iterations
   constexpr size_t p = 2;           // parallelism

   auto pbkdf = Botan::PasswordHashFamily::create_or_throw(pbkdf_algo)->from_params(M, t, p);
   BOTAN_ASSERT_NONNULL(pbkdf);

   Botan::secure_vector<uint8_t> key(output_length);
   pbkdf->hash(key, password, salt);

   return key;
}

std::unique_ptr<Botan::AEAD_Mode> prepare_aead(std::string_view password,
                                               std::span<const uint8_t> salt,
                                               Botan::Cipher_Dir direction) {
   auto aead = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", direction);

   const size_t key_length = aead->key_spec().maximum_keylength();
   const size_t nonce_length = aead->default_nonce_length();

   // Stretch the password into enough cryptographically strong key material
   // to initialize the AEAD with a key and nonce (aka. initialization vector).
   const auto keydata = derive_key_material(password, salt, key_length + nonce_length);
   BOTAN_ASSERT_NOMSG(keydata.size() == key_length + nonce_length);
   const auto key = std::span{keydata}.first(key_length);
   const auto nonce = std::span{keydata}.last(nonce_length);

   aead->set_key(key);
   aead->start(nonce);

   return aead;
}

/**
 * Encrypts the data in @p plaintext using the given @p password.
 *
 * To resist offline brute-force attacks we stretch the password into key
 * material using a password-based key derivation function (PBKDF). The key
 * material is then used to initialize an AEAD for encryption and authentication
 * of the plaintext. This ensures that on-one can read or manipulate the data
 * without knowledge of the password.
 */
std::vector<uint8_t> encrypt_by_password(std::string_view password,
                                         Botan::RandomNumberGenerator& rng,
                                         std::span<const uint8_t> plaintext) {
   const auto kdf_salt = rng.random_array<salt_length>();
   auto aead = prepare_aead(password, kdf_salt, Botan::Cipher_Dir::Encryption);

   Botan::secure_vector<uint8_t> out(plaintext.begin(), plaintext.end());
   aead->finish(out);

   // The random salt used by the key derivation function is not secret and is
   // therefore prepended to the ciphertext.
   return concat(kdf_salt, out);
}

/**
 * Decrypts the output of `encrypt_by_password` given the correct @p password
 * or throws an exception if decryption is not possible.
 */
Botan::secure_vector<uint8_t> decrypt_by_password(std::string_view password, std::span<const uint8_t> wrapped_data) {
   if(wrapped_data.size() < salt_length) {
      throw std::runtime_error("Encrypted data is too short");
   }

   const auto kdf_salt = wrapped_data.first<salt_length>();
   auto aead = prepare_aead(password, kdf_salt, Botan::Cipher_Dir::Decryption);

   const auto ciphertext = wrapped_data.subspan(salt_length);
   Botan::secure_vector<uint8_t> out(ciphertext.begin(), ciphertext.end());

   try {
      aead->finish(out);
   } catch(const Botan::Invalid_Authentication_Tag&) {
      throw std::runtime_error("Failed to decrypt, wrong password?");
   }

   return out;
}

}  // namespace

int main() {
   Botan::AutoSeeded_RNG rng;

   // Note: For simplicity we omit the authentication of any associated data.
   //       If your use case would benefit from it, you should add it. Perhaps
   //       to both the password hashing and the AEAD.
   std::string_view password = "geheimnis";
   std::string_view message = "Attack at dawn!";

   try {
      const auto ciphertext = encrypt_by_password(password, rng, as<Botan::secure_vector<uint8_t>>(message));
      std::cout << "Ciphertext: " << Botan::hex_encode(ciphertext) << "\n";

      const auto decrypted_message = decrypt_by_password(password, ciphertext);
      BOTAN_ASSERT_NOMSG(message.size() == decrypted_message.size() &&
                         std::equal(message.begin(), message.end(), decrypted_message.begin()));

      std::cout << "Decrypted message: " << as<std::string>(decrypted_message) << "\n";
   } catch(const std::exception& ex) {
      std::cerr << "Something went wrong: " << ex.what() << "\n";
      return 1;
   }

   return 0;
}
