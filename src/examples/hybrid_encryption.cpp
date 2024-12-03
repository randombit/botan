#include <botan/aead.h>
#include <botan/auto_rng.h>
#include <botan/pubkey.h>
#include <botan/rsa.h>
#include <botan/secmem.h>

#include <iostream>

struct EncryptedData {
      Botan::secure_vector<uint8_t> ciphertext;
      std::vector<uint8_t> nonce;
      std::vector<uint8_t> encryptedKey;
};

namespace {

std::unique_ptr<Botan::Private_Key> generate_keypair(const size_t bits, Botan::RandomNumberGenerator& rng) {
   return std::make_unique<Botan::RSA_PrivateKey>(rng, bits);
}

EncryptedData encrypt(std::span<const uint8_t> data,
                      std::unique_ptr<Botan::Public_Key> pubkey,
                      Botan::RandomNumberGenerator& rng) {
   auto sym_cipher = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Encryption);

   EncryptedData d;

   // prepare random key material for the symmetric encryption/authentication
   const auto key = rng.random_vec(sym_cipher->minimum_keylength());
   d.nonce = rng.random_vec<std::vector<uint8_t>>(sym_cipher->default_nonce_length());
   d.ciphertext.assign(data.begin(), data.end());

   // encrypt/authenticate the data symmetrically
   sym_cipher->set_key(key);
   sym_cipher->start(d.nonce);
   sym_cipher->finish(d.ciphertext);

   // encrypt the symmetric key using RSA with a secure padding scheme
   Botan::PK_Encryptor_EME asym_cipher(*pubkey, rng, "EME-OAEP(SHA-256,MGF1)");
   d.encryptedKey = asym_cipher.encrypt(key, rng);

   return d;
}

Botan::secure_vector<uint8_t> decrypt(const EncryptedData& encdata,
                                      const Botan::Private_Key& privkey,
                                      Botan::RandomNumberGenerator& rng) {
   Botan::secure_vector<uint8_t> plaintext = encdata.ciphertext;

   // decrypt the symmetric key
   Botan::PK_Decryptor_EME asym_cipher(privkey, rng, "EME-OAEP(SHA-256,MGF1)");
   const auto key = asym_cipher.decrypt(encdata.encryptedKey);

   // decrypt the data symmetrically
   auto sym_cipher = Botan::AEAD_Mode::create_or_throw("AES-256/GCM", Botan::Cipher_Dir::Decryption);
   sym_cipher->set_key(key);
   sym_cipher->start(encdata.nonce);
   sym_cipher->finish(plaintext);

   return plaintext;
}

template <typename Out, typename In>
Out as(const In& data) {
   return Out(data.data(), data.data() + data.size());
}

}  // namespace

int main() {
   Botan::AutoSeeded_RNG rng;

   const auto privkey = generate_keypair(2048 /*  bits */, rng);

   const std::string_view plaintext = "The quick brown fox jumps over the lazy dog.";
   const auto ciphertext = encrypt(as<Botan::secure_vector<uint8_t>>(plaintext), privkey->public_key(), rng);
   const auto new_plaintext = decrypt(ciphertext, *privkey, rng);

   std::cout << as<std::string>(new_plaintext) << '\n';

   return 0;
}
