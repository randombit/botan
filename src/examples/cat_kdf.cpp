#include <botan/auto_rng.h>
#include <botan/hash.h>
#include <botan/hex.h>
#include <botan/kdf.h>
#include <botan/pk_algs.h>
#include <botan/pubkey.h>

#include <iostream>
#include <numeric>

namespace {

// TS 103 744 - V1.1.1, Section 7.2, Context formatting function (f)
std::vector<uint8_t> f_context_func(std::string_view hash_function, const std::vector<std::span<const uint8_t>>& val) {
   auto hash = Botan::HashFunction::create_or_throw(hash_function);
   for(const auto& v : val) {
      BOTAN_ARG_CHECK(v.size() <= 0xFFFFFFFF, "Value too long");
      auto len = static_cast<uint32_t>(v.size());
      hash->update_be(len);
      hash->update(v);
   }
   return hash->final_stdvec();
}

// TS 103 744 - V1.1.1, Section 8.2, Concatenate hybrid key agreement scheme
void cat_kdf_secret_combiner(std::span<uint8_t> out_key_material /* also defines length */,
                             std::string_view hash_function,
                             std::span<const uint8_t> psk,
                             const std::vector<std::span<const uint8_t>>& ki,
                             std::span<const uint8_t> ma,
                             std::span<const uint8_t> mb,
                             std::span<const uint8_t> context,
                             std::span<const uint8_t> label) {
   // TS 103 744 - V1.1.1, Section 8.2
   // 1) Form secret = psk || k_1 || k_2 || … || k_n.
   size_t secret_len = std::accumulate(
      ki.begin(), ki.end(), size_t(0), [](size_t sum, std::span<const uint8_t> ss) { return sum + ss.size(); });

   Botan::secure_vector<uint8_t> secret;
   secret.reserve(secret_len);
   secret.insert(secret.end(), psk.begin(), psk.end());
   for(const auto& k_i : ki) {
      secret.insert(secret.end(), k_i.begin(), k_i.end());
   }
   BOTAN_ASSERT_NOMSG(secret.size() == secret_len);

   // 2) Set f_context = f(context, MA, MB), where f is a context formatting function.
   const auto f_context = f_context_func(hash_function, {context, ma, mb});

   // 3) key_material = KDF(secret, label, f_context, length).
   auto kdf = Botan::KDF::create_or_throw("HKDF(" + std::string(hash_function) + ")");
   kdf->derive_key(out_key_material, secret, label, f_context);
}

// Concatenation operator for up to three spans
std::vector<uint8_t> concat(std::span<const uint8_t> s1,
                            std::span<const uint8_t> s2,
                            std::span<const uint8_t> s3 = {}) {
   std::vector<uint8_t> out;
   out.reserve(s1.size() + s2.size() + s3.size());
   for(auto s : {s1, s2, s3}) {
      out.insert(out.end(), s.begin(), s.end());
   }
   return out;
}

// Concatenation operator as used in the specification
std::vector<uint8_t> bytes_from_string(std::string_view str) {
   return {str.begin(), str.end()};
}

// TS 103 744 - V1.1.1 - Test C.2.1
bool test_kdf() {
   auto la = Botan::hex_decode("0102030405060708090A0B0C0D0E0F10");
   auto pa1 = Botan::hex_decode(
      "119F2F047902782AB0C9E27A54AFF5EB9B964829CA99C06B02DDBA95B0A3F6D08F52B726664CAC366FC"
      "98AC7A012B2682CBD962E5ACB544671D41B9445704D1D");
   auto pa2 = Botan::hex_decode(
      "4484D7AADB44B40CC180DC568B2C142A60E6E2863F5988614A6215254B2F5F6F79B48F329AD1A2DED2"
      "0B7ABAB10F7DBF59C3E20B59A700093060D2A44ACDC0083A53CF0808E0B3A827C45176BEE0DC6EC7CC1"
      "6461E38461C12451BB95191407C1E942BB50D4C7B25A49C644B630159E6C403653838E689FBF4A7ADEA"
      "693ED0657BA4A724786AF7953F7BA6E15F9BBF9F5007FB711569E72ACAB05D3463A458536CAB647F00C"
      "205D27D5311B2A5113D4B26548000DB237515931A040804E769361F94FF0167C78353D2630A1E6F595A"
      "1F80E87F6A5BCD679D7A64C5006F6191D4ADEFA1EA67F6388B7017D453F4FE2DFE80CCC709000B52175"
      "BFC3ADE52ECCB0CEBE1654F89D39131C357EACB61E5F13C80AB0165B7714D6BE6DF65F8DE73FF47B7F3"
      "304639F0903653ECCFA252F6E2104C4ABAD3C33AF24FD0E56F58DB92CC66859766035419AB2DF600");
   auto lb = Botan::hex_decode("0202030405060708090A0B0C0D0E0F10");
   auto pb1 = Botan::hex_decode(
      "809F04289C64348C01515EB03D5CE7AC1A8CB9498F5CAA50197E58D43A86A7AEB29D84E811197F25EBA"
      "8F5194092CB6FF440E26D4421011372461F579271CDA3");
   auto pb2 = Botan::hex_decode(
      "0FDEB26DBD96E0CD272283CA5BDD1435BC9A7F9AB7FC24F83CA926DEED038AE4E47F39F9886E0BD7EEB"
      "EAACD12AB435CC92AA3383B2C01E6B9E02BC3BEF9C6C2719014562A96A0F3E784E3FA44E5C62ED8CEA7"
      "9E1108B6FECD5BF8836BF2DAE9FEB1863C4C8B3429220E2797F601FB4B8EBAFDD4F17355508D259CA60"
      "721D167F6E5480B5133E824F76D3240E97F31325DBB9A53E9A3EEE2E0712734825615A027857E2000D4"
      "D00E11988499A738452C93DA895BFA0E10294895CCF25E3C261CBE38F5D7E19ABE4E322094CB8DEC5BF"
      "7484902BABDE33CC69595F6013B20AABA9698C1DEA2BC6F65D57519294E6FEEA3B549599D480948374D"
      "2D21B643573C276E1A5B0745301F648D7982AB46A3065639960182BF365819EFC0D4E61E87D2820DBC0"
      "E849E99E875B21501D1CA7588A1D458CD70C7DF793D4993B9B1679886CAE8013A8DD854F010A100C993"
      "3FA642DC0AEA9985786ED36B98D3");
   auto k1 = Botan::hex_decode_locked("057D636096CB80B67A8C038C890E887D1ADFA4195E9B3CE241C8A778C59CDA67");
   auto k2 = Botan::hex_decode_locked("35F7F8FF388714DEDC41F139078CEDC9");

   auto context = bytes_from_string("CONCATENATION TEST VECTOR 1");

   auto label = concat(la, lb);
   auto ma = concat(la, pa1, pa2);
   auto mb = concat(lb, pb1, pb2);

   auto expected_key_material = Botan::hex_decode_locked("5C366F23281D33EB85CAB026D3D9A35A");

   Botan::secure_vector<uint8_t> key_material(expected_key_material.size());
   cat_kdf_secret_combiner(key_material, "SHA-256", {/* no psk */}, {k1, k2}, ma, mb, context, label);

   return key_material == expected_key_material;
}

// TS 103 744 - Section 8.1.2 - ResponseFunc(P)
std::pair<Botan::secure_vector<uint8_t>, std::vector<uint8_t>> response_func_kex(const Botan::Public_Key& pub_key,
                                                                                 Botan::RandomNumberGenerator& rng) {
   const auto sk_prime = pub_key.generate_another(rng);
   auto big_R = sk_prime->public_key_bits();
   auto k =
      Botan::PK_Key_Agreement(*sk_prime, rng, "Raw").derive_key(0 /* ignored */, pub_key.public_key_bits()).bits_of();
   return std::make_pair(std::move(k), std::move(big_R));
}

// TS 103 744 - Section 8.1.3 - ResponseFunc(P)
std::pair<Botan::secure_vector<uint8_t>, std::vector<uint8_t>> response_func_kem(const Botan::Public_Key& pub_key,
                                                                                 Botan::RandomNumberGenerator& rng) {
   auto [r_1, k_1_b] = Botan::KEM_Encapsulation::destructure(Botan::PK_KEM_Encryptor(pub_key, "Raw").encrypt(rng));
   return std::make_pair(std::move(k_1_b), std::move(r_1));
}

// TS 103 744 - Section 8.1.2 - ReceiveFunc(sk, R)
Botan::secure_vector<uint8_t> receive_func_kex(const Botan::Private_Key& sk,
                                               std::span<const uint8_t> big_r,
                                               Botan::RandomNumberGenerator& rng) {
   return Botan::PK_Key_Agreement(sk, rng, "Raw").derive_key(0 /* ignored */, big_r).bits_of();
}

// TS 103 744 - Section 8.1.3 - ReceiveFunc(sk, R)
Botan::secure_vector<uint8_t> receive_func_kem(const Botan::Private_Key& sk,
                                               std::span<const uint8_t> big_r,
                                               Botan::RandomNumberGenerator& rng) {
   return Botan::PK_KEM_Decryptor(sk, rng, "Raw").decrypt(big_r);
}

// Example CatKDF Protocol flow
bool my_protocol() {
   Botan::AutoSeeded_RNG rng;

   // Parameter Configuration
   const size_t key_len = 32;
   const std::vector<uint8_t> label_a = {'A', 'L', 'I', 'C', 'E'};
   const std::vector<uint8_t> label_b = {'B', 'O', 'B'};
   const auto label = concat(label_a, label_b);
   const std::vector<uint8_t> context = {'M', 'Y', ' ', 'P', 'R', 'O', 'T', 'O', 'C', 'O', 'L'};

   // === Alice (Initiator) ===
   auto sk_1 = Botan::create_private_key("Kyber", rng, "Kyber-768-r3");
   auto big_p_1 = sk_1->public_key();

   auto sk_2 = Botan::create_private_key("ECDH", rng, "secp256r1");
   auto big_p_2 = sk_2->public_key();

   auto ma = std::make_pair(big_p_1->public_key_bits(), big_p_2->public_key_bits());
   // ---------- MA ----------->

   // === Bob (Responder) ===
   auto big_p_1_from_a = Botan::load_public_key(big_p_1->algorithm_identifier(), ma.first);
   auto [k_1_b, r_1] = response_func_kem(*big_p_1_from_a, rng);

   auto big_p_2_from_a = Botan::load_public_key(big_p_2->algorithm_identifier(), ma.second);
   auto [k_2_b, r_2] = response_func_kex(*big_p_2_from_a, rng);

   auto mb = std::make_pair(r_1, r_2);
   // <---------- MB -----------

   // === Alice (Initiator) ===
   auto k_1_a = receive_func_kem(*sk_1, r_1, rng);
   auto k_2_a = receive_func_kex(*sk_2, r_2, rng);

   // === Key Derivation ===
   auto ma_bytes = concat(ma.first, ma.second);
   auto mb_bytes = concat(mb.first, mb.second);

   // Alice Key Derivation
   Botan::secure_vector<uint8_t> key_material_a(key_len);
   cat_kdf_secret_combiner(
      key_material_a, "SHA-256", {/* no psk */}, {k_1_a, k_2_a}, ma_bytes, mb_bytes, context, label);

   // Bob Key Derivation
   Botan::secure_vector<uint8_t> key_material_b(key_len);
   cat_kdf_secret_combiner(
      key_material_b, "SHA-256", {/* no psk */}, {k_1_b, k_2_b}, ma_bytes, mb_bytes, context, label);

   return key_material_a == key_material_b;
}

}  // namespace

int main() {
   if(!test_kdf()) {
      std::cout << "CatKDF test failed" << std::endl;
      return 1;
   }
   std::cout << "CatKDF test passed" << std::endl;

   if(!my_protocol()) {
      std::cout << "CatKDF key exchange failed" << std::endl;
      return 1;
   }
   std::cout << "CatKDF key exchange successful" << std::endl;
   return 0;
}
