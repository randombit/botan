/*
* (C) 2016 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"

#if defined(BOTAN_HAS_DL_GROUP)
   #include <botan/dl_group.h>
   #include <botan/exceptn.h>
   #include <botan/hex.h>
   #include <botan/rng.h>
   #include <botan/internal/dl_element.h>
   #include <botan/internal/dl_scalar.h>
   #include <botan/internal/workfactor.h>
#endif

namespace Botan_Tests {

#if defined(BOTAN_HAS_DL_GROUP)

namespace {

class DL_Group_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         std::vector<Test::Result> results;

         results.push_back(test_dl_encoding());
         results.push_back(test_dl_errors());
         results.push_back(test_mod_q_arithmetic());

         return results;
      }

   private:
      // These are deprecated, but have separate code paths for small and large q
      Test::Result test_mod_q_arithmetic() {
         Test::Result result("DL_Group mod q arithmetic");

         for(const auto& name : {"dsa/jce/1024", "ffdhe/ietf/2048"}) {
            const auto group = Botan::DL_Group::from_name(name);
            const Botan::BigInt& q = group.get_q();

            std::vector<Botan::BigInt> values = {Botan::BigInt::zero(), Botan::BigInt::one(), q - 1};
            for(size_t i = 0; i != 4; ++i) {
               values.push_back(Botan::BigInt::random_integer(rng(), Botan::BigInt::zero(), q));
            }

            for(const auto& x : values) {
               result.test_bn_eq("square_mod_q", group.square_mod_q(x), (x * x) % q);
               for(const auto& y : values) {
                  result.test_bn_eq("multiply_mod_q", group.multiply_mod_q(x, y), (x * y) % q);
                  result.test_bn_eq("multiply_mod_q 3 arg", group.multiply_mod_q(x, y, x), (x * y * x) % q);
               }
            }

            result.test_throws<Botan::Invalid_Argument>("multiply_mod_q rejects q",
                                                        [&]() { group.multiply_mod_q(q, Botan::BigInt::one()); });
            result.test_throws<Botan::Invalid_Argument>("square_mod_q rejects q", [&]() { group.square_mod_q(q); });
         }

         return result;
      }

      static Test::Result test_dl_errors() {
         Test::Result result("DL_Group errors");
         result.test_throws("Uninitialized", "DL_Group uninitialized", []() {
            const Botan::DL_Group dl;
            dl.get_p();
         });

         result.test_throws<Botan::Decoding_Error>(
            "Subgroup order of 1 is rejected", "Invalid DL group subgroup order", []() {
               const auto group = Botan::DL_Group::from_name("modp/ietf/1024");
               const Botan::DL_Group dl(group.get_p(), Botan::BigInt::one(), group.get_g());
            });

         return result;
      }

      static Test::Result test_dl_encoding() {
         Test::Result result("DL_Group encoding");

         const auto orig = Botan::DL_Group::from_name("modp/ietf/1024");

         const std::string pem1 = orig.PEM_encode(Botan::DL_Group_Format::ANSI_X9_42);
         const std::string pem2 = orig.PEM_encode(Botan::DL_Group_Format::ANSI_X9_57);
         const std::string pem3 = orig.PEM_encode(Botan::DL_Group_Format::PKCS_3);

         const auto group1 = Botan::DL_Group::from_PEM(pem1);

         result.test_bn_eq("Same p in X9.42 decoding", group1.get_p(), orig.get_p());
         result.test_bn_eq("Same q in X9.42 decoding", group1.get_q(), orig.get_q());
         result.test_bn_eq("Same g in X9.42 decoding", group1.get_g(), orig.get_g());

         const auto group2 = Botan::DL_Group::from_PEM(pem2);

         result.test_bn_eq("Same p in X9.57 decoding", group2.get_p(), orig.get_p());
         result.test_bn_eq("Same q in X9.57 decoding", group2.get_q(), orig.get_q());
         result.test_bn_eq("Same g in X9.57 decoding", group2.get_g(), orig.get_g());

         const auto group3 = Botan::DL_Group::from_PEM(pem3);

         result.test_bn_eq("Same p in X9.57 decoding", group3.get_p(), orig.get_p());
         // no q in PKCS #3 format
         result.test_bn_eq("Same g in X9.57 decoding", group3.get_g(), orig.get_g());

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "dl_group", DL_Group_Tests);

class DL_Element_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         // Groups with and without q, including primes whose length is not a multiple of the word size
         const std::vector<std::pair<std::string, Botan::DL_Group>> groups = {
            {"modp/srp/1024", Botan::DL_Group::from_name("modp/srp/1024")},
            {"dsa/jce/1024", Botan::DL_Group::from_name("dsa/jce/1024")},
            {"modp/ietf/2048", Botan::DL_Group::from_name("modp/ietf/2048")},
            {"ffdhe/ietf/3072", Botan::DL_Group::from_name("ffdhe/ietf/3072")},
            {"2^127-1", Botan::DL_Group(Botan::BigInt::power_of_2(127) - 1, Botan::BigInt::from_word(3))},
            {"2^61-1", Botan::DL_Group(Botan::BigInt::power_of_2(61) - 1, Botan::BigInt::from_word(37))},
         };

         std::vector<Test::Result> results;
         results.reserve(groups.size() + 1);
         for(const auto& [name, group] : groups) {
            results.push_back(test_arithmetic(name, group));
         }
         results.push_back(test_errors(groups[0].second, groups[1].second));
         return results;
      }

   private:
      // Square and multiply using only BigInt arithmetic
      static Botan::BigInt ref_pow(const Botan::BigInt& b, const Botan::BigInt& k, const Botan::BigInt& p) {
         Botan::BigInt r = Botan::BigInt::one();
         for(size_t i = k.bits(); i > 0; --i) {
            r = (r * r) % p;
            if(k.get_bit(i - 1)) {
               r = (r * b) % p;
            }
         }
         return r;
      }

      Test::Result test_arithmetic(const std::string& name, const Botan::DL_Group& group) {
         Test::Result result("DL_Element " + name);

         const Botan::BigInt& p = group.get_p();
         const Botan::BigInt& g = group.get_g();
         const size_t p_bytes = group.p_bytes();

         std::vector<Botan::BigInt> values = {
            Botan::BigInt::zero(), Botan::BigInt::one(), Botan::BigInt::from_word(2), p - 2, p - 1};
         for(size_t i = 0; i != 6; ++i) {
            values.push_back(Botan::BigInt::random_integer(rng(), Botan::BigInt::zero(), p));
         }

         const auto elem = [&](const Botan::BigInt& x) { return Botan::DL_Element::from_bigint(group, x); };

         for(const auto& x : values) {
            const auto ex = elem(x);

            result.test_bn_eq("to_bigint", ex.to_bigint(), x);
            result.test_bin_eq("serialize", ex.serialize(), x.serialize(p_bytes));
            result.test_bn_eq("square", ex.square().to_bigint(), (x * x) % p);

            if(x.is_nonzero()) {
               result.test_bn_eq("invert", (ex.invert() * ex).to_bigint(), Botan::BigInt::one());
            }

            for(const auto& y : values) {
               const auto ey = elem(y);
               result.test_bn_eq("mul", (ex * ey).to_bigint(), (x * y) % p);
               result.test_bn_eq("add", (ex + ey).to_bigint(), (x + y) % p);
               result.test_bn_eq("sub", (ex - ey).to_bigint(), x >= y ? x - y : x + p - y);
            }
         }

         for(const size_t k_bits : {0, 1, 2, 63, 64, 65, 200}) {
            const Botan::BigInt k =
               (k_bits == 0) ? Botan::BigInt::zero()
                             : Botan::BigInt::random_integer(
                                  rng(), Botan::BigInt::power_of_2(k_bits - 1), Botan::BigInt::power_of_2(k_bits));

            // The bound may be larger than the exponent
            for(const size_t max_k_bits : {k_bits, k_bits + 17}) {
               result.test_bn_eq("g_pow", Botan::DL_Element::g_pow(group, k, max_k_bits).to_bigint(), ref_pow(g, k, p));

               for(const auto& x : values) {
                  result.test_bn_eq("pow", elem(x).pow(k, max_k_bits).to_bigint(), ref_pow(x, k, p));
               }
            }
         }

         for(size_t i = 0; i != 10; ++i) {
            const auto r = Botan::DL_Element::random(group, rng()).to_bigint();
            result.test_is_true("random in range", r > 0 && r < p);
         }

         return result;
      }

      static Test::Result test_errors(const Botan::DL_Group& group1, const Botan::DL_Group& group2) {
         Test::Result result("DL_Element errors");

         const Botan::BigInt& p = group1.get_p();

         result.test_throws<Botan::Invalid_Argument>("p is out of range",
                                                     [&]() { Botan::DL_Element::from_bigint(group1, p); });
         result.test_throws<Botan::Invalid_Argument>(
            "negative is out of range", [&]() { Botan::DL_Element::from_bigint(group1, Botan::BigInt::from_s32(-1)); });
         result.test_throws<Botan::Invalid_Argument>(
            "zero has no inverse", [&]() { Botan::DL_Element::from_bigint(group1, Botan::BigInt::zero()).invert(); });

         const auto x = Botan::DL_Element::from_bigint(group1, Botan::BigInt::from_word(5));
         const auto y = Botan::DL_Element::from_bigint(group2, Botan::BigInt::from_word(5));
         result.test_throws<Botan::Invalid_Argument>("group mismatch", [&]() { x.mul(y); });

         std::vector<uint8_t> short_buf(group1.p_bytes() - 1);
         result.test_throws<Botan::Invalid_Argument>("short output", [&]() { x.serialize_to(short_buf); });

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "dl_element", DL_Element_Tests);

class DL_Scalar_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         // q of 160 and 256 bits
         const std::vector<std::string> groups = {
            "dsa/jce/1024",
            "dsa/botan/2048",
            "dsa/botan/3072",
         };

         std::vector<Test::Result> results;
         results.reserve(groups.size() + 1);
         for(const auto& name : groups) {
            results.push_back(test_arithmetic(name, Botan::DL_Group::from_name(name)));
         }
         results.push_back(test_errors());
         return results;
      }

   private:
      Test::Result test_arithmetic(const std::string& name, const Botan::DL_Group& group) {
         Test::Result result("DL_Scalar " + name);

         const Botan::BigInt& p = group.get_p();
         const Botan::BigInt& q = group.get_q();
         const size_t q_bytes = group.q_bytes();

         std::vector<Botan::BigInt> values = {
            Botan::BigInt::zero(), Botan::BigInt::one(), Botan::BigInt::from_word(2), q - 2, q - 1};
         for(size_t i = 0; i != 6; ++i) {
            values.push_back(Botan::BigInt::random_integer(rng(), Botan::BigInt::zero(), q));
         }

         const auto scalar = [&](const Botan::BigInt& x) { return Botan::DL_Scalar::from_bigint(group, x); };

         for(const auto& x : values) {
            const auto sx = scalar(x);

            result.test_bn_eq("to_bigint", sx.to_bigint(), x);
            result.test_bin_eq("serialize", sx.serialize(), x.serialize(q_bytes));
            result.test_bn_eq("square", sx.square().to_bigint(), (x * x) % q);
            result.test_is_true("is_zero", sx.is_zero() == x.is_zero());

            const auto decoded = Botan::DL_Scalar::deserialize(group, x.serialize(q_bytes));
            result.test_is_true("deserialize", decoded.has_value() && decoded.value() == sx);

            if(x.is_nonzero()) {
               result.test_bn_eq("invert", (sx.invert() * sx).to_bigint(), Botan::BigInt::one());
            }

            for(const auto& y : values) {
               const auto sy = scalar(y);
               result.test_bn_eq("mul", (sx * sy).to_bigint(), (x * y) % q);
               result.test_bn_eq("add", (sx + sy).to_bigint(), (x + y) % q);
               result.test_is_true("is_eq", (sx == sy) == (x == y));
            }
         }

         // Exponentiations are checked against DL_Element and BigInt reduction
         const auto ref_mod_q = [&](const Botan::DL_Element& e) { return e.to_bigint() % q; };

         for(const auto& k : values) {
            result.test_bn_eq("g_pow_mod_q",
                              Botan::DL_Scalar::g_pow_mod_q(scalar(k)).to_bigint(),
                              ref_mod_q(Botan::DL_Element::g_pow(group, k, group.q_bits())));
         }

         for(size_t i = 0; i != 4; ++i) {
            const auto y = Botan::BigInt::random_integer(rng(), Botan::BigInt::one(), p);
            const auto a = Botan::BigInt::random_integer(rng(), Botan::BigInt::zero(), q);
            const auto b =
               (i == 0) ? Botan::BigInt::zero() : Botan::BigInt::random_integer(rng(), Botan::BigInt::zero(), q);

            const auto expected = ref_mod_q(Botan::DL_Element::g_pow(group, a, group.q_bits()) *
                                            Botan::DL_Element::from_bigint(group, y).pow(b, group.q_bits()));

            result.test_bn_eq("multi_exp_mod_q_vartime",
                              Botan::DL_Scalar::multi_exp_mod_q_vartime(scalar(a), y, scalar(b)).to_bigint(),
                              expected);
         }

         for(const size_t len : {size_t(1), q_bytes - 1, q_bytes, q_bytes + 1, size_t(64)}) {
            const auto bytes = rng().random_vec(len);
            Botan::BigInt expected = Botan::BigInt::from_bytes(bytes);
            if(8 * len > group.q_bits()) {
               expected >>= 8 * len - group.q_bits();
            }
            result.test_bn_eq("from_bytes_with_trunc",
                              Botan::DL_Scalar::from_bytes_with_trunc(group, bytes).to_bigint(),
                              expected % q);
         }

         // Also exercises the reduction of a truncated value which is >= q
         const std::vector<uint8_t> all_ones(q_bytes + 3, 0xFF);
         result.test_bn_eq("from_bytes_with_trunc max",
                           Botan::DL_Scalar::from_bytes_with_trunc(group, all_ones).to_bigint(),
                           (Botan::BigInt::power_of_2(group.q_bits()) - 1) % q);

         result.test_is_true("deserialize rejects q", !Botan::DL_Scalar::deserialize(group, q.serialize(q_bytes)));
         result.test_is_true("deserialize rejects short input",
                             !Botan::DL_Scalar::deserialize(group, std::vector<uint8_t>(q_bytes - 1)));
         result.test_is_true("deserialize rejects long input",
                             !Botan::DL_Scalar::deserialize(group, std::vector<uint8_t>(q_bytes + 1)));

         for(size_t i = 0; i != 10; ++i) {
            const auto r = Botan::DL_Scalar::random(group, rng()).to_bigint();
            result.test_is_true("random in range", r > 0 && r < q);
         }

         return result;
      }

      static Test::Result test_errors() {
         Test::Result result("DL_Scalar errors");

         const auto group1 = Botan::DL_Group::from_name("dsa/jce/1024");
         const auto group2 = Botan::DL_Group::from_name("dsa/botan/2048");
         const Botan::BigInt& q = group1.get_q();

         result.test_throws<Botan::Invalid_Argument>("q is out of range",
                                                     [&]() { Botan::DL_Scalar::from_bigint(group1, q); });
         result.test_throws<Botan::Invalid_Argument>(
            "negative is out of range", [&]() { Botan::DL_Scalar::from_bigint(group1, Botan::BigInt::from_s32(-1)); });
         result.test_throws<Botan::Invalid_Argument>(
            "zero has no inverse", [&]() { Botan::DL_Scalar::from_bigint(group1, Botan::BigInt::zero()).invert(); });

         const auto x = Botan::DL_Scalar::from_bigint(group1, Botan::BigInt::from_word(5));
         const auto y = Botan::DL_Scalar::from_bigint(group2, Botan::BigInt::from_word(5));
         result.test_throws<Botan::Invalid_Argument>("group mismatch", [&]() { x.mul(y); });
         result.test_throws<Botan::Invalid_Argument>("group mismatch in comparison",
                                                     [&]() { static_cast<void>(x == y); });

         std::vector<uint8_t> short_buf(group1.q_bytes() - 1);
         result.test_throws<Botan::Invalid_Argument>("short output", [&]() { x.serialize_to(short_buf); });

         const auto no_q = Botan::DL_Group::from_name("modp/srp/1024");
         result.test_throws<Botan::Invalid_State>("group without q",
                                                  [&]() { Botan::DL_Scalar::from_bigint(no_q, Botan::BigInt::one()); });

         const auto large_q = Botan::DL_Group::from_name("ffdhe/ietf/2048");
         result.test_throws<Botan::Invalid_State>(
            "group with large q", [&]() { Botan::DL_Scalar::from_bigint(large_q, Botan::BigInt::one()); });

         return result;
      }
};

BOTAN_REGISTER_TEST("pubkey", "dl_scalar", DL_Scalar_Tests);

class DL_Generate_Group_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         Test::Result result("DL_Group generate");

         result.start_timer();

         auto& rng = this->rng();

         const Botan::DL_Group dh1050(rng, Botan::DL_Group::Prime_Subgroup, 1050, 175);
         result.test_sz_eq("DH p size", dh1050.get_p().bits(), 1050);
         result.test_sz_eq("DH q size", dh1050.get_q().bits(), 175);
         result.test_sz_lte("DH g size", dh1050.get_g().bits(), 1050);
         result.test_is_true("DH group verifies", dh1050.verify_group(rng, false));

         const Botan::DL_Group dh_implicit_q(rng, Botan::DL_Group::Prime_Subgroup, 1040);
         result.test_sz_eq("DH p size", dh_implicit_q.get_p().bits(), 1040);
         result.test_sz_eq("DH q size", dh_implicit_q.get_q().bits(), Botan::dl_exponent_size(1040));
         result.test_sz_lte("DH g size", dh_implicit_q.get_g().bits(), 1040);
         result.test_is_true("DH group verifies", dh_implicit_q.verify_group(rng, false));

         if(Test::run_long_tests()) {
            const Botan::DL_Group dh_strong(rng, Botan::DL_Group::Strong, 1025);
            result.test_sz_eq("DH p size", dh_strong.get_p().bits(), 1025);
            result.test_sz_eq("DH q size", dh_strong.get_q().bits(), 1024);
            result.test_bn_eq("DH generator", dh_strong.get_g(), Botan::BigInt::from_word(2));
            result.test_is_true("DH group verifies", dh_strong.verify_group(rng, false));
         }

   #if defined(BOTAN_HAS_SHA1)
         const Botan::DL_Group dsa1024(rng, Botan::DL_Group::DSA_Kosherizer, 1024);
         result.test_sz_eq("DSA p size", dsa1024.get_p().bits(), 1024);
         result.test_sz_eq("DSA q size", dsa1024.get_q().bits(), 160);
         result.test_sz_lte("DSA g size", dsa1024.get_g().bits(), 1024);
         result.test_is_true("DSA group verifies", dsa1024.verify_group(rng, false));

         const std::vector<uint8_t> invalid_seed(20);
         result.test_throws("DSA seed does not generate group",
                            "DL_Group: The seed given does not generate a DSA group",
                            [&rng, &invalid_seed]() { const Botan::DL_Group dsa(rng, invalid_seed, 1024, 160); });

         const std::vector<uint8_t> short_seed(16);
         result.test_throws(
            "DSA seed is too short",
            "Generating a DSA parameter set with a 160 bit long q requires a seed at least as many bits long",
            [&rng, &short_seed]() { const Botan::DL_Group dsa(rng, short_seed, 1024, 160); });

         const std::vector<uint8_t> working_seed = Botan::hex_decode("0000000000000000000000000000000000000021");
         const Botan::DL_Group dsa(rng, working_seed, 1024, 160);
         result.test_is_true("DSA group from working seed verifies", dsa.verify_group(rng, false));

         // From FIPS 186-3 test data
         const std::vector<uint8_t> seed = Botan::hex_decode("1F5DA0AF598EEADEE6E6665BF880E63D8B609BA2");

         result.test_throws("invalid params", [&]() { const Botan::DL_Group invalid(rng, seed, 1024, 224); });
         result.test_throws("invalid params", [&]() { const Botan::DL_Group invalid(rng, seed, 3072, 224); });
         result.test_throws("invalid params", [&]() { const Botan::DL_Group invalid(rng, seed, 2048, 256); });

         const Botan::DL_Group dsa_from_seed(rng, seed, 1024, 160);

         result.test_bn_eq(
            "DSA q from seed", dsa_from_seed.get_q(), Botan::BigInt("0xAB1A788BCE3C557A965A5BFA6908FAA665FDEB7D"));

         // Modulo just to avoid embedding entire 1024-bit P in src file
         result.test_sz_eq(
            "DSA p from seed", static_cast<size_t>(dsa_from_seed.get_p() % 4294967291), size_t(2513712339));

         result.test_is_true("DSA group from seed verifies", dsa_from_seed.verify_group(rng, false));
   #endif

         result.end_timer();

         return {result};
      }
};

BOTAN_REGISTER_TEST("pubkey", "dl_group_gen", DL_Generate_Group_Tests);

class DL_Named_Group_Tests final : public Test {
   public:
      std::vector<Test::Result> run() override {
         const std::vector<std::string> dl_named = {
            "modp/ietf/1024",  "modp/ietf/1536",  "modp/ietf/2048",  "modp/ietf/3072",  "modp/ietf/4096",
            "modp/ietf/6144",  "modp/ietf/8192",

            "modp/srp/1024",   "modp/srp/1536",   "modp/srp/2048",   "modp/srp/3072",   "modp/srp/4096",
            "modp/srp/6144",   "modp/srp/8192",

            "dsa/jce/1024",    "dsa/botan/2048",  "dsa/botan/3072",

            "ffdhe/ietf/2048", "ffdhe/ietf/3072", "ffdhe/ietf/4096", "ffdhe/ietf/6144", "ffdhe/ietf/8192",
         };

         Test::Result result("DL_Group named");
         result.start_timer();

         for(const std::string& name : dl_named) {
            // Confirm we can load every group we expect
            const auto group = Botan::DL_Group::from_name(name);

            result.test_bn_ne("DL_Group p is set", group.get_p(), 0);
            result.test_bn_ne("DL_Group g is set", group.get_g(), 0);

            const size_t strength = group.estimated_strength();

            // 8192 bit ~~ 2**202 strength
            result.test_is_true("Plausible strength", strength >= 80 && strength < 210);

            result.test_enum_eq("Expected source", group.source(), Botan::DL_Group_Source::Builtin);

            if(name.find("modp/srp/") == std::string::npos) {
               result.test_bn_ne("DL_Group q is set", group.get_q(), 0);
            } else {
               result.test_bn_eq("DL_Group q is not set for SRP groups", group.get_q(), 0);
            }

            const auto g_inv = Botan::DL_Element::inverse_of_g(group);
            if(group.get_g() == 2) {
               result.test_is_true("g^-1 is precomputed for g = 2", g_inv.has_value());
               if(g_inv) {
                  result.test_bn_eq(
                     "g^-1 is the inverse of g", (group.get_g() * g_inv->to_bigint()) % group.get_p(), 1);
               }
            } else {
               result.test_is_false("g^-1 is not precomputed for other g", g_inv.has_value());
            }

            if(group.p_bits() <= 1536 || Test::run_long_tests()) {
               result.test_is_true(name + " verifies", group.verify_group(this->rng()));
            }
         }
         result.end_timer();

         return {result};
      }
};

BOTAN_REGISTER_TEST("pubkey", "dl_group_named", DL_Named_Group_Tests);

}  // namespace

#endif

}  // namespace Botan_Tests
