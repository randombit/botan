/*
* Bcrypt Password Hashing
* (C) 2010,2018,2020 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/bcrypt.h>

#include <botan/base64.h>
#include <botan/rng.h>
#include <botan/internal/blowfish.h>
#include <botan/internal/ct_utils.h>
#include <botan/internal/fmt.h>
#include <botan/internal/parsing.h>

namespace Botan {

namespace {

// Bcrypt uses a non-standard base64 alphabet
uint8_t base64_to_bcrypt_encoding(uint8_t c) {
   const auto is_ab = CT::Mask<uint8_t>::is_within_range(c, 'a', 'b');
   const auto is_cz = CT::Mask<uint8_t>::is_within_range(c, 'c', 'z');
   const auto is_CZ = CT::Mask<uint8_t>::is_within_range(c, 'C', 'Z');

   const auto is_01 = CT::Mask<uint8_t>::is_within_range(c, '0', '1');
   const auto is_29 = CT::Mask<uint8_t>::is_within_range(c, '2', '9');

   const auto is_A = CT::Mask<uint8_t>::is_equal(c, 'A');
   const auto is_B = CT::Mask<uint8_t>::is_equal(c, 'B');
   const auto is_plus = CT::Mask<uint8_t>::is_equal(c, '+');
   const auto is_slash = CT::Mask<uint8_t>::is_equal(c, '/');

   uint8_t ret = 0x80;
   ret = is_ab.select(c - 'a' + 'Y', ret);
   ret = is_cz.select(c - 2, ret);
   ret = is_CZ.select(c - 2, ret);
   ret = is_01.select(c - '0' + 'y', ret);
   ret = is_29.select(c - '2' + '0', ret);
   ret = is_A.select('.', ret);
   ret = is_B.select('/', ret);
   ret = is_plus.select('8', ret);
   ret = is_slash.select('9', ret);

   return ret;
}

uint8_t bcrypt_encoding_to_base64(uint8_t c) {
   const auto is_ax = CT::Mask<uint8_t>::is_within_range(c, 'a', 'x');
   const auto is_yz = CT::Mask<uint8_t>::is_within_range(c, 'y', 'z');

   const auto is_AX = CT::Mask<uint8_t>::is_within_range(c, 'A', 'X');
   const auto is_YZ = CT::Mask<uint8_t>::is_within_range(c, 'Y', 'Z');
   const auto is_07 = CT::Mask<uint8_t>::is_within_range(c, '0', '7');

   const auto is_8 = CT::Mask<uint8_t>::is_equal(c, '8');
   const auto is_9 = CT::Mask<uint8_t>::is_equal(c, '9');
   const auto is_dot = CT::Mask<uint8_t>::is_equal(c, '.');
   const auto is_slash = CT::Mask<uint8_t>::is_equal(c, '/');

   uint8_t ret = 0x80;
   ret = is_ax.select(c - 'a' + 'c', ret);
   ret = is_yz.select(c - 'y' + '0', ret);
   ret = is_AX.select(c - 'A' + 'C', ret);
   ret = is_YZ.select(c - 'Y' + 'a', ret);
   ret = is_07.select(c - '0' + '2', ret);
   ret = is_8.select('+', ret);
   ret = is_9.select('/', ret);
   ret = is_dot.select('A', ret);
   ret = is_slash.select('B', ret);

   return ret;
}

std::string bcrypt_base64_encode(const uint8_t input[], size_t length) {
   std::string b64 = base64_encode(input, length);

   while(!b64.empty() && b64[b64.size() - 1] == '=') {
      b64 = b64.substr(0, b64.size() - 1);
   }

   for(size_t i = 0; i != b64.size(); ++i) {
      b64[i] = static_cast<char>(base64_to_bcrypt_encoding(static_cast<uint8_t>(b64[i])));
   }

   return b64;
}

std::vector<uint8_t> bcrypt_base64_decode(std::string_view input) {
   std::string translated;
   for(size_t i = 0; i != input.size(); ++i) {
      char c = bcrypt_encoding_to_base64(static_cast<uint8_t>(input[i]));
      translated.push_back(c);
   }

   return unlock(base64_decode(translated));
}

std::string make_bcrypt(std::string_view pass, const std::vector<uint8_t>& salt, uint16_t work_factor, char version) {
   /*
   * On a 4 GHz Skylake, workfactor == 18 takes about 15 seconds to
   * hash a password. This seems like a reasonable upper bound for the
   * time being.
   * Bcrypt allows up to work factor 31 (2^31 iterations)
   */
   BOTAN_ARG_CHECK(work_factor >= 4 && work_factor <= 18, "Invalid bcrypt work factor");

   alignas(64) static const uint8_t BCRYPT_MAGIC[8 * 3] = {0x4F, 0x72, 0x70, 0x68, 0x65, 0x61, 0x6E, 0x42,
                                                           0x65, 0x68, 0x6F, 0x6C, 0x64, 0x65, 0x72, 0x53,
                                                           0x63, 0x72, 0x79, 0x44, 0x6F, 0x75, 0x62, 0x74};

   Blowfish blowfish;

   secure_vector<uint8_t> pass_with_trailing_null(pass.size() + 1);
   copy_mem(pass_with_trailing_null.data(), cast_char_ptr_to_uint8(pass.data()), pass.length());

   // Include the trailing NULL byte, so we need c_str() not data()
   blowfish.salted_set_key(
      pass_with_trailing_null.data(), pass_with_trailing_null.size(), salt.data(), salt.size(), work_factor);

   std::vector<uint8_t> ctext(BCRYPT_MAGIC, BCRYPT_MAGIC + 8 * 3);

   for(size_t i = 0; i != 64; ++i) {
      blowfish.encrypt_n(ctext.data(), ctext.data(), 3);
   }

   std::string salt_b64 = bcrypt_base64_encode(salt.data(), salt.size());

   std::string work_factor_str = std::to_string(work_factor);
   if(work_factor_str.length() == 1) {
      work_factor_str = "0" + work_factor_str;
   }

   return fmt("$2{}${}${}{}",
              version,
              work_factor_str,
              salt_b64.substr(0, 22),
              bcrypt_base64_encode(ctext.data(), ctext.size() - 1));
}

}  // namespace

std::string generate_bcrypt(std::string_view pass, RandomNumberGenerator& rng, uint16_t work_factor, char version) {
   /*
   2a, 2b and 2y are identical for our purposes because our implementation of 2a
   never had the truncation or signed char bugs in the first place.
   */

   if(version != 'a' && version != 'b' && version != 'y') {
      throw Invalid_Argument("Unknown bcrypt version '" + std::string(1, version) + "'");
   }

   std::vector<uint8_t> salt;
   rng.random_vec(salt, 16);
   return make_bcrypt(pass, salt, work_factor, version);
}

bool check_bcrypt(std::string_view pass, std::string_view hash) {
   if(hash.size() != 60 || hash[0] != '$' || hash[1] != '2' || hash[3] != '$' || hash[6] != '$') {
      return false;
   }

   const char bcrypt_version = hash[2];

   if(bcrypt_version != 'a' && bcrypt_version != 'b' && bcrypt_version != 'y') {
      return false;
   }

   const uint16_t workfactor = to_uint16(hash.substr(4, 2));

   const std::vector<uint8_t> salt = bcrypt_base64_decode(hash.substr(7, 22));
   if(salt.size() != 16) {
      return false;
   }

   const std::string compare = make_bcrypt(pass, salt, workfactor, bcrypt_version);

   return CT::is_equal(cast_char_ptr_to_uint8(hash.data()), cast_char_ptr_to_uint8(compare.data()), compare.size())
      .as_bool();
}

}  // namespace Botan
