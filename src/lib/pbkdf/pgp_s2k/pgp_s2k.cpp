/*
* OpenPGP S2K
* (C) 1999-2007,2017 Jack Lloyd
* (C) 2018 Ribose Inc
*
* Distributed under the terms of the Botan license
*/

#include <botan/pgp_s2k.h>
#include <botan/exceptn.h>
#include <botan/internal/timer.h>
#include <algorithm>

namespace Botan {

/*
PGP stores the iteration count as a single byte
Thus it can only actually take on one of 256 values, based on the
formula in RFC 4880 section 3.6.1.3
*/
static const uint32_t OPENPGP_S2K_ITERS[256] = {
   1024, 1088, 1152, 1216, 1280, 1344, 1408, 1472, 1536, 1600,
   1664, 1728, 1792, 1856, 1920, 1984, 2048, 2176, 2304, 2432,
   2560, 2688, 2816, 2944, 3072, 3200, 3328, 3456, 3584, 3712,
   3840, 3968, 4096, 4352, 4608, 4864, 5120, 5376, 5632, 5888,
   6144, 6400, 6656, 6912, 7168, 7424, 7680, 7936, 8192, 8704,
   9216, 9728, 10240, 10752, 11264, 11776, 12288, 12800, 13312,
   13824, 14336, 14848, 15360, 15872, 16384, 17408, 18432, 19456,
   20480, 21504, 22528, 23552, 24576, 25600, 26624, 27648, 28672,
   29696, 30720, 31744, 32768, 34816, 36864, 38912, 40960, 43008,
   45056, 47104, 49152, 51200, 53248, 55296, 57344, 59392, 61440,
   63488, 65536, 69632, 73728, 77824, 81920, 86016, 90112, 94208,
   98304, 102400, 106496, 110592, 114688, 118784, 122880, 126976,
   131072, 139264, 147456, 155648, 163840, 172032, 180224, 188416,
   196608, 204800, 212992, 221184, 229376, 237568, 245760, 253952,
   262144, 278528, 294912, 311296, 327680, 344064, 360448, 376832,
   393216, 409600, 425984, 442368, 458752, 475136, 491520, 507904,
   524288, 557056, 589824, 622592, 655360, 688128, 720896, 753664,
   786432, 819200, 851968, 884736, 917504, 950272, 983040, 1015808,
   1048576, 1114112, 1179648, 1245184, 1310720, 1376256, 1441792,
   1507328, 1572864, 1638400, 1703936, 1769472, 1835008, 1900544,
   1966080, 2031616, 2097152, 2228224, 2359296, 2490368, 2621440,
   2752512, 2883584, 3014656, 3145728, 3276800, 3407872, 3538944,
   3670016, 3801088, 3932160, 4063232, 4194304, 4456448, 4718592,
   4980736, 5242880, 5505024, 5767168, 6029312, 6291456, 6553600,
   6815744, 7077888, 7340032, 7602176, 7864320, 8126464, 8388608,
   8912896, 9437184, 9961472, 10485760, 11010048, 11534336,
   12058624, 12582912, 13107200, 13631488, 14155776, 14680064,
   15204352, 15728640, 16252928, 16777216, 17825792, 18874368,
   19922944, 20971520, 22020096, 23068672, 24117248, 25165824,
   26214400, 27262976, 28311552, 29360128, 30408704, 31457280,
   32505856, 33554432, 35651584, 37748736, 39845888, 41943040,
   44040192, 46137344, 48234496, 50331648, 52428800, 54525952,
   56623104, 58720256, 60817408, 62914560, 65011712 };

uint8_t RFC4880_encode_count(size_t desired_iterations)
   {
   if(desired_iterations <= OPENPGP_S2K_ITERS[0])
      return 0;

   if(desired_iterations >= OPENPGP_S2K_ITERS[255])
      return 255;

   auto i = std::lower_bound(OPENPGP_S2K_ITERS, OPENPGP_S2K_ITERS + 256, desired_iterations);

   return static_cast<uint8_t>(i - OPENPGP_S2K_ITERS);
   }

size_t RFC4880_decode_count(uint8_t iter)
   {
   return OPENPGP_S2K_ITERS[iter];
   }

namespace {

void pgp_s2k(HashFunction& hash,
             uint8_t output_buf[], size_t output_len,
             const char* password, const size_t password_size,
             const uint8_t salt[], size_t salt_len,
             size_t iterations)
   {
   if(iterations > 1 && salt_len == 0)
      throw Invalid_Argument("OpenPGP S2K requires a salt in iterated mode");

   secure_vector<uint8_t> input_buf(salt_len + password_size);
   if(salt_len > 0)
      {
      copy_mem(&input_buf[0], salt, salt_len);
      }
   if(password_size > 0)
      {
      copy_mem(&input_buf[salt_len],
               cast_char_ptr_to_uint8(password),
               password_size);
      }

   secure_vector<uint8_t> hash_buf(hash.output_length());

   size_t pass = 0;
   size_t generated = 0;

   while(generated != output_len)
      {
      const size_t output_this_pass =
         std::min(hash_buf.size(), output_len - generated);

      // Preload some number of zero bytes (empty first iteration)
      std::vector<uint8_t> zero_padding(pass);
      hash.update(zero_padding);

      // The input is always fully processed even if iterations is very small
      if(input_buf.empty() == false)
         {
         size_t left = std::max(iterations, input_buf.size());
         while(left > 0)
            {
            const size_t input_to_take = std::min(left, input_buf.size());
            hash.update(input_buf.data(), input_to_take);
            left -= input_to_take;
            }
         }

      hash.final(hash_buf.data());
      copy_mem(output_buf + generated, hash_buf.data(), output_this_pass);
      generated += output_this_pass;
      ++pass;
      }
   }

}

size_t OpenPGP_S2K::pbkdf(uint8_t output_buf[], size_t output_len,
                          const std::string& password,
                          const uint8_t salt[], size_t salt_len,
                          size_t iterations,
                          std::chrono::milliseconds msec) const
   {
   std::unique_ptr<PasswordHash> pwdhash;

   if(iterations == 0)
      {
      RFC4880_S2K_Family s2k_params(m_hash->clone());
      iterations = s2k_params.tune(output_len, msec, 0)->iterations();
      }

   pgp_s2k(*m_hash, output_buf, output_len,
           password.c_str(), password.size(),
           salt, salt_len,
           iterations);

   return iterations;
   }

std::string RFC4880_S2K_Family::name() const
   {
   return "OpenPGP-S2K(" + m_hash->name() + ")";
   }

std::unique_ptr<PasswordHash> RFC4880_S2K_Family::tune(size_t output_len, std::chrono::milliseconds msec, size_t) const
   {
   const auto tune_time = BOTAN_PBKDF_TUNING_TIME;

   const size_t buf_size = 1024;
   std::vector<uint8_t> buffer(buf_size);

   Timer timer("RFC4880_S2K", buf_size);
   timer.run_until_elapsed(tune_time, [&]() {
      m_hash->update(buffer);
      });

   const double hash_bytes_per_second = timer.bytes_per_second();
   const uint64_t desired_nsec = msec.count() * 1000000;

   const size_t hash_size = m_hash->output_length();
   const size_t blocks_required = (output_len <= hash_size ? 1 : (output_len + hash_size - 1) / hash_size);

   const double bytes_to_be_hashed = (hash_bytes_per_second * (desired_nsec / 1000000000.0)) / blocks_required;
   const size_t iterations = RFC4880_round_iterations(static_cast<size_t>(bytes_to_be_hashed));

   return std::unique_ptr<PasswordHash>(new RFC4880_S2K(m_hash->clone(), iterations));
   }

std::unique_ptr<PasswordHash> RFC4880_S2K_Family::from_params(size_t iter, size_t, size_t) const
   {
   return std::unique_ptr<PasswordHash>(new RFC4880_S2K(m_hash->clone(), iter));
   }

std::unique_ptr<PasswordHash> RFC4880_S2K_Family::default_params() const
   {
   return std::unique_ptr<PasswordHash>(new RFC4880_S2K(m_hash->clone(), 50331648));
   }

std::unique_ptr<PasswordHash> RFC4880_S2K_Family::from_iterations(size_t iter) const
   {
   return std::unique_ptr<PasswordHash>(new RFC4880_S2K(m_hash->clone(), iter));
   }

RFC4880_S2K::RFC4880_S2K(HashFunction* hash, size_t iterations) :
   m_hash(hash),
   m_iterations(iterations)
   {
   }

std::string RFC4880_S2K::to_string() const
   {
   return "OpenPGP-S2K(" + m_hash->name() + "," + std::to_string(m_iterations) + ")";
   }

void RFC4880_S2K::derive_key(uint8_t out[], size_t out_len,
                             const char* password, const size_t password_len,
                             const uint8_t salt[], size_t salt_len) const
   {
   pgp_s2k(*m_hash, out, out_len,
           password, password_len,
           salt, salt_len,
           m_iterations);
   }

}
