/*
* Format Preserving Encryption (FE1 scheme)
* (C) 2009 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/fpe_fe1.h>
#include <botan/numthry.h>
#include <botan/hmac.h>
#include <botan/sha2_32.h>
#include <stdexcept>

namespace Botan {

namespace FPE {

namespace {

// Normally FPE is for SSNs, CC#s, etc, nothing too big
const size_t MAX_N_BYTES = 128/8;

/*
* Factor n into a and b which are as close together as possible.
* Assumes n is composed mostly of small factors which is the case for
* typical uses of FPE (typically, n is a power of 10)
*
* Want a >= b since the safe number of rounds is 2+log_a(b); if a >= b
* then this is always 3
*/
void factor(BigInt n, BigInt& a, BigInt& b)
   {
   a = 1;
   b = 1;

   size_t n_low_zero = low_zero_bits(n);

   a <<= (n_low_zero / 2);
   b <<= n_low_zero - (n_low_zero / 2);
   n >>= n_low_zero;

   for(size_t i = 0; i != PRIME_TABLE_SIZE; ++i)
      {
      while(n % PRIMES[i] == 0)
         {
         a *= PRIMES[i];
         if(a > b)
            std::swap(a, b);
         n /= PRIMES[i];
         }
      }

   if(a > b)
      std::swap(a, b);
   a *= n;
   if(a < b)
      std::swap(a, b);

   if(a <= 1 || b <= 1)
      throw std::runtime_error("Could not factor n for use in FPE");
   }

/*
* According to a paper by Rogaway, Bellare, etc, the min safe number
* of rounds to use for FPE is 2+log_a(b). If a >= b then log_a(b) <= 1
* so 3 rounds is safe. The FPE factorization routine should always
* return a >= b, so just confirm that and return 3.
*/
size_t rounds(const BigInt& a, const BigInt& b)
   {
   if(a < b)
      throw std::logic_error("FPE rounds: a < b");
   return 3;
   }

/*
* A simple round function based on HMAC(SHA-256)
*/
class FPE_Encryptor
   {
   public:
      FPE_Encryptor(const SymmetricKey& key,
                    const BigInt& n,
                    const std::vector<byte>& tweak);

      BigInt operator()(size_t i, const BigInt& R);

   private:
      std::unique_ptr<MessageAuthenticationCode> mac;
      std::vector<byte> mac_n_t;
   };

FPE_Encryptor::FPE_Encryptor(const SymmetricKey& key,
                             const BigInt& n,
                             const std::vector<byte>& tweak)
   {
   mac.reset(new HMAC(new SHA_256));
   mac->set_key(key);

   std::vector<byte> n_bin = BigInt::encode(n);

   if(n_bin.size() > MAX_N_BYTES)
      throw std::runtime_error("N is too large for FPE encryption");

   mac->update_be(static_cast<u32bit>(n_bin.size()));
   mac->update(n_bin.data(), n_bin.size());

   mac->update_be(static_cast<u32bit>(tweak.size()));
   mac->update(tweak.data(), tweak.size());

   mac_n_t = unlock(mac->final());
   }

BigInt FPE_Encryptor::operator()(size_t round_no, const BigInt& R)
   {
   secure_vector<byte> r_bin = BigInt::encode_locked(R);

   mac->update(mac_n_t);
   mac->update_be(static_cast<u32bit>(round_no));

   mac->update_be(static_cast<u32bit>(r_bin.size()));
   mac->update(r_bin.data(), r_bin.size());

   secure_vector<byte> X = mac->final();
   return BigInt(X.data(), X.size());
   }

}

/*
* Generic Z_n FPE encryption, FE1 scheme
*/
BigInt fe1_encrypt(const BigInt& n, const BigInt& X0,
                   const SymmetricKey& key,
                   const std::vector<byte>& tweak)
   {
   FPE_Encryptor F(key, n, tweak);

   BigInt a, b;
   factor(n, a, b);

   const size_t r = rounds(a, b);

   BigInt X = X0;

   for(size_t i = 0; i != r; ++i)
      {
      BigInt L = X / b;
      BigInt R = X % b;

      BigInt W = (L + F(i, R)) % a;
      X = a * R + W;
      }

   return X;
   }

/*
* Generic Z_n FPE decryption, FD1 scheme
*/
BigInt fe1_decrypt(const BigInt& n, const BigInt& X0,
                   const SymmetricKey& key,
                   const std::vector<byte>& tweak)
   {
   FPE_Encryptor F(key, n, tweak);

   BigInt a, b;
   factor(n, a, b);

   const size_t r = rounds(a, b);

   BigInt X = X0;

   for(size_t i = 0; i != r; ++i)
      {
      BigInt W = X % a;
      BigInt R = X / a;

      BigInt L = (W - F(r-i-1, R)) % a;
      X = b * L + R;
      }

   return X;
   }

}

}
