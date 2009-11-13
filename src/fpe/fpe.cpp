/*
* Format Preserving Encryption
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/fpe.h>
#include <botan/numthry.h>
#include <botan/hmac.h>
#include <botan/sha2_32.h>
#include <botan/loadstor.h>
#include <stdexcept>

#include <iostream>

namespace Botan {

namespace {

// Normally FPE is for SSNs, CC#s, etc, nothing too big
const u32bit MAX_N_BYTES = 128/8;

void factor(BigInt n, BigInt& a, BigInt& b)
   {
   a = 1;
   b = 1;

   for(u32bit i = 0; i != PRIME_TABLE_SIZE; ++i)
      {
      while(n % PRIMES[i] == 0)
         {
         a *= PRIMES[i];
         std::swap(a, b);
         n /= PRIMES[i];
         }
      }

   a *= n;

   if(a <= 1 || b <= 1)
      throw std::runtime_error("Could not factor n for use in FPE");
   }

u32bit rounds(const BigInt& a, const BigInt& b)
   {
   return 8;
   }

class FPE_Encryptor
   {
   public:
      FPE_Encryptor(const SymmetricKey& key,
                    const BigInt& n,
                    const MemoryRegion<byte>& tweak);

      ~FPE_Encryptor() { delete mac; }

      BigInt operator()(u32bit i, const BigInt& R);

   private:
      MessageAuthenticationCode* mac;
      SecureVector<byte> mac_n_t;
   };

FPE_Encryptor::FPE_Encryptor(const SymmetricKey& key,
                             const BigInt& n,
                             const MemoryRegion<byte>& tweak)
   {
   mac = new HMAC(new SHA_256);
   mac->set_key(key);

   SecureVector<byte> n_bin = BigInt::encode(n);

   if(n_bin.size() > MAX_N_BYTES)
      throw std::runtime_error("N is too large for FPE encryption");

   for(u32bit i = 0; i != 4; ++i)
      mac->update(get_byte(i, n_bin.size()));
   mac->update(&n_bin[0], n_bin.size());

   for(u32bit i = 0; i != 4; ++i)
      mac->update(get_byte(i, tweak.size()));
   mac->update(&tweak[0], tweak.size());

   mac_n_t = mac->final();
   }

BigInt FPE_Encryptor::operator()(u32bit round_no, const BigInt& R)
   {
   mac->update(mac_n_t);

   for(u32bit i = 0; i != 4; ++i)
      mac->update(get_byte(i, round_no));

   SecureVector<byte> r_bin = BigInt::encode(R);

   for(u32bit i = 0; i != 4; ++i)
      mac->update(get_byte(i, r_bin.size()));
   mac->update(&r_bin[0], r_bin.size());

   SecureVector<byte> X = mac->final();
   return BigInt(&X[0], X.size());
   }

}

/**
* Generic Z_n FPE encryption, FE1 scheme
* See http://eprint.iacr.org/2009/251
*/
BigInt fpe_encrypt(const BigInt& n, const BigInt& X0,
                   const SymmetricKey& key,
                   const MemoryRegion<byte>& tweak)
   {
   FPE_Encryptor F(key, n, tweak);

   BigInt a, b;
   factor(n, a, b);

   const u32bit r = rounds(a, b);

   BigInt X = X0;

   for(u32bit i = 0; i != r; ++i)
      {
      BigInt L = X / b;
      BigInt R = X % b;

      BigInt W = (L + F(i, R)) % a;
      X = a * R + W;
      }

   return X;
   }

/**
* Generic Z_n FPE decryption, FD1 scheme
* See http://eprint.iacr.org/2009/251
*/
BigInt fpe_decrypt(const BigInt& n, const BigInt& X0,
                   const SymmetricKey& key,
                   const MemoryRegion<byte>& tweak)
   {
   FPE_Encryptor F(key, n, tweak);

   BigInt a, b;
   factor(n, a, b);

   const u32bit r = rounds(a, b);

   BigInt X = X0;

   for(u32bit i = 0; i != r; ++i)
      {
      BigInt W = X % a;
      BigInt R = X / a;

      BigInt L = (W - F(r-i, R)) % a;
      X = b*L + R;
      }

   return X;
   }

}
