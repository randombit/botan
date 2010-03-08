/*
* Blinding for public key operations
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/blinding.h>
#include <botan/numthry.h>
#include <botan/libstate.h>
#include <botan/hash.h>
#include <botan/time.h>
#include <botan/loadstor.h>
#include <memory>

namespace Botan {

/*
* Blinder Constructor
*/
Blinder::Blinder(const BigInt& e, const BigInt& d, const BigInt& n)
   {
   if(e < 1 || d < 1 || n < 1)
      throw Invalid_Argument("Blinder: Arguments too small");

   reducer = Modular_Reducer(n);
   this->e = e;
   this->d = d;
   }

BigInt Blinder::choose_nonce(const BigInt& x, const BigInt& mod)
   {
   Algorithm_Factory& af = global_state().algorithm_factory();

   std::auto_ptr<HashFunction> hash(af.make_hash_function("SHA-512"));

   u64bit ns_clock = get_nanoseconds_clock();
   for(size_t i = 0; i != sizeof(ns_clock); ++i)
      hash->update(get_byte(i, ns_clock));

   hash->update(BigInt::encode(x));
   hash->update(BigInt::encode(mod));

   u64bit timestamp = system_time();
   for(size_t i = 0; i != sizeof(timestamp); ++i)
      hash->update(get_byte(i, timestamp));

   SecureVector<byte> r = hash->final();

   return BigInt::decode(r) % mod;
   }

/*
* Blind a number
*/
BigInt Blinder::blind(const BigInt& i) const
   {
   if(!reducer.initialized())
      return i;

   e = reducer.square(e);
   d = reducer.square(d);
   return reducer.multiply(i, e);
   }

/*
* Unblind a number
*/
BigInt Blinder::unblind(const BigInt& i) const
   {
   if(!reducer.initialized())
      return i;
   return reducer.multiply(i, d);
   }

}
