/*************************************************
* Randpool Header File                           *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_RANDPOOL_H__
#define BOTAN_RANDPOOL_H__

#include <botan/rng.h>
#include <botan/base.h>
#include <vector>

namespace Botan {

/*************************************************
* Randpool                                       *
*************************************************/
class BOTAN_DLL Randpool : public RandomNumberGenerator
   {
   public:
      void randomize(byte[], u32bit);
      bool is_seeded() const;
      void clear() throw();
      std::string name() const;

      void reseed();
      void add_entropy_source(EntropySource*);
      void add_entropy(const byte[], u32bit);

      Randpool(const std::string&, const std::string&);
      ~Randpool();
   private:
      void update_buffer();
      void mix_pool();

      const u32bit ITERATIONS_BEFORE_RESEED, POOL_BLOCKS;
      BlockCipher* cipher;
      MessageAuthenticationCode* mac;

      std::vector<EntropySource*> entropy_sources;
      SecureVector<byte> pool, buffer, counter;
      u32bit entropy;
   };

}

#endif
