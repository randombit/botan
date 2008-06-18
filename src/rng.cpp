/*************************************************
* Random Number Generator Base Source File       *
* (C) 1999-2008 Jack Lloyd                       *
*************************************************/

#include <botan/rng.h>
#include <botan/secmem.h>
#include <botan/util.h>

namespace Botan {

/*************************************************
* Default fast poll for EntropySources           *
*************************************************/
u32bit EntropySource::fast_poll(byte buf[], u32bit len)
   {
   return this->slow_poll(buf, len);
   }

/*************************************************
* Get a single random byte                       *
*************************************************/
byte RandomNumberGenerator::next_byte()
   {
   byte out;
   this->randomize(&out, 1);
   return out;
   }

/*************************************************
* Add entropy to internal state                  *
*************************************************/
void RandomNumberGenerator::add_entropy(const byte random[], u32bit length)
   {
   this->add_randomness(random, length);
   }

/*************************************************
* Add entropy to internal state                  *
*************************************************/
u32bit RandomNumberGenerator::add_entropy(EntropySource& source,
                                          bool slow_poll)
   {
   SecureVector<byte> buffer(1024);
   u32bit bytes_gathered = 0;

   if(slow_poll)
      bytes_gathered = source.slow_poll(buffer, buffer.size());
   else
      bytes_gathered = source.fast_poll(buffer, buffer.size());

   this->add_entropy(buffer, bytes_gathered);

   return entropy_estimate(buffer, bytes_gathered);
   }

}
