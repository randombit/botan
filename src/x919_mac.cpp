/*************************************************
* ANSI X9.19 MAC Source File                     *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#include <botan/x919_mac.h>
#include <botan/lookup.h>
#include <botan/bit_ops.h>
#include <algorithm>

namespace Botan {

/*************************************************
* Update an ANSI X9.19 MAC Calculation           *
*************************************************/
void ANSI_X919_MAC::add_data(const byte input[], u32bit length)
   {
   u32bit xored = std::min(8 - position, length);
   xor_buf(state + position, input, xored);
   position += xored;

   if(position < 8) return;

   e->encrypt(state);
   input += xored;
   length -= xored;
   while(length >= 8)
      {
      xor_buf(state, input, 8);
      e->encrypt(state);
      input += 8;
      length -= 8;
      }

   xor_buf(state, input, length);
   position = length;
   }

/*************************************************
* Finalize an ANSI X9.19 MAC Calculation         *
*************************************************/
void ANSI_X919_MAC::final_result(byte mac[])
   {
   if(position)
      e->encrypt(state);
   d->decrypt(state, mac);
   e->encrypt(mac);
   state.clear();
   position = 0;
   }

/*************************************************
* ANSI X9.19 MAC Key Schedule                    *
*************************************************/
void ANSI_X919_MAC::key(const byte key[], u32bit length)
   {
   e->set_key(key, 8);
   if(length == 8) d->set_key(key, 8);
   else            d->set_key(key + 8, 8);
   }

/*************************************************
* Clear memory of sensitive data                 *
*************************************************/
void ANSI_X919_MAC::clear() throw()
   {
   e->clear();
   d->clear();
   state.clear();
   position = 0;
   }

/*************************************************
* ANSI X9.19 MAC Constructor                     *
*************************************************/
ANSI_X919_MAC::ANSI_X919_MAC() : MessageAuthenticationCode(8, 8, 16, 8)
   {
   e = get_block_cipher("DES");
   d = get_block_cipher("DES");
   position = 0;
   }

/*************************************************
* ANSI X9.19 MAC Destructor                      *
*************************************************/
ANSI_X919_MAC::~ANSI_X919_MAC()
   {
   delete e;
   delete d;
   }

}
