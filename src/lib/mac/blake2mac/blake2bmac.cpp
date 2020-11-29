/*
* BLAKE2b MAC
* (C) 1999-2007,2014 Jack Lloyd
* (C) 2020           Tom Crowley
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/blake2bmac.h>

namespace Botan {

/*
* Clear memory of sensitive data
*/
void BLAKE2bMAC::clear()
   {
   m_blake.clear();
   }

/*
* Return a clone of this object
*/
MessageAuthenticationCode* BLAKE2bMAC::clone() const
   {
   return new BLAKE2bMAC(m_blake.output_length() * 8);
   }

/*
* BLAKE2bMAC Constructor
*/
BLAKE2bMAC::BLAKE2bMAC(size_t output_bits) :
       m_blake(output_bits)
   {
   }

}
