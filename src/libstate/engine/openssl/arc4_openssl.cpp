/*************************************************
* OpenSSL ARC4 Source File                       *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#include <botan/arc4_openssl.h>
#include <botan/parsing.h>
#include <openssl/rc4.h>

namespace Botan {

/*************************************************
* Return the name of this type                   *
*************************************************/
std::string ARC4_OpenSSL::name() const
   {
   if(SKIP == 0)   return "ARC4";
   if(SKIP == 256) return "MARK-4";
   else            return "RC4_skip(" + to_string(SKIP) + ")";
   }

/*************************************************
* ARC4 Key Schedule                              *
*************************************************/
void ARC4_OpenSSL::key_schedule(const byte key[], u32bit length)
   {
   RC4_set_key(&state, length, key);
   byte dummy = 0;
   for(u32bit j = 0; j != SKIP; j++)
      RC4(&state, 1, &dummy, &dummy);
   }

/*************************************************
* ARC4 Encryption                                *
*************************************************/
void ARC4_OpenSSL::cipher(const byte in[], byte out[], u32bit length)
   {
   RC4(&state, length, in, out);
   }

}
