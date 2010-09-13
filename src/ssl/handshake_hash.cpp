/*
* TLS Handshake Hash
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/handshake_hash.h>
#include <botan/md5.h>
#include <botan/sha160.h>
#include <memory>

namespace Botan {

/**
* Return a TLS Handshake Hash
*/
SecureVector<byte> HandshakeHash::final()
   {
   MD5 md5;
   SHA_160 sha1;

   md5.update(data);
   sha1.update(data);

   SecureVector<byte> output;
   output.append(md5.final());
   output.append(sha1.final());
   return output;
   }

/**
* Return a SSLv3 Handshake Hash
*/
SecureVector<byte> HandshakeHash::final_ssl3(const MemoryRegion<byte>& secret)
   {
   const byte PAD_INNER = 0x36, PAD_OUTER = 0x5C;

   MD5 md5;
   SHA_160 sha1;

   md5.update(data);
   sha1.update(data);

   md5.update(secret);
   sha1.update(secret);

   for(u32bit j = 0; j != 48; j++) md5.update(PAD_INNER);
   for(u32bit j = 0; j != 40; j++) sha1.update(PAD_INNER);

   SecureVector<byte> inner_md5 = md5.final(), inner_sha1 = sha1.final();

   md5.update(secret);
   sha1.update(secret);
   for(u32bit j = 0; j != 48; j++) md5.update(PAD_OUTER);
   for(u32bit j = 0; j != 40; j++) sha1.update(PAD_OUTER);
   md5.update(inner_md5);
   sha1.update(inner_sha1);

   SecureVector<byte> output;
   output.append(md5.final());
   output.append(sha1.final());
   return output;
   }

}
