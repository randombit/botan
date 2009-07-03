/*
* KDF/MGF
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_KDF_BASE_H__
#define BOTAN_KDF_BASE_H__

#include <botan/secmem.h>
#include <botan/types.h>

namespace Botan {

/*
* Key Derivation Function
*/
class BOTAN_DLL KDF
   {
   public:
      SecureVector<byte> derive_key(u32bit key_len,
                                    const MemoryRegion<byte>& secret,
                                    const std::string& salt = "") const;
      SecureVector<byte> derive_key(u32bit key_len,
                                    const MemoryRegion<byte>& secret,
                                    const MemoryRegion<byte>& salt) const;

      SecureVector<byte> derive_key(u32bit key_len,
                                    const MemoryRegion<byte>& secret,
                                    const byte salt[], u32bit salt_len) const;

      SecureVector<byte> derive_key(u32bit key_len,
                                    const byte secret[], u32bit secret_len,
                                    const std::string& salt = "") const;
      SecureVector<byte> derive_key(u32bit key_len,
                                    const byte secret[], u32bit secret_len,
                                    const byte salt[], u32bit salt_len) const;

      virtual ~KDF() {}
   private:
      virtual SecureVector<byte> derive(u32bit, const byte[], u32bit,
                                        const byte[], u32bit) const = 0;
   };

/*
* Mask Generation Function
*/
class BOTAN_DLL MGF
   {
   public:
      virtual void mask(const byte in[], u32bit in_len,
                        byte out[], u32bit out_len) const = 0;

      virtual ~MGF() {}
   };

}

#endif
