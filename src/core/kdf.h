/*************************************************
* KDF/MGF Header File                            *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_KDF_BASE_H__
#define BOTAN_KDF_BASE_H__

#include <botan/secmem.h>
#include <botan/types.h>

namespace Botan {

/*************************************************
* Key Derivation Function                        *
*************************************************/
class BOTAN_DLL KDF
   {
   public:
      SecureVector<byte> derive_key(u32bit, const MemoryRegion<byte>&,
                                    const std::string& = "") const;
      SecureVector<byte> derive_key(u32bit, const MemoryRegion<byte>&,
                                    const MemoryRegion<byte>&) const;
      SecureVector<byte> derive_key(u32bit, const MemoryRegion<byte>&,
                                    const byte[], u32bit) const;

      SecureVector<byte> derive_key(u32bit, const byte[], u32bit,
                                    const std::string& = "") const;
      SecureVector<byte> derive_key(u32bit, const byte[], u32bit,
                                    const byte[], u32bit) const;

      virtual ~KDF() {}
   private:
      virtual SecureVector<byte> derive(u32bit, const byte[], u32bit,
                                        const byte[], u32bit) const = 0;
   };

/*************************************************
* Mask Generation Function                       *
*************************************************/
class BOTAN_DLL MGF
   {
   public:
      virtual void mask(const byte[], u32bit, byte[], u32bit) const = 0;
      virtual ~MGF() {}
   };

}

#endif
