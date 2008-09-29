/*************************************************
* PK Utility Classes Header File                 *
* (C) 1999-2007 Jack Lloyd                       *
*************************************************/

#ifndef BOTAN_PUBKEY_UTIL_H__
#define BOTAN_PUBKEY_UTIL_H__

#include <botan/base.h>
#include <botan/rng.h>

namespace Botan {

/*************************************************
* Encoding Method for Encryption                 *
*************************************************/
class BOTAN_DLL EME
   {
   public:
      virtual u32bit maximum_input_size(u32bit) const = 0;

      SecureVector<byte> encode(const byte[], u32bit, u32bit,
                                RandomNumberGenerator&) const;
      SecureVector<byte> encode(const MemoryRegion<byte>&, u32bit,
                                RandomNumberGenerator&) const;

      SecureVector<byte> decode(const byte[], u32bit, u32bit) const;
      SecureVector<byte> decode(const MemoryRegion<byte>&, u32bit) const;

      virtual ~EME() {}
   private:
      virtual SecureVector<byte> pad(const byte[], u32bit, u32bit,
                                     RandomNumberGenerator&) const = 0;

      virtual SecureVector<byte> unpad(const byte[], u32bit, u32bit) const = 0;
   };

/*************************************************
* Encoding Method for Signatures, Appendix       *
*************************************************/
class BOTAN_DLL EMSA
   {
   public:
      virtual void update(const byte[], u32bit) = 0;
      virtual SecureVector<byte> raw_data() = 0;

      virtual SecureVector<byte> encoding_of(const MemoryRegion<byte>&,
                                             u32bit,
                                             RandomNumberGenerator& rng) = 0;

      virtual bool verify(const MemoryRegion<byte>&, const MemoryRegion<byte>&,
                          u32bit) throw() = 0;
      virtual ~EMSA() {}
   };

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
