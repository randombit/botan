/*************************************************
* PK Key Types Header File                       *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_PK_KEYS_H__
#define BOTAN_PK_KEYS_H__

#include <botan/base.h>
#include <botan/asn1_oid.h>

namespace Botan {

/*************************************************
* Generic PK Key                                 *
*************************************************/
class PK_Key
   {
   public:
      virtual std::string algo_name() const = 0;

      virtual OID get_oid() const;
      virtual u32bit max_input_bits() const { return 0; }
      virtual bool check_key(bool) const { return true; }
      virtual u32bit message_parts() const { return 1; }
      virtual u32bit message_part_size() const { return 0; }
      virtual ~PK_Key() {}
   protected:
      void check_loaded_public() const;
      void check_loaded_private() const;
      void check_generated_private() const;
   };

/*************************************************
* PK Encrypting Key                              *
*************************************************/
class PK_Encrypting_Key : public virtual PK_Key
   {
   public:
      virtual SecureVector<byte> encrypt(const byte[], u32bit) const = 0;
      virtual ~PK_Encrypting_Key() {}
   };

/*************************************************
* PK Decrypting Key                              *
*************************************************/
class PK_Decrypting_Key : public virtual PK_Key
   {
   public:
      virtual SecureVector<byte> decrypt(const byte[], u32bit) const = 0;
      virtual ~PK_Decrypting_Key() {}
   };

/*************************************************
* PK Signing Key                                 *
*************************************************/
class PK_Signing_Key : public virtual PK_Key
   {
   public:
      virtual SecureVector<byte> sign(const byte[], u32bit) const = 0;
      virtual ~PK_Signing_Key() {}
   };

/*************************************************
* PK Verifying Key, Message Recovery Version     *
*************************************************/
class PK_Verifying_with_MR_Key : public virtual PK_Key
   {
   public:
      virtual SecureVector<byte> verify(const byte[], u32bit) const = 0;
      virtual ~PK_Verifying_with_MR_Key() {}
   };

/*************************************************
* PK Verifying Key, No Message Recovery Version  *
*************************************************/
class PK_Verifying_wo_MR_Key : public virtual PK_Key
   {
   public:
      virtual bool verify(const byte[], u32bit,
                          const byte[], u32bit) const = 0;
      virtual ~PK_Verifying_wo_MR_Key() {}
   };

/*************************************************
* PK Secret Value Derivation Key                 *
*************************************************/
class PK_Key_Agreement_Key : public virtual PK_Key
   {
   public:
      virtual SecureVector<byte> derive_key(const byte[], u32bit) const = 0;
      virtual MemoryVector<byte> public_value() const = 0;
      virtual ~PK_Key_Agreement_Key() {}
   };

typedef PK_Key_Agreement_Key PK_KA_Key;

}

#endif
