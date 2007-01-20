/*************************************************
* S2K Header File                                *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_S2K_H__
#define BOTAN_S2K_H__

#include <botan/base.h>

namespace Botan {

/*************************************************
* S2K Interface                                  *
*************************************************/
class S2K
   {
   public:
      virtual S2K* clone() const = 0;
      virtual std::string name() const = 0;
      virtual void clear() {}

      OctetString derive_key(u32bit, const std::string&) const;

      void set_iterations(u32bit);
      void change_salt(const byte[], u32bit);
      void change_salt(const MemoryRegion<byte>&);
      void new_random_salt(u32bit);

      u32bit iterations() const { return iter; }
      SecureVector<byte> current_salt() const { return salt; }

      S2K() { iter = 0; }
      virtual ~S2K() {}
   private:
      virtual OctetString derive(u32bit, const std::string&,
                                 const byte[], u32bit, u32bit) const = 0;
      SecureVector<byte> salt;
      u32bit iter;
   };

}

#endif
