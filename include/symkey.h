/*************************************************
* OctetString Header File                        *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_SYMKEY_H__
#define BOTAN_SYMKEY_H__

#include <botan/secmem.h>
#include <string>

namespace Botan {

/*************************************************
* Octet String                                   *
*************************************************/
class OctetString
   {
   public:
      u32bit length() const { return bits.size(); }
      SecureVector<byte> bits_of() const { return bits; }

      const byte* begin() const { return bits.begin(); }
      const byte* end() const   { return bits.end(); }

      std::string as_string() const;

      OctetString& operator^=(const OctetString&);

      void set_odd_parity();

      void change(u32bit);
      void change(const std::string&);
      void change(const byte[], u32bit);
      void change(const MemoryRegion<byte>& in) { bits = in; }

      OctetString(u32bit len) { change(len); }
      OctetString(const std::string& str = "") { change(str); }
      OctetString(const byte in[], u32bit len) { change(in, len); }
      OctetString(const MemoryRegion<byte>& in) { change(in); }
   private:
      SecureVector<byte> bits;
   };

/*************************************************
* Operations on Octet Strings                    *
*************************************************/
bool operator==(const OctetString&, const OctetString&);
bool operator!=(const OctetString&, const OctetString&);
OctetString operator+(const OctetString&, const OctetString&);
OctetString operator^(const OctetString&, const OctetString&);

/*************************************************
* Alternate Names                                *
*************************************************/
typedef OctetString SymmetricKey;
typedef OctetString InitializationVector;

}

#endif
