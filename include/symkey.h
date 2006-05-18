/*************************************************
* OctetString Header File                        *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_SYMKEY_H__
#define BOTAN_SYMKEY_H__

#include <botan/secmem.h>
#include <botan/enums.h>
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
* Symmetric Key                                  *
*************************************************/
class SymmetricKey : public OctetString
   {
   public:
      SymmetricKey(u32bit len) { change(len); }
      SymmetricKey(const std::string& str = "") : OctetString(str) {}
      SymmetricKey(const byte in[], u32bit l) : OctetString(in, l) {}
      SymmetricKey(const MemoryRegion<byte>& in) : OctetString(in) {}
      SymmetricKey(const OctetString& os) : OctetString(os) {}
   };

/*************************************************
* Initialization Vector                          *
*************************************************/
class InitializationVector : public OctetString
   {
   public:
      InitializationVector(u32bit len) { change(len); }
      InitializationVector(const std::string& str = "") : OctetString(str) {}
      InitializationVector(const byte in[], u32bit l) : OctetString(in, l) {}
      InitializationVector(const MemoryRegion<byte>& in) : OctetString(in) {}
      InitializationVector(const OctetString& os) : OctetString(os) {}
   };

}

#endif
