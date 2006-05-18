/*************************************************
* Common ASN.1 Objects Header File               *
* (C) 1999-2006 The Botan Project                *
*************************************************/

#ifndef BOTAN_ASN1_OBJ_H__
#define BOTAN_ASN1_OBJ_H__

#include <botan/asn1_int.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <map>
#include <vector>

namespace Botan {

/*************************************************
* Algorithm Identifier                           *
*************************************************/
class AlgorithmIdentifier : public ASN1_Object
   {
   public:
      void encode_into(DER_Encoder&) const;

      AlgorithmIdentifier() {}
      AlgorithmIdentifier(const OID&, const MemoryRegion<byte>&);
      AlgorithmIdentifier(const std::string&, const MemoryRegion<byte>&);
   public:
      OID oid;
      SecureVector<byte> parameters;
   };

/*************************************************
* Extension                                      *
*************************************************/
class Extension : public ASN1_Object
   {
   public:
      bool critical;
      OID oid;
      SecureVector<byte> value;

      void encode_into(DER_Encoder&) const;

      Extension() { critical = false; }
      Extension(const OID&, const MemoryRegion<byte>&);
      Extension(const std::string&, const MemoryRegion<byte>&);
   };

/*************************************************
* Attribute                                      *
*************************************************/
class Attribute : public ASN1_Object
   {
   public:
      void encode_into(DER_Encoder&) const;

      OID oid;
      SecureVector<byte> parameters;

      Attribute() {}
      Attribute(const OID&, const MemoryRegion<byte>&);
      Attribute(const std::string&, const MemoryRegion<byte>&);
   };

/*************************************************
* X.509 Time                                     *
*************************************************/
class X509_Time : public ASN1_Object
   {
   public:
      void encode_into(DER_Encoder&) const;

      std::string as_string() const;
      std::string readable_string() const;
      bool time_is_set() const;

      s32bit cmp(const X509_Time&) const;

      X509_Time(u64bit);
      X509_Time(const std::string& = "");
      X509_Time(const std::string&, ASN1_Tag);
   private:
      bool passes_sanity_check() const;
      u32bit year, month, day, hour, minute, second;
      ASN1_Tag tag;
   };

/*************************************************
* Simple String                                  *
*************************************************/
class ASN1_String : public ASN1_Object
   {
   public:
      void encode_into(DER_Encoder&) const;

      std::string value() const;
      std::string iso_8859() const;

      ASN1_Tag tagging() const;

      ASN1_String(const std::string& = "");
      ASN1_String(const std::string&, ASN1_Tag);
   private:
      std::string iso_8859_str;
      ASN1_Tag tag;
   };

/*************************************************
* Distinguished Name                             *
*************************************************/
class X509_DN : public ASN1_Object
   {
   public:
      void encode_into(DER_Encoder&) const;

      std::multimap<OID, std::string> get_attributes() const;
      std::vector<std::string> get_attribute(const std::string&) const;

      void add_attribute(const std::string&, const std::string&);
      void add_attribute(const OID&, const std::string&);

      static std::string deref_info_field(const std::string&);

      void do_decode(const MemoryRegion<byte>&);
      SecureVector<byte> get_bits() const;

      X509_DN();
      X509_DN(const std::multimap<OID, std::string>&);
      X509_DN(const std::multimap<std::string, std::string>&);
   private:
      std::multimap<OID, ASN1_String> dn_info;
      SecureVector<byte> dn_bits;
   };

/*************************************************
* Alternative Name                               *
*************************************************/
class AlternativeName : public ASN1_Object
   {
   public:
      void encode_into(DER_Encoder&) const;

      void add_attribute(const std::string&, const std::string&);
      std::multimap<std::string, std::string> get_attributes() const;

      void add_othername(const OID&, const std::string&, ASN1_Tag);
      std::multimap<OID, ASN1_String> get_othernames() const;

      bool has_items() const;

      AlternativeName(const std::string& = "", const std::string& = "",
                      const std::string& = "");
   private:
      std::multimap<std::string, std::string> alt_info;
      std::multimap<OID, ASN1_String> othernames;
   };

/*************************************************
* Comparison Operations                          *
*************************************************/
bool operator==(const AlgorithmIdentifier&, const AlgorithmIdentifier&);
bool operator!=(const AlgorithmIdentifier&, const AlgorithmIdentifier&);

bool operator==(const X509_Time&, const X509_Time&);
bool operator!=(const X509_Time&, const X509_Time&);
bool operator<=(const X509_Time&, const X509_Time&);
bool operator>=(const X509_Time&, const X509_Time&);

bool operator==(const X509_DN&, const X509_DN&);
bool operator!=(const X509_DN&, const X509_DN&);
bool operator<(const X509_DN&, const X509_DN&);

s32bit validity_check(const X509_Time&, const X509_Time&, u64bit);

bool is_string_type(ASN1_Tag);

/*************************************************
* DER Encoding Functions                         *
*************************************************/
namespace DER {

//void encode(DER_Encoder&, const Attribute&);
//void encode(DER_Encoder&, const ASN1_String&);
void encode(DER_Encoder&, const ASN1_String&,
            ASN1_Tag, ASN1_Tag = CONTEXT_SPECIFIC);

}

/*************************************************
* BER Decoding Functions                         *
*************************************************/
namespace BER {

void decode(BER_Decoder&, AlgorithmIdentifier&);
void decode(BER_Decoder&, Extension&);
void decode(BER_Decoder&, Attribute&);
void decode(BER_Decoder&, X509_Time&);
void decode(BER_Decoder&, ASN1_String&);
void decode(BER_Decoder&, ASN1_String&, ASN1_Tag, ASN1_Tag);
void decode(BER_Decoder&, X509_DN&);
void decode(BER_Decoder&, AlternativeName&);
void decode(BER_Decoder&, Key_Constraints&);

}

}

#endif
