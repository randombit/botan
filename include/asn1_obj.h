/*************************************************
* Common ASN.1 Objects Header File               *
* (C) 1999-2007 The Botan Project                *
*************************************************/

#ifndef BOTAN_ASN1_OBJ_H__
#define BOTAN_ASN1_OBJ_H__

#include <botan/asn1_int.h>
#include <botan/asn1_oid.h>
#include <botan/alg_id.h>
#include <vector>
#include <map>

namespace Botan
  {

  /*************************************************
  * Attribute                                      *
  *************************************************/
  class Attribute : public ASN1_Object
    {
    public:
      void encode_into(class DER_Encoder&) const;
      void decode_from(class BER_Decoder&);

      OID oid;
      MemoryVector<byte> parameters;

      Attribute()
      {}
      Attribute(const OID&, const MemoryRegion<byte>&);
      Attribute(const std::string&, const MemoryRegion<byte>&);
    };

  /*************************************************
  * X.509 Time                                     *
  *************************************************/
  class X509_Time : public ASN1_Object
    {
    public:
      void encode_into(class DER_Encoder&) const;
      void decode_from(class BER_Decoder&);

      std::string as_string() const;
      std::string readable_string() const;
      bool time_is_set() const;

      s32bit cmp(const X509_Time&) const;

      void set_to(const std::string&);
      void set_to(const std::string&, ASN1_Tag);

      X509_Time(u64bit);
      X509_Time(const std::string& = "");
      X509_Time(const std::string&, ASN1_Tag);
    private:
      bool passes_sanity_check() const;
      u32bit year, month, day, hour, minute, second;
      ASN1_Tag tag;
    };

  /*************************************************
  * CVC EAC Time                                     *
  *************************************************/
  class EAC_Time : public ASN1_Object
    {
    public:
      void encode_into(class DER_Encoder&) const;
      void decode_from(class BER_Decoder&);

      std::string as_string() const;
      std::string readable_string() const;
      bool time_is_set() const;

      s32bit cmp(const EAC_Time&) const;

      void set_to(const std::string&);
      //void set_to(const std::string&, ASN1_Tag);
      void add_years(u32bit years);
      void add_months(u32bit months);

      u32bit get_year() const;
      u32bit get_month() const;
      u32bit get_day() const;

      EAC_Time(u64bit, ASN1_Tag t = ASN1_Tag(0));
      //EAC_Time(const std::string& = "");
      EAC_Time(const std::string&, ASN1_Tag = ASN1_Tag(0));
      EAC_Time(u32bit year, u32bit month, u32bit day, ASN1_Tag = ASN1_Tag(0));
      virtual ~EAC_Time(){};
    private:
      SecureVector<byte> encoded_eac_time() const;
      bool passes_sanity_check() const;
      u32bit year, month, day;
      ASN1_Tag tag;
    };

    class ASN1_Ced : public EAC_Time
    {
        // function definitions in asn_eac_tm.cpp
        public:
            ASN1_Ced(std::string const& str="");
            ASN1_Ced(u64bit);
            ASN1_Ced(EAC_Time const& other);
            //ASN1_Ced(ASN1_Cex const& cex);
    };

    class ASN1_Cex : public EAC_Time
    {
        // function definitions in asn_eac_tm.cpp
        public:
            ASN1_Cex(std::string const& str="");
            ASN1_Cex(u64bit);
            ASN1_Cex(EAC_Time const& other);
            //ASN1_Cex(ASN1_Ced const& ced);
    };
  /*************************************************
  * Simple String                                  *
  *************************************************/
  class ASN1_String : public ASN1_Object
    {
    public:
      void encode_into(class DER_Encoder&) const;
      void decode_from(class BER_Decoder&);

      std::string value() const;
      std::string iso_8859() const; // actually returns iso 8859-1 (latin1)

      ASN1_Tag tagging() const;

      ASN1_String(const std::string& = "");
      ASN1_String(const std::string&, ASN1_Tag);
    private:
      std::string iso_8859_str;
      ASN1_Tag tag;
    };


  /*************************************************
  * String for car/chr of cv certificates          *
  *************************************************/
  class ASN1_EAC_String: public ASN1_Object
    {
    public:
      void encode_into(class DER_Encoder&) const;
      void decode_from(class BER_Decoder&);

      std::string value() const;
      std::string iso_8859() const;

      ASN1_Tag tagging() const;
      ASN1_EAC_String(const std::string& str, ASN1_Tag the_tag);
      virtual ~ASN1_EAC_String()
      {}

    protected:
        bool sanity_check() const;
    private:
      std::string iso_8859_str;
      ASN1_Tag tag;
    };

  class ASN1_Car : public ASN1_EAC_String
    {

      // function definitions in asn1_eac_str.cpp
    public:
      ASN1_Car(std::string const& str = "");
    };

  class ASN1_Chr : public ASN1_EAC_String
    {
      // function definitions in asn1_eac_str.cpp
    public:
      ASN1_Chr(std::string const& str = "");
    };


  /*************************************************
  * Distinguished Name                             *
  *************************************************/
  class X509_DN : public ASN1_Object
    {
    public:
      void encode_into(class DER_Encoder&) const;
      void decode_from(class BER_Decoder&);

      std::multimap<OID, std::string> get_attributes() const;
      std::vector<std::string> get_attribute(const std::string&) const;

      std::multimap<std::string, std::string> contents() const;

      void add_attribute(const std::string&, const std::string&);
      void add_attribute(const OID&, const std::string&);

      static std::string deref_info_field(const std::string&);

      void do_decode(const MemoryRegion<byte>&);
      MemoryVector<byte> get_bits() const;

      X509_DN();
      X509_DN(const std::multimap<OID, std::string>&);
      X509_DN(const std::multimap<std::string, std::string>&);
    private:
      std::multimap<OID, ASN1_String> dn_info;
      MemoryVector<byte> dn_bits;
    };

  /*************************************************
  * Alternative Name                               *
  *************************************************/
  class AlternativeName : public ASN1_Object
    {
    public:
      void encode_into(class DER_Encoder&) const;
      void decode_from(class BER_Decoder&);

      std::multimap<std::string, std::string> contents() const;

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

  bool operator==(const EAC_Time&, const EAC_Time&);
  bool operator!=(const EAC_Time&, const EAC_Time&);
  bool operator<=(const EAC_Time&, const EAC_Time&);
  bool operator>=(const EAC_Time&, const EAC_Time&);
  bool operator>(const EAC_Time&, const EAC_Time&);
  bool operator<(const EAC_Time&, const EAC_Time&);

  bool operator==(const X509_DN&, const X509_DN&);
  bool operator!=(const X509_DN&, const X509_DN&);
  bool operator<(const X509_DN&, const X509_DN&);

  bool operator==(const ASN1_EAC_String&, const ASN1_EAC_String&);
  inline bool operator!=(const ASN1_EAC_String& lhs, const ASN1_EAC_String& rhs)
  {
   return !(lhs == rhs);
  }
  /*************************************************
  * Helper Functions                               *
  *************************************************/
  s32bit validity_check(const X509_Time&, const X509_Time&, u64bit);

  bool is_string_type(ASN1_Tag);

}

#endif
