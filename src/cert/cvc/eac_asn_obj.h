/*************************************************
* EAC ASN.1 Objects Header File                  *
* (C) 1999-2007 Jack Lloyd                       *
*     2007 FlexSecure GmbH                       *
*************************************************/

#ifndef BOTAN_EAC_ASN1_OBJ_H__
#define BOTAN_EAC_ASN1_OBJ_H__

#include <botan/asn1_obj.h>
#include <vector>
#include <map>

namespace Botan {

/*************************************************
* CVC EAC Time                                   *
*************************************************/
class BOTAN_DLL EAC_Time : public ASN1_Object
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

// function definitions in asn_eac_tm.cpp
class BOTAN_DLL ASN1_Ced : public EAC_Time
   {
   public:
      ASN1_Ced(std::string const& str="");
      ASN1_Ced(u64bit);
      ASN1_Ced(EAC_Time const& other);
      //ASN1_Ced(ASN1_Cex const& cex);
   };

// function definitions in asn_eac_tm.cpp
class BOTAN_DLL ASN1_Cex : public EAC_Time
   {
   public:
      ASN1_Cex(std::string const& str="");
      ASN1_Cex(u64bit);
      ASN1_Cex(EAC_Time const& other);
      //ASN1_Cex(ASN1_Ced const& ced);
   };

/*************************************************
* String for car/chr of cv certificates          *
*************************************************/
class BOTAN_DLL ASN1_EAC_String: public ASN1_Object
   {
   public:
      void encode_into(class DER_Encoder&) const;
      void decode_from(class BER_Decoder&);

      std::string value() const;
      std::string iso_8859() const;

      ASN1_Tag tagging() const;
      ASN1_EAC_String(const std::string& str, ASN1_Tag the_tag);

      virtual ~ASN1_EAC_String() {}
   protected:
      bool sanity_check() const;
   private:
      std::string iso_8859_str;
      ASN1_Tag tag;
   };

// String tagged with 2
// function definitions in asn1_eac_str.cpp
class BOTAN_DLL ASN1_Car : public ASN1_EAC_String
   {
   public:
      ASN1_Car(std::string const& str = "");
   };

// String tagged with 32
// function definitions in asn1_eac_str.cpp
class BOTAN_DLL ASN1_Chr : public ASN1_EAC_String
   {
   public:
      ASN1_Chr(std::string const& str = "");
   };

/*************************************************
* Comparison Operations                          *
*************************************************/
bool operator==(const EAC_Time&, const EAC_Time&);
bool operator!=(const EAC_Time&, const EAC_Time&);
bool operator<=(const EAC_Time&, const EAC_Time&);
bool operator>=(const EAC_Time&, const EAC_Time&);
bool operator>(const EAC_Time&, const EAC_Time&);
bool operator<(const EAC_Time&, const EAC_Time&);

bool operator==(const ASN1_EAC_String&, const ASN1_EAC_String&);
inline bool operator!=(const ASN1_EAC_String& lhs, const ASN1_EAC_String& rhs)
   {
   return !(lhs == rhs);
   }

}

#endif
