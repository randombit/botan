/*
* EAC ASN.1 Objects
* (C) 2007-2008 FlexSecure GmbH
*     2008-2010 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_EAC_ASN1_OBJ_H__
#define BOTAN_EAC_ASN1_OBJ_H__

#include <botan/asn1_obj.h>
#include <chrono>

namespace Botan {

/**
* This class represents CVC EAC Time objects.
* It only models year, month and day. Only limited sanity checks of
* the inputted date value are performed.
*/
class BOTAN_DLL EAC_Time : public ASN1_Object
   {
   public:
      void encode_into(class DER_Encoder&) const;
      void decode_from(class BER_Decoder&);

      /**
      * Get a this objects value as a string.
      * @return date string
      */
      std::string as_string() const;

      /**
      * Get a this objects value as a readable formatted string.
      * @return date string
      */
      std::string readable_string() const;

      /**
      * Find out whether this object's values have been set.
      * @return true if this object's internal values are set
      */
      bool time_is_set() const;

      /**
      * Compare this to another EAC_Time object.
      * @return -1 if this object's date is earlier than
      * other, +1 in the opposite case, and 0 if both dates are
      * equal.
      */
      s32bit cmp(const EAC_Time& other) const;

      /**
      * Set this' value by a string value.
      * @param str a string in the format "yyyy mm dd",
      * e.g. "2007 08 01"
      */
      void set_to(const std::string& str);

      /**
      * Add the specified number of years to this.
      * @param years the number of years to add
      */
      void add_years(u32bit years);

      /**
      * Add the specified number of months to this.
      * @param months the number of months to add
      */
      void add_months(u32bit months);

      /**
      * Get the year value of this objects.
      * @return year value
      */
      u32bit get_year() const { return m_year; }

      /**
      * Get the month value of this objects.
      * @return month value
      */
      u32bit get_month() const { return m_month; }

      /**
      * Get the day value of this objects.
      * @return day value
      */
      u32bit get_day() const { return m_day; }

      EAC_Time(const std::chrono::system_clock::time_point& time,
               ASN1_Tag tag = ASN1_Tag(0));

      EAC_Time(const std::string& yyyy_mm_dd,
               ASN1_Tag tag = ASN1_Tag(0));

      EAC_Time(u32bit year, u32bit month, u32bit day,
               ASN1_Tag tag = ASN1_Tag(0));

      virtual ~EAC_Time() {}
   private:
      std::vector<byte> encoded_eac_time() const;
      bool passes_sanity_check() const;
      u32bit m_year, m_month, m_day;
      ASN1_Tag m_tag;
   };

/**
* This class represents CVC CEDs. Only limited sanity checks of
* the inputted date value are performed.
*/
class BOTAN_DLL ASN1_Ced : public EAC_Time
   {
   public:
      /**
      * Construct a CED from a string value.
      * @param str a string in the format "yyyy mm dd",
      * e.g. "2007 08 01"
      */
      ASN1_Ced(const std::string& str = "") :
         EAC_Time(str, ASN1_Tag(37)) {}

      /**
      * Construct a CED from a time point
      */
      ASN1_Ced(const std::chrono::system_clock::time_point& time) :
         EAC_Time(time, ASN1_Tag(37)) {}

      /**
      * Copy constructor (for general EAC_Time objects).
      * @param other the object to copy from
      */
      ASN1_Ced(const EAC_Time& other) :
         EAC_Time(other.get_year(), other.get_month(), other.get_day(),
                  ASN1_Tag(37))
         {}
   };

/**
* This class represents CVC CEXs. Only limited sanity checks of
* the inputted date value are performed.
*/
class BOTAN_DLL ASN1_Cex : public EAC_Time
   {
   public:
      /**
      * Construct a CEX from a string value.
      * @param str a string in the format "yyyy mm dd",
      * e.g. "2007 08 01"
      */
      ASN1_Cex(const std::string& str = "") :
         EAC_Time(str, ASN1_Tag(36)) {}

      ASN1_Cex(const std::chrono::system_clock::time_point& time) :
         EAC_Time(time, ASN1_Tag(36)) {}

      ASN1_Cex(const EAC_Time& other) :
         EAC_Time(other.get_year(), other.get_month(), other.get_day(),
                  ASN1_Tag(36))
         {}
   };

/**
* Base class for car/chr of cv certificates.
*/
class BOTAN_DLL ASN1_EAC_String: public ASN1_Object
   {
   public:
      void encode_into(class DER_Encoder&) const;
      void decode_from(class BER_Decoder&);

      /**
      * Get this objects string value.
      * @return string value
      */
      std::string value() const;

      /**
      * Get this objects string value.
      * @return string value in iso8859 encoding
      */
      std::string iso_8859() const;

      ASN1_Tag tagging() const;
      ASN1_EAC_String(const std::string& str, ASN1_Tag the_tag);

      virtual ~ASN1_EAC_String() {}
   protected:
      bool sanity_check() const;
   private:
      std::string m_iso_8859_str;
      ASN1_Tag m_tag;
   };

/**
* This class represents CARs of CVCs. (String tagged with 2)
*/
class BOTAN_DLL ASN1_Car : public ASN1_EAC_String
   {
   public:
      /**
      * Create a CAR with the specified content.
      * @param str the CAR value
      */
      ASN1_Car(std::string const& str = "");
   };

/**
* This class represents CHRs of CVCs (tag 32)
*/
class BOTAN_DLL ASN1_Chr : public ASN1_EAC_String
   {
   public:
      /**
      * Create a CHR with the specified content.
      * @param str the CHR value
      */
      ASN1_Chr(std::string const& str = "");
   };

/*
* Comparison Operations
*/
bool BOTAN_DLL operator==(const EAC_Time&, const EAC_Time&);
bool BOTAN_DLL operator!=(const EAC_Time&, const EAC_Time&);
bool BOTAN_DLL operator<=(const EAC_Time&, const EAC_Time&);
bool BOTAN_DLL operator>=(const EAC_Time&, const EAC_Time&);
bool BOTAN_DLL operator>(const EAC_Time&, const EAC_Time&);
bool BOTAN_DLL operator<(const EAC_Time&, const EAC_Time&);

bool BOTAN_DLL operator==(const ASN1_EAC_String&, const ASN1_EAC_String&);
inline bool operator!=(const ASN1_EAC_String& lhs, const ASN1_EAC_String& rhs)
   {
   return !(lhs == rhs);
   }

}

#endif
