/*
* EAC ASN.1 Objects
* (C) 2007-2008 FlexSecure GmbH
*     2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_EAC_ASN1_OBJ_H__
#define BOTAN_EAC_ASN1_OBJ_H__

#include <botan/asn1_obj.h>
#include <vector>
#include <map>

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
      * @return the date string
      */
      std::string as_string() const;

      /**
      * Get a this objects value as a readable formatted string.
      * @return the date string
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
      //void set_to(const std::string&, ASN1_Tag);

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
      * @return the year value
      */
      u32bit get_year() const;

      /**
      * Get the month value of this objects.
      * @return the month value
      */
      u32bit get_month() const;

      /**
      * Get the day value of this objects.
      * @return the day value
      */
      u32bit get_day() const;

      EAC_Time(u64bit, ASN1_Tag t = ASN1_Tag(0));
      //EAC_Time(const std::string& = "");
      EAC_Time(const std::string&, ASN1_Tag = ASN1_Tag(0));
      EAC_Time(u32bit year, u32bit month, u32bit day, ASN1_Tag = ASN1_Tag(0));

      virtual ~EAC_Time() {}
   private:
      SecureVector<byte> encoded_eac_time() const;
      bool passes_sanity_check() const;
      u32bit year, month, day;
      ASN1_Tag tag;
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
      ASN1_Ced(std::string const& str = "");

      /**
      * Construct a CED from a timer value.
      * @param time the number of seconds elapsed midnight, 1st
      * January 1970 GMT (or 7pm, 31st December 1969 EST) up to the
      * desired date
      */
      ASN1_Ced(u64bit time);

      /**
      * Copy constructor (for general EAC_Time objects).
      * @param other the object to copy from
      */
      ASN1_Ced(EAC_Time const& other);
      //ASN1_Ced(ASN1_Cex const& cex);
   };


/**
* This class represents CVC CEXs. Only limited sanity checks of
* the inputted date value are performed.
*/
class BOTAN_DLL ASN1_Cex : public EAC_Time
   {
   public:
      /**
      * Construct a CED from a string value.
      * @param str a string in the format "yyyy mm dd",
      * e.g. "2007 08 01"
      */
      ASN1_Cex(std::string const& str="");

      /**
      * Construct a CED from a timer value.
      * @param time the number of seconds elapsed
      *  midnight, 1st
      * January 1970 GMT (or 7pm, 31st December 1969 EST)
      * up to the desired date
      */
      ASN1_Cex(u64bit time);

      /**
      * Copy constructor (for general EAC_Time objects).
      * @param other the object to copy from
      */
      ASN1_Cex(EAC_Time const& other);
      //ASN1_Cex(ASN1_Ced const& ced);
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
      * @return the string value
      */
      std::string value() const;

      /**
      * Get this objects string value.
      * @return the string value in iso8859 encoding
      */
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
