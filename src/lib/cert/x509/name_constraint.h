/*
* X.509 Name Constraint
* (C) 2015 Kai Michaelis
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_NAME_CONSTRAINT_H__
#define BOTAN_NAME_CONSTRAINT_H__

#include <botan/asn1_obj.h>
#include <ostream>

namespace Botan {

   class X509_Certificate;

   /**
    * @brief X.509 GeneralName Type
    *
    * Handles parsing GeneralName types in their BER and canonical string
    * encoding. Allows matching GeneralNames against each other using
    * the rules laid out in the X.509 4.2.1.10 (Name Contraints).
    */
   class BOTAN_DLL GeneralName : public ASN1_Object
      {
      public:
         enum MatchResult : int
            {
            All,
            Some,
            None,
            NotFound,
            UnknownType,
            };

         GeneralName() : m_type(), m_name() {}

         /// Constructs a new GeneralName for its string format.
         GeneralName(const std::string& s);

         void encode_into(class DER_Encoder&) const override;
         void decode_from(class BER_Decoder&) override;

         /// Type of the name. Can be DN, DNS, IP, RFC822, URI.
         const std::string& type() const { return m_type; }

         /// The name as string. Format depends on type.
         const std::string& name() const { return m_name; }

         /// Checks whenever a given certificate (partially) matches this name.
         MatchResult matches(const X509_Certificate&) const;

      private:
         std::string m_type;
         std::string m_name;

         bool matches_dns(const std::string&) const;
         bool matches_dn(const std::string&) const;
         bool matches_ip(const std::string&) const;
      };

   std::ostream& operator<<(std::ostream& os, const GeneralName& gn);

   /**
    * @brief A single Name Constraints
    *
    * THe Name Constraint extension adds a minimum and maximum path
    * length to a GeneralName to form a constraint. The length limits
    * are currently unused.
    */
   class BOTAN_DLL GeneralSubtree : public ASN1_Object
      {
      public:
         GeneralSubtree() : m_base(), m_minimum(0), m_maximum(std::numeric_limits<std::size_t>::max())
         {}

         /// Constructs a new Name Constraint
         GeneralSubtree(GeneralName b,size_t min,size_t max)
         : m_base(b), m_minimum(min), m_maximum(max)
         {}

         /// Constructs a new GeneralSubtree for its string format.
         GeneralSubtree(const std::string&);

         void encode_into(class DER_Encoder&) const override;
         void decode_from(class BER_Decoder&) override;

         /// Name
         GeneralName base() const { return m_base; }

         // Minimum path length
         size_t minimum() const { return m_minimum; }

         // Maximum path length
         size_t maximum() const { return m_maximum; }

      private:
         GeneralName m_base;
         size_t m_minimum;
         size_t m_maximum;
      };

   std::ostream& operator<<(std::ostream& os, const GeneralSubtree& gs);

   /**
    * @brief Name Constraints
    *
    * Wraps the Name Constraints associated with a certificate.
    */
   class BOTAN_DLL NameConstraints
      {
      public:
         NameConstraints() : m_permitted_subtrees(), m_excluded_subtrees() {}

         NameConstraints(std::vector<GeneralSubtree>&& ps, std::vector<GeneralSubtree>&& es)
         : m_permitted_subtrees(ps), m_excluded_subtrees(es)
         {}

         /// Permitted names
         const std::vector<GeneralSubtree>& permitted() const { return m_permitted_subtrees; }

         /// Excluded names
         const std::vector<GeneralSubtree>& excluded() const { return m_excluded_subtrees; }

      private:
        std::vector<GeneralSubtree> m_permitted_subtrees;
        std::vector<GeneralSubtree> m_excluded_subtrees;
      };
}

#endif
