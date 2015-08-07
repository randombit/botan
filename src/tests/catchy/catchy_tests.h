// (C) 2015 Simon Warta (Kullo GmbH)
// Botan is released under the Simplified BSD License (see license.txt)

#ifndef BOTAN_CATCHY_TESTS_H__
#define BOTAN_CATCHY_TESTS_H__

#include "catch.hpp"
#include <botan/build.h>


// BEGIN CATCH STD::VECTOR IMPLEMENTATION
// This is basically https://github.com/philsquared/Catch/pull/466
#include <vector>

#include <type_traits>

namespace Catch {

namespace Matchers {
    namespace Impl {

    namespace StdVector {
        template<typename T, typename Alloc>
        struct Equals : MatcherImpl<Equals<T, Alloc>, std::vector<T, Alloc> > {
            Equals( std::vector<T, Alloc> const& vec ) : m_vector( vec ){}
            Equals( Equals const& other ) : m_vector( other.m_vector ){}

            virtual ~Equals() {};

            virtual bool match( std::vector<T, Alloc> const& expr ) const {
                return m_vector == expr;
            }
            virtual std::string toString() const {
                return "equals: std::vector of length " + Catch::toString(m_vector.size());
            }

            std::vector<T, Alloc> m_vector;
        };
    } // namespace StdVector

    namespace Boolean {
        struct Equals : MatcherImpl<Equals, bool> {
            Equals( const bool expected ) : m_expected( expected ){}
            Equals( Equals const& other ) : m_expected( other.m_expected ){}

            virtual ~Equals() override {};

            virtual bool match( bool const& expr ) const {
                return m_expected == expr;
            }
            virtual std::string toString() const {
                return " == " + Catch::toString(m_expected);
            }

            bool m_expected;
        };
    } // Boolean

    namespace Integer {
        template<typename T>
        struct Equals : MatcherImpl<Equals<T>, T> {
            Equals( const T expected ) : m_expected( expected ){}
            Equals( Equals const& other ) : m_expected( other.m_expected ){}

            virtual ~Equals() override {};

            virtual bool match( T const& expr ) const {
                return m_expected == expr;
            }
            virtual std::string toString() const {
                return "== " + Catch::toString(m_expected);
            }

            T m_expected;
        };
    } // namespace Integer

    } // namespace Impl

    // The following functions create the actual matcher objects.
    // This allows the types to be inferred
    template <typename T, typename Alloc>
    inline Impl::StdVector::Equals<T, Alloc>      Equals( std::vector<T, Alloc> const& vec ) {
        return Impl::StdVector::Equals<T, Alloc>( vec );
    }

    template <typename T,
              typename = typename std::enable_if<std::numeric_limits<T>::is_integer, T>::type>
    inline Impl::Integer::Equals<T>    Equals( T expected ) {
        return Impl::Integer::Equals<T>( expected );
    }

    inline Impl::Boolean::Equals          Equals( bool expected ) {
        return Impl::Boolean::Equals( expected );
    }

} // namespace Matchers
} // namespace Catch
// END CATCH STD::VECTOR IMPLEMENTATION

#endif // BOTAN_CATCHY_TESTS_H__
