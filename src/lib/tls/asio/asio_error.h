/*
* TLS Stream Errors
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_ERROR_H_
#define BOTAN_ASIO_ERROR_H_

#include <botan/build.h>

#include <boost/version.hpp>
#if BOOST_VERSION >= 106600

#include <boost/system/system_error.hpp>

#include <botan/exceptn.h>
#include <botan/tls_alert.h>
#include <botan/tls_exceptn.h>

namespace Botan {
namespace TLS {

//! @brief An error category for TLS alerts
struct BotanAlertCategory : boost::system::error_category
   {
   const char* name() const noexcept override
      {
      return "asio.botan.tls.alert";
      }

   std::string message(int ev) const override
      {
      Botan::TLS::Alert alert(static_cast<Botan::TLS::Alert::Type>(ev));
      return alert.type_string();
      }
   };

inline const BotanAlertCategory& botan_alert_category() noexcept
   {
   static BotanAlertCategory category;
   return category;
   }

inline boost::system::error_code make_error_code(Botan::TLS::Alert::Type c)
   {
   return boost::system::error_code(static_cast<int>(c), Botan::TLS::botan_alert_category());
   }

}  // namespace TLS

//! @brief An error category for errors from Botan (other than TLS alerts)
struct BotanErrorCategory : boost::system::error_category
   {
   const char* name() const noexcept override
      {
      return "asio.botan.tls";
      }

   std::string message(int ev) const override
      {
      return Botan::to_string(static_cast<Botan::ErrorType>(ev));
      }
   };

inline const BotanErrorCategory& botan_category() noexcept
   {
   static BotanErrorCategory category;
   return category;
   }

inline boost::system::error_code make_error_code(Botan::ErrorType e)
   {
   return boost::system::error_code(static_cast<int>(e), Botan::botan_category());
   }

}  // namespace Botan

namespace boost {
namespace system {

template<> struct is_error_code_enum<Botan::TLS::Alert::Type>
   {
   static const bool value = true;
   };

template<> struct is_error_code_enum<Botan::ErrorType>
   {
   static const bool value = true;
   };

}  // namespace system
}  // namespace boost

#endif // BOOST_VERSION
#endif // BOTAN_ASIO_ERROR_H_
