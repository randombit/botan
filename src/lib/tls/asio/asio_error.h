/*
* TLS Stream Errors
* (C) 2018-2020 Jack Lloyd
*     2018-2020 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_ERROR_H_
#define BOTAN_ASIO_ERROR_H_

#include <botan/asio_compat.h>
#if defined(BOTAN_FOUND_COMPATIBLE_BOOST_ASIO_VERSION)

   #include <boost/system/system_error.hpp>

   #include <botan/exceptn.h>
   #include <botan/tls_alert.h>
   #include <botan/tls_exceptn.h>

/*
 * This file defines Botan-specific subclasses of boost::system::error_category.
 * In addition to the class definition, each category class is accompanied by function `make_error_code` used to create
 * a `boost::system::error_code` of the category from some other kind of error in Botan (for example, a TLS alert).
 * Since error_category instances should be singletons, there's also a method to get/create the instance for each class.
 */

namespace Botan {

/**
* Generic base class wrapping boost::system::error_category and
* adding a (bizarrely missing) virtual destructor.
*/
class BoostErrorCategory : public boost::system::error_category {
   public:
      virtual ~BoostErrorCategory() = default;

      BoostErrorCategory() = default;
      BoostErrorCategory(const BoostErrorCategory& other) = delete;
      BoostErrorCategory(BoostErrorCategory&& other) = delete;
      BoostErrorCategory& operator=(const BoostErrorCategory& other) = delete;
      BoostErrorCategory& operator=(BoostErrorCategory&& other) = delete;
};

namespace TLS {

enum StreamError : uint8_t { StreamTruncated = 1 };

//! @brief An error category for errors from the TLS::Stream
class StreamCategory final : public BoostErrorCategory {
   public:
      const char* name() const noexcept override { return "Botan TLS Stream"; }

      std::string message(int value) const override {
         if(value == StreamTruncated) {
            return "stream truncated";
         } else {
            return "generic error";
         }
      }
};

inline const StreamCategory& botan_stream_category() {
   static const StreamCategory category;
   return category;
}

inline boost::system::error_code make_error_code(Botan::TLS::StreamError e) {
   return boost::system::error_code(static_cast<int>(e), Botan::TLS::botan_stream_category());
}

//! @brief An error category for TLS alerts
class BotanAlertCategory final : public BoostErrorCategory {
   public:
      const char* name() const noexcept override { return "Botan TLS Alert"; }

      std::string message(int ev) const override {
         const Botan::TLS::Alert alert(static_cast<Botan::TLS::Alert::Type>(ev));
         return alert.type_string();
      }
};

inline const BotanAlertCategory& botan_alert_category() noexcept {
   static const BotanAlertCategory category;
   return category;
}

inline boost::system::error_code make_error_code(Botan::TLS::Alert::Type c) {
   return boost::system::error_code(static_cast<int>(c), Botan::TLS::botan_alert_category());
}

}  // namespace TLS

//! @brief An error category for errors from Botan (other than TLS alerts)
class BotanErrorCategory : public BoostErrorCategory {
   public:
      const char* name() const noexcept override { return "Botan"; }

      std::string message(int ev) const override { return Botan::to_string(static_cast<Botan::ErrorType>(ev)); }
};

inline const BotanErrorCategory& botan_category() noexcept {
   static const BotanErrorCategory category;
   return category;
}

inline boost::system::error_code make_error_code(Botan::ErrorType e) {
   return boost::system::error_code(static_cast<int>(e), Botan::botan_category());
}

}  // namespace Botan

/*
 * Add a template specialization of `is_error_code_enum` for each kind of error to allow automatic conversion to an
 * error code.
 */
namespace boost::system {

template <>
struct is_error_code_enum<Botan::TLS::Alert::Type> {
      static const bool value = true;
};

template <>
struct is_error_code_enum<Botan::TLS::StreamError> {
      static const bool value = true;
};

template <>
struct is_error_code_enum<Botan::ErrorType> {
      static const bool value = true;
};

}  // namespace boost::system

#endif
#endif  // BOTAN_ASIO_ERROR_H_
