#ifndef BOTAN_ASIO_ERROR_H_
#define BOTAN_ASIO_ERROR_H_

#include <boost/system/system_error.hpp>

#include <botan/tls_alert.h>

namespace Botan {

using error_code = boost::system::error_code;
using error_category = boost::system::error_category;

// TLS Alerts
struct BotanAlertCategory : error_category
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

inline error_code make_error_code(Botan::TLS::Alert::Type c)
   {
   return error_code(static_cast<int>(c), botan_alert_category());
   }

enum class error
   {
   unexpected_message = 1,
   invalid_argument,
   unsupported_argument,
   invalid_state,
   key_not_set,
   lookup_error,
   internal_error,
   invalid_key_length,
   invalid_iv_length,
   prng_unseeded,
   policy_violation,
   algorithm_not_found,
   no_provider_found,
   provider_not_found,
   invalid_algorithm_name,
   encoding_error,
   decoding_error,
   integrity_failure,
   invalid_oid,
   stream_io_error,
   self_test_failure,
   not_implemented,
   unknown
   };

struct BotanErrorCategory : error_category
   {
   const char* name() const noexcept override
      {
      return "asio.botan.tls";
      }

   std::string message(int ev) const override
      {
      switch(static_cast<error>(ev))
         {
         case error::unexpected_message:
            return "unexpected_message";
         case error::invalid_argument:
            return "invalid_argument";
         case error::unsupported_argument:
            return "unsupported_argument";
         case error::invalid_state:
            return "invalid_state";
         case error::key_not_set:
            return "key_not_set";
         case error::lookup_error:
            return "lookup_error";
         case error::internal_error:
            return "internal_error";
         case error::invalid_key_length:
            return "invalid_key_length";
         case error::invalid_iv_length:
            return "invalid_iv_length";
         case error::prng_unseeded:
            return "prng_unseeded";
         case error::policy_violation:
            return "policy_violation";
         case error::algorithm_not_found:
            return "algorithm_not_found";
         case error::no_provider_found:
            return "no_provider_found";
         case error::provider_not_found:
            return "provider_not_found";
         case error::invalid_algorithm_name:
            return "invalid_algorithm_name";
         case error::encoding_error:
            return "encoding_error";
         case error::decoding_error:
            return "decoding_error";
         case error::integrity_failure:
            return "integrity_failure";
         case error::invalid_oid:
            return "invalid_oid";
         case error::stream_io_error:
            return "stream_io_error";
         case error::self_test_failure:
            return "self_test_failure";
         case error::not_implemented:
            return "not_implemented";

         default:
            return "(unrecognized botan tls error)";
         }
      }
   };

inline const BotanErrorCategory& botan_category() noexcept
   {
   static BotanErrorCategory category;
   return category;
   }

inline error_code make_error_code(error c)
   {
   return error_code(static_cast<int>(c), botan_category());
   }
}

namespace boost {
namespace system {

template<> struct is_error_code_enum<Botan::TLS::Alert::Type>
   {
   static const bool value = true;
   };

template<> struct is_error_code_enum<Botan::error>
   {
   static const bool value = true;
   };
}
}

#endif
