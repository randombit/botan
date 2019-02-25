/*
* TLS Stream Helper
* (C) 2018-2019 Jack Lloyd
*     2018-2019 Hannes Rantzsch, Tim Oesterreich, Rene Meusel
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#ifndef BOTAN_ASIO_CONVERT_EXCEPTIONS_H_
#define BOTAN_ASIO_CONVERT_EXCEPTIONS_H_

#include <botan/asio_error.h>
#include <botan/tls_exceptn.h>

namespace Botan {

namespace TLS {

inline boost::system::error_code convertException()
   {
   try
      {
      throw;
      }
   catch(const Botan::TLS::Unexpected_Message&)
      {
      return make_error_code(Botan::TLS::error::unexpected_message);
      }
   catch(const Botan::TLS::TLS_Exception& e)
      {
      return make_error_code(e.type());
      }
   catch(const Botan::Unsupported_Argument&)
      {
      return make_error_code(Botan::TLS::error::unsupported_argument);
      }
   catch(const Botan::Invalid_Key_Length&)
      {
      return make_error_code(Botan::TLS::error::invalid_key_length);
      }
   catch(const Botan::Invalid_IV_Length&)
      {
      return make_error_code(Botan::TLS::error::invalid_iv_length);
      }
   catch(const Botan::Invalid_Algorithm_Name&)
      {
      return make_error_code(Botan::TLS::error::invalid_algorithm_name);
      }
   catch(const Botan::Encoding_Error&)
      {
      return make_error_code(Botan::TLS::error::encoding_error);
      }
   catch(const Botan::Invalid_OID&)
      {
      return make_error_code(Botan::TLS::error::invalid_oid);
      }
   catch(const Botan::Decoding_Error&)
      {
      return make_error_code(Botan::TLS::error::decoding_error);
      }
   catch(const Botan::Invalid_Argument&)
      {
      return make_error_code(Botan::TLS::error::invalid_argument);
      }
   catch(const Botan::Key_Not_Set&)
      {
      return make_error_code(Botan::TLS::error::key_not_set);
      }
   catch(const Botan::PRNG_Unseeded&)
      {
      return make_error_code(Botan::TLS::error::prng_unseeded);
      }
   catch(const Botan::Policy_Violation&)
      {
      return make_error_code(Botan::TLS::error::policy_violation);
      }
   catch(const Botan::Invalid_State&)
      {
      return make_error_code(Botan::TLS::error::invalid_state);
      }
   catch(const Botan::Algorithm_Not_Found&)
      {
      return make_error_code(Botan::TLS::error::algorithm_not_found);
      }
   catch(const Botan::Provider_Not_Found&)
      {
      return make_error_code(Botan::TLS::error::provider_not_found);
      }
   catch(const Botan::Lookup_Error&)
      {
      return make_error_code(Botan::TLS::error::lookup_error);
      }
   catch(const Botan::Self_Test_Failure&)
      {
      return make_error_code(Botan::TLS::error::self_test_failure);
      }
   catch(const Botan::Internal_Error&)
      {
      return make_error_code(Botan::TLS::error::internal_error);
      }
   catch(const Botan::No_Provider_Found&)
      {
      return make_error_code(Botan::TLS::error::no_provider_found);
      }
   catch(const Botan::Integrity_Failure&)
      {
      return make_error_code(Botan::TLS::error::integrity_failure);
      }
   catch(const Botan::Stream_IO_Error&)
      {
      return make_error_code(Botan::TLS::error::stream_io_error);
      }
   catch(const Botan::Not_Implemented&)
      {
      return make_error_code(Botan::TLS::error::not_implemented);
      }
   catch(const Botan::Exception&)
      {
      return make_error_code(Botan::TLS::error::unknown);
      }
   catch(const std::exception&)
      {
      return make_error_code(Botan::TLS::error::unknown);
      }
   }

}  // namespace TLS

}  // namespace Botan

#endif
