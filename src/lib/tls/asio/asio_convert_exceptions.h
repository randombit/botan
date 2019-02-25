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
      return Botan::TLS::error::unexpected_message;
      }
   catch(const Botan::TLS::TLS_Exception& e)
      {
      return e.type();
      }
   catch(const Botan::Unsupported_Argument&)
      {
      return Botan::TLS::error::unsupported_argument;
      }
   catch(const Botan::Invalid_Key_Length&)
      {
      return Botan::TLS::error::invalid_key_length;
      }
   catch(const Botan::Invalid_IV_Length&)
      {
      return Botan::TLS::error::invalid_iv_length;
      }
   catch(const Botan::Invalid_Algorithm_Name&)
      {
      return Botan::TLS::error::invalid_algorithm_name;
      }
   catch(const Botan::Encoding_Error&)
      {
      return Botan::TLS::error::encoding_error;
      }
   catch(const Botan::Invalid_OID&)
      {
      return Botan::TLS::error::invalid_oid;
      }
   catch(const Botan::Decoding_Error&)
      {
      return Botan::TLS::error::decoding_error;
      }
   catch(const Botan::Invalid_Argument&)
      {
      return Botan::TLS::error::invalid_argument;
      }
   catch(const Botan::Key_Not_Set&)
      {
      return Botan::TLS::error::key_not_set;
      }
   catch(const Botan::PRNG_Unseeded&)
      {
      return Botan::TLS::error::prng_unseeded;
      }
   catch(const Botan::Policy_Violation&)
      {
      return Botan::TLS::error::policy_violation;
      }
   catch(const Botan::Invalid_State&)
      {
      return Botan::TLS::error::invalid_state;
      }
   catch(const Botan::Algorithm_Not_Found&)
      {
      return Botan::TLS::error::algorithm_not_found;
      }
   catch(const Botan::Provider_Not_Found&)
      {
      return Botan::TLS::error::provider_not_found;
      }
   catch(const Botan::Lookup_Error&)
      {
      return Botan::TLS::error::lookup_error;
      }
   catch(const Botan::Self_Test_Failure&)
      {
      return Botan::TLS::error::self_test_failure;
      }
   catch(const Botan::Internal_Error&)
      {
      return Botan::TLS::error::internal_error;
      }
   catch(const Botan::No_Provider_Found&)
      {
      return Botan::TLS::error::no_provider_found;
      }
   catch(const Botan::Integrity_Failure&)
      {
      return Botan::TLS::error::integrity_failure;
      }
   catch(const Botan::Stream_IO_Error&)
      {
      return Botan::TLS::error::stream_io_error;
      }
   catch(const Botan::Not_Implemented&)
      {
      return Botan::TLS::error::not_implemented;
      }
   catch(const Botan::Exception&)
      {
      return Botan::TLS::error::unknown;
      }
   catch(const std::exception&)
      {
      return Botan::TLS::error::unknown;
      }
   }

}  // namespace TLS

}  // namespace Botan

#endif
