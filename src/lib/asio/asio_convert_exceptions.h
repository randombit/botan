#ifndef BOTAN_ASIO_CONVERT_EXCEPTIONS_H_
#define BOTAN_ASIO_CONVERT_EXCEPTIONS_H_

#include <botan/asio_error.h>
#include <botan/tls_exceptn.h>

namespace Botan {
inline boost::system::error_code convertException()
   {
   try
      {
      throw;
      }
   catch(Botan::TLS::Unexpected_Message& e)
      {
      return make_error_code(Botan::error::unexpected_message);
      }
   catch(Botan::TLS::TLS_Exception& e)
      {
      return make_error_code(e.type());
      }
   catch(Botan::Unsupported_Argument& e)
      {
      return make_error_code(Botan::error::unsupported_argument);
      }
   catch(Botan::Invalid_Key_Length& e)
      {
      return make_error_code(Botan::error::invalid_key_length);
      }
   catch(Botan::Invalid_IV_Length& e)
      {
      return make_error_code(Botan::error::invalid_iv_length);
      }
   catch(Botan::Invalid_Algorithm_Name& e)
      {
      return make_error_code(Botan::error::invalid_algorithm_name);
      }
   catch(Botan::Encoding_Error& e)
      {
      return make_error_code(Botan::error::encoding_error);
      }
   catch(Botan::Invalid_OID& e)
      {
      return make_error_code(Botan::error::invalid_oid);
      }
   catch(Botan::Decoding_Error& e)
      {
      return make_error_code(Botan::error::decoding_error);
      }
   catch(Botan::Invalid_Argument& e)
      {
      return make_error_code(Botan::error::invalid_argument);
      }
   catch(Botan::Key_Not_Set& e)
      {
      return make_error_code(Botan::error::key_not_set);
      }
   catch(Botan::PRNG_Unseeded& e)
      {
      return make_error_code(Botan::error::prng_unseeded);
      }
   catch(Botan::Policy_Violation& e)
      {
      return make_error_code(Botan::error::policy_violation);
      }
   catch(Botan::Invalid_State& e)
      {
      return make_error_code(Botan::error::invalid_state);
      }
   catch(Botan::Algorithm_Not_Found& e)
      {
      return make_error_code(Botan::error::algorithm_not_found);
      }
   catch(Botan::Provider_Not_Found& e)
      {
      return make_error_code(Botan::error::provider_not_found);
      }
   catch(Botan::Lookup_Error& e)
      {
      return make_error_code(Botan::error::lookup_error);
      }
   catch(Botan::Self_Test_Failure& e)
      {
      return make_error_code(Botan::error::self_test_failure);
      }
   catch(Botan::Internal_Error& e)
      {
      return make_error_code(Botan::error::internal_error);
      }
   catch(Botan::No_Provider_Found& e)
      {
      return make_error_code(Botan::error::no_provider_found);
      }
   catch(Botan::Integrity_Failure& e)
      {
      return make_error_code(Botan::error::integrity_failure);
      }
   catch(Botan::Stream_IO_Error& e)
      {
      return make_error_code(Botan::error::stream_io_error);
      }
   catch(Botan::Not_Implemented& e)
      {
      return make_error_code(Botan::error::not_implemented);
      }
   catch(Botan::Exception& e)
      {
      return make_error_code(Botan::error::unknown);
      }
   catch(std::exception& e)
      {
      return make_error_code(Botan::error::unknown);
      }
   }
}

#endif
