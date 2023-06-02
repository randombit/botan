/*
* PKCS#11
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/p11.h>

#include <botan/p11_types.h>
#include <botan/internal/dyn_load.h>

#include <cstdint>
#include <functional>
#include <string>

namespace Botan::PKCS11 {

// NOLINTNEXTLINE(*-no-int-to-ptr,*-avoid-non-const-global-variables)
ReturnValue* ThrowException = reinterpret_cast<ReturnValue*>(-1);

/// @param function_result Return value of the PKCS11 module function
/// @param return_value if (`ThrowException`) is passed the function throws an exception, otherwise if a non-NULL pointer is passed:
/// return_value receives the return value of the PKCS#11 function and no exception is thrown.
/// @return true if function call was successful, false otherwise
bool LowLevel::handle_return_value(const CK_RV function_result, ReturnValue* return_value) {
   if(return_value == ThrowException) {
      if(static_cast<ReturnValue>(function_result) != ReturnValue::OK) {
         // caller wants exception
         throw PKCS11_ReturnError(static_cast<ReturnValue>(function_result));
      }
   } else if(return_value != nullptr) {
      // caller wants return value
      *return_value = static_cast<ReturnValue>(function_result);
   }

   return static_cast<ReturnValue>(function_result) == ReturnValue::OK;
}

void initialize_token(Slot& slot, std::string_view label, const secure_string& so_pin, const secure_string& pin) {
   slot.initialize(label, so_pin);
   set_pin(slot, so_pin, pin);
}

void change_pin(Slot& slot, const secure_string& old_pin, const secure_string& new_pin) {
   Session session(slot, false);
   session.login(UserType::User, old_pin);
   session.set_pin(old_pin, new_pin);
}

void change_so_pin(Slot& slot, const secure_string& old_so_pin, const secure_string& new_so_pin) {
   Session session(slot, false);
   session.login(UserType::SO, old_so_pin);
   session.set_pin(old_so_pin, new_so_pin);
}

void set_pin(Slot& slot, const secure_string& so_pin, const secure_string& pin) {
   Session session(slot, false);
   session.login(UserType::SO, so_pin);
   session.init_pin(pin);
}

LowLevel::LowLevel(FunctionListPtr ptr) : m_func_list_ptr(ptr) {
   if(m_func_list_ptr == nullptr) {
      throw Invalid_Argument("Invalid PKCS#11 function list ptr");
   }
}

/****************************** General purpose functions ******************************/

bool LowLevel::C_Initialize(VoidPtr init_args, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_Initialize(init_args), return_value);
}

bool LowLevel::C_Finalize(VoidPtr reserved, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_Finalize(reserved), return_value);
}

bool LowLevel::C_GetInfo(Info* info_ptr, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_GetInfo(info_ptr), return_value);
}

bool LowLevel::C_GetFunctionList(Dynamically_Loaded_Library& pkcs11_module,
                                 FunctionListPtr* function_list_ptr_ptr,
                                 ReturnValue* return_value) {
   using get_function_list = CK_RV (*)(FunctionListPtr*);

   get_function_list get_function_list_ptr = pkcs11_module.resolve<get_function_list>("C_GetFunctionList");

   return handle_return_value(get_function_list_ptr(function_list_ptr_ptr), return_value);
}

/****************************** Slot and token management functions ******************************/

bool LowLevel::C_GetSlotList(Bbool token_present,
                             SlotId* slot_list_ptr,
                             Ulong* count_ptr,
                             ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_GetSlotList(token_present, slot_list_ptr, count_ptr), return_value);
}

bool LowLevel::C_GetSlotList(bool token_present, std::vector<SlotId>& slot_ids, ReturnValue* return_value) const {
   slot_ids.clear();

   // first get available slots
   Ulong number_slots = 0;

   bool success = C_GetSlotList(token_present, nullptr, &number_slots, return_value);

   if(!success || !number_slots) {
      return success;
   }

   // get actual slot ids
   slot_ids.resize(number_slots);
   return C_GetSlotList(token_present, slot_ids.data(), &number_slots, return_value);
}

bool LowLevel::C_GetSlotInfo(SlotId slot_id, SlotInfo* info_ptr, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_GetSlotInfo(slot_id, info_ptr), return_value);
}

bool LowLevel::C_GetTokenInfo(SlotId slot_id, TokenInfo* info_ptr, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_GetTokenInfo(slot_id, info_ptr), return_value);
}

bool LowLevel::C_WaitForSlotEvent(Flags flags, SlotId* slot_ptr, VoidPtr reserved, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_WaitForSlotEvent(flags, slot_ptr, reserved), return_value);
}

bool LowLevel::C_GetMechanismList(SlotId slot_id,
                                  MechanismType* mechanism_list_ptr,
                                  Ulong* count_ptr,
                                  ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_GetMechanismList(
                                 slot_id, reinterpret_cast<CK_MECHANISM_TYPE_PTR>(mechanism_list_ptr), count_ptr),
                              return_value);
}

bool LowLevel::C_GetMechanismList(SlotId slot_id,
                                  std::vector<MechanismType>& mechanisms,
                                  ReturnValue* return_value) const {
   mechanisms.clear();

   // first get number of mechanisms
   Ulong number_mechanisms = 0;

   bool success = C_GetMechanismList(slot_id, nullptr, &number_mechanisms, return_value);

   if(!success || !number_mechanisms) {
      return success;
   }

   // get actual mechanisms
   mechanisms.resize(number_mechanisms);
   return C_GetMechanismList(
      slot_id, reinterpret_cast<MechanismType*>(mechanisms.data()), &number_mechanisms, return_value);
}

bool LowLevel::C_GetMechanismInfo(SlotId slot_id,
                                  MechanismType type,
                                  MechanismInfo* info_ptr,
                                  ReturnValue* return_value) const {
   return handle_return_value(
      m_func_list_ptr->C_GetMechanismInfo(slot_id, static_cast<CK_MECHANISM_TYPE>(type), info_ptr), return_value);
}

bool LowLevel::C_InitToken(
   SlotId slot_id, Utf8Char* so_pin_ptr, Ulong so_pin_len, Utf8Char* label_ptr, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_InitToken(slot_id, so_pin_ptr, so_pin_len, label_ptr), return_value);
}

bool LowLevel::C_InitPIN(SessionHandle session, Utf8Char* pin_ptr, Ulong pin_len, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_InitPIN(session, pin_ptr, pin_len), return_value);
}

bool LowLevel::C_SetPIN(SessionHandle session,
                        Utf8Char* old_pin_ptr,
                        Ulong old_len,
                        Utf8Char* new_pin_ptr,
                        Ulong new_len,
                        ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_SetPIN(session, old_pin_ptr, old_len, new_pin_ptr, new_len),
                              return_value);
}

/****************************** Session management ******************************/

bool LowLevel::C_OpenSession(SlotId slot_id,
                             Flags flags,
                             VoidPtr application,
                             Notify notify,
                             SessionHandle* session_ptr,
                             ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_OpenSession(slot_id, flags, application, notify, session_ptr),
                              return_value);
}

bool LowLevel::C_CloseSession(SessionHandle session, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_CloseSession(session), return_value);
}

bool LowLevel::C_CloseAllSessions(SlotId slot_id, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_CloseAllSessions(slot_id), return_value);
}

bool LowLevel::C_GetSessionInfo(SessionHandle session, SessionInfo* info_ptr, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_GetSessionInfo(session, info_ptr), return_value);
}

bool LowLevel::C_GetOperationState(SessionHandle session,
                                   Byte* operation_state_ptr,
                                   Ulong* operation_state_len_ptr,
                                   ReturnValue* return_value) const {
   return handle_return_value(
      m_func_list_ptr->C_GetOperationState(session, operation_state_ptr, operation_state_len_ptr), return_value);
}

bool LowLevel::C_SetOperationState(SessionHandle session,
                                   Byte* operation_state_ptr,
                                   Ulong operation_state_len,
                                   ObjectHandle encryption_key,
                                   ObjectHandle authentication_key,
                                   ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_SetOperationState(
                                 session, operation_state_ptr, operation_state_len, encryption_key, authentication_key),
                              return_value);
}

bool LowLevel::C_Login(
   SessionHandle session, UserType user_type, Utf8Char* pin_ptr, Ulong pin_len, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_Login(session, static_cast<CK_USER_TYPE>(user_type), pin_ptr, pin_len),
                              return_value);
}

bool LowLevel::C_Logout(SessionHandle session, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_Logout(session), return_value);
}

/****************************** Object management functions ******************************/

bool LowLevel::C_CreateObject(SessionHandle session,
                              Attribute* attribute_template_ptr,
                              Ulong count,
                              ObjectHandle* object_ptr,
                              ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_CreateObject(session, attribute_template_ptr, count, object_ptr),
                              return_value);
}

bool LowLevel::C_CopyObject(SessionHandle session,
                            ObjectHandle object,
                            Attribute* attribute_template_ptr,
                            Ulong count,
                            ObjectHandle* new_object_ptr,
                            ReturnValue* return_value) const {
   return handle_return_value(
      m_func_list_ptr->C_CopyObject(session, object, attribute_template_ptr, count, new_object_ptr), return_value);
}

bool LowLevel::C_DestroyObject(SessionHandle session, ObjectHandle object, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_DestroyObject(session, object), return_value);
}

bool LowLevel::C_GetObjectSize(SessionHandle session,
                               ObjectHandle object,
                               Ulong* size_ptr,
                               ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_GetObjectSize(session, object, size_ptr), return_value);
}

bool LowLevel::C_GetAttributeValue(SessionHandle session,
                                   ObjectHandle object,
                                   Attribute* attribute_template_ptr,
                                   Ulong count,
                                   ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_GetAttributeValue(session, object, attribute_template_ptr, count),
                              return_value);
}

bool LowLevel::C_SetAttributeValue(SessionHandle session,
                                   ObjectHandle object,
                                   Attribute* attribute_template_ptr,
                                   Ulong count,
                                   ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_SetAttributeValue(session, object, attribute_template_ptr, count),
                              return_value);
}

bool LowLevel::C_FindObjectsInit(SessionHandle session,
                                 Attribute* attribute_template_ptr,
                                 Ulong count,
                                 ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_FindObjectsInit(session, attribute_template_ptr, count), return_value);
}

bool LowLevel::C_FindObjects(SessionHandle session,
                             ObjectHandle* object_ptr,
                             Ulong max_object_count,
                             Ulong* object_count_ptr,
                             ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_FindObjects(session, object_ptr, max_object_count, object_count_ptr),
                              return_value);
}

bool LowLevel::C_FindObjectsFinal(SessionHandle session, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_FindObjectsFinal(session), return_value);
}

/****************************** Encryption functions ******************************/

bool LowLevel::C_EncryptInit(SessionHandle session,
                             Mechanism* mechanism_ptr,
                             ObjectHandle key,
                             ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_EncryptInit(session, mechanism_ptr, key), return_value);
}

bool LowLevel::C_Encrypt(SessionHandle session,
                         Byte* data_ptr,
                         Ulong data_len,
                         Byte* encrypted_data_ptr,
                         Ulong* encrypted_data_len_ptr,
                         ReturnValue* return_value) const {
   return handle_return_value(
      m_func_list_ptr->C_Encrypt(session, data_ptr, data_len, encrypted_data_ptr, encrypted_data_len_ptr),
      return_value);
}

bool LowLevel::C_EncryptUpdate(SessionHandle session,
                               Byte* part_ptr,
                               Ulong part_len,
                               Byte* encrypted_part_ptr,
                               Ulong* encrypted_part_len_ptr,
                               ReturnValue* return_value) const {
   return handle_return_value(
      m_func_list_ptr->C_EncryptUpdate(session, part_ptr, part_len, encrypted_part_ptr, encrypted_part_len_ptr),
      return_value);
}

bool LowLevel::C_EncryptFinal(SessionHandle session,
                              Byte* last_encrypted_part_ptr,
                              Ulong* last_encrypted_part_len_ptr,
                              ReturnValue* return_value) const {
   return handle_return_value(
      m_func_list_ptr->C_EncryptFinal(session, last_encrypted_part_ptr, last_encrypted_part_len_ptr), return_value);
}

/****************************** Decryption functions ******************************/

bool LowLevel::C_DecryptInit(SessionHandle session,
                             Mechanism* mechanism_ptr,
                             ObjectHandle key,
                             ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_DecryptInit(session, mechanism_ptr, key), return_value);
}

bool LowLevel::C_Decrypt(SessionHandle session,
                         Byte* encrypted_data_ptr,
                         Ulong encrypted_data_len,
                         Byte* data_ptr,
                         Ulong* data_len_ptr,
                         ReturnValue* return_value) const {
   return handle_return_value(
      m_func_list_ptr->C_Decrypt(session, encrypted_data_ptr, encrypted_data_len, data_ptr, data_len_ptr),
      return_value);
}

bool LowLevel::C_DecryptUpdate(SessionHandle session,
                               Byte* encrypted_part_ptr,
                               Ulong encrypted_part_len,
                               Byte* part_ptr,
                               Ulong* part_len_ptr,
                               ReturnValue* return_value) const {
   return handle_return_value(
      m_func_list_ptr->C_DecryptUpdate(session, encrypted_part_ptr, encrypted_part_len, part_ptr, part_len_ptr),
      return_value);
}

bool LowLevel::C_DecryptFinal(SessionHandle session,
                              Byte* last_part_ptr,
                              Ulong* last_part_len_ptr,
                              ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_DecryptFinal(session, last_part_ptr, last_part_len_ptr), return_value);
}

/****************************** Message digesting functions ******************************/

bool LowLevel::C_DigestInit(SessionHandle session, Mechanism* mechanism, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_DigestInit(session, mechanism), return_value);
}

bool LowLevel::C_Digest(SessionHandle session,
                        Byte* data_ptr,
                        Ulong data_len,
                        Byte* digest_ptr,
                        Ulong* digest_len_ptr,
                        ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_Digest(session, data_ptr, data_len, digest_ptr, digest_len_ptr),
                              return_value);
}

bool LowLevel::C_DigestUpdate(SessionHandle session, Byte* part_ptr, Ulong part_len, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_DigestUpdate(session, part_ptr, part_len), return_value);
}

bool LowLevel::C_DigestKey(SessionHandle session, ObjectHandle key, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_DigestKey(session, key), return_value);
}

bool LowLevel::C_DigestFinal(SessionHandle session,
                             Byte* digest_ptr,
                             Ulong* digest_len_ptr,
                             ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_DigestFinal(session, digest_ptr, digest_len_ptr), return_value);
}

/****************************** Signing and MACing functions ******************************/

bool LowLevel::C_SignInit(SessionHandle session,
                          Mechanism* mechanism_ptr,
                          ObjectHandle key,
                          ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_SignInit(session, mechanism_ptr, key), return_value);
}

bool LowLevel::C_Sign(SessionHandle session,
                      const Byte* data_ptr,
                      Ulong data_len,
                      Byte* signature_ptr,
                      Ulong* signature_len_ptr,
                      ReturnValue* return_value) const {
   return handle_return_value(
      m_func_list_ptr->C_Sign(session, const_cast<Byte*>(data_ptr), data_len, signature_ptr, signature_len_ptr),
      return_value);
}

bool LowLevel::C_SignUpdate(SessionHandle session,
                            const Byte* part_ptr,
                            Ulong part_len,
                            ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_SignUpdate(session, const_cast<Byte*>(part_ptr), part_len),
                              return_value);
}

bool LowLevel::C_SignFinal(SessionHandle session,
                           Byte* signature_ptr,
                           Ulong* signature_len_ptr,
                           ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_SignFinal(session, signature_ptr, signature_len_ptr), return_value);
}

bool LowLevel::C_SignRecoverInit(SessionHandle session,
                                 Mechanism* mechanism_ptr,
                                 ObjectHandle key,
                                 ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_SignRecoverInit(session, mechanism_ptr, key), return_value);
}

bool LowLevel::C_SignRecover(SessionHandle session,
                             Byte* data,
                             Ulong data_len,
                             Byte* signature,
                             Ulong* signature_len,
                             ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_SignRecover(session, data, data_len, signature, signature_len),
                              return_value);
}

/****************************** Functions for verifying signatures and MACs ******************************/

bool LowLevel::C_VerifyInit(SessionHandle session,
                            Mechanism* mechanism_ptr,
                            ObjectHandle key,
                            ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_VerifyInit(session, mechanism_ptr, key), return_value);
}

bool LowLevel::C_Verify(SessionHandle session,
                        const Byte* data_ptr,
                        Ulong data_len,
                        const Byte* signature_ptr,
                        Ulong signature_len,
                        ReturnValue* return_value) const {
   return handle_return_value(
      m_func_list_ptr->C_Verify(
         session, const_cast<Byte*>(data_ptr), data_len, const_cast<Byte*>(signature_ptr), signature_len),
      return_value);
}

bool LowLevel::C_VerifyUpdate(SessionHandle session,
                              const Byte* part_ptr,
                              Ulong part_len,
                              ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_VerifyUpdate(session, const_cast<Byte*>(part_ptr), part_len),
                              return_value);
}

bool LowLevel::C_VerifyFinal(SessionHandle session,
                             const Byte* signature_ptr,
                             Ulong signature_len,
                             ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_VerifyFinal(session, const_cast<Byte*>(signature_ptr), signature_len),
                              return_value);
}

bool LowLevel::C_VerifyRecoverInit(SessionHandle session,
                                   Mechanism* mechanism_ptr,
                                   ObjectHandle key,
                                   ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_VerifyRecoverInit(session, mechanism_ptr, key), return_value);
}

bool LowLevel::C_VerifyRecover(SessionHandle session,
                               Byte* signature_ptr,
                               Ulong signature_len,
                               Byte* data_ptr,
                               Ulong* data_len_ptr,
                               ReturnValue* return_value) const {
   return handle_return_value(
      m_func_list_ptr->C_VerifyRecover(session, signature_ptr, signature_len, data_ptr, data_len_ptr), return_value);
}

/****************************** Dual-purpose cryptographic functions ******************************/

bool LowLevel::C_DigestEncryptUpdate(SessionHandle session,
                                     Byte* part_ptr,
                                     Ulong part_len,
                                     Byte* encrypted_part_ptr,
                                     Ulong* encrypted_part_len_ptr,
                                     ReturnValue* return_value) const {
   return handle_return_value(
      m_func_list_ptr->C_DigestEncryptUpdate(session, part_ptr, part_len, encrypted_part_ptr, encrypted_part_len_ptr),
      return_value);
}

bool LowLevel::C_DecryptDigestUpdate(SessionHandle session,
                                     Byte* encrypted_part_ptr,
                                     Ulong encrypted_part_len,
                                     Byte* part_ptr,
                                     Ulong* part_len_ptr,
                                     ReturnValue* return_value) const {
   return handle_return_value(
      m_func_list_ptr->C_DecryptDigestUpdate(session, encrypted_part_ptr, encrypted_part_len, part_ptr, part_len_ptr),
      return_value);
}

bool LowLevel::C_SignEncryptUpdate(SessionHandle session,
                                   Byte* part_ptr,
                                   Ulong part_len,
                                   Byte* encrypted_part_ptr,
                                   Ulong* encrypted_part_len_ptr,
                                   ReturnValue* return_value) const {
   return handle_return_value(
      m_func_list_ptr->C_SignEncryptUpdate(session, part_ptr, part_len, encrypted_part_ptr, encrypted_part_len_ptr),
      return_value);
}

bool LowLevel::C_DecryptVerifyUpdate(SessionHandle session,
                                     Byte* encrypted_part_ptr,
                                     Ulong encrypted_part_len,
                                     Byte* part_ptr,
                                     Ulong* part_len_ptr,
                                     ReturnValue* return_value) const {
   return handle_return_value(
      m_func_list_ptr->C_DecryptVerifyUpdate(session, encrypted_part_ptr, encrypted_part_len, part_ptr, part_len_ptr),
      return_value);
}

/****************************** Key management functions ******************************/

bool LowLevel::C_GenerateKey(SessionHandle session,
                             Mechanism* mechanism_ptr,
                             Attribute* attribute_template_ptr,
                             Ulong count,
                             ObjectHandle* key_ptr,
                             ReturnValue* return_value) const {
   return handle_return_value(
      m_func_list_ptr->C_GenerateKey(session, mechanism_ptr, attribute_template_ptr, count, key_ptr), return_value);
}

bool LowLevel::C_GenerateKeyPair(SessionHandle session,
                                 Mechanism* mechanism_ptr,
                                 Attribute* public_key_template_ptr,
                                 Ulong public_key_attribute_count,
                                 Attribute* private_key_template_ptr,
                                 Ulong private_key_attribute_count,
                                 ObjectHandle* public_key_ptr,
                                 ObjectHandle* private_key_ptr,
                                 ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_GenerateKeyPair(session,
                                                                 mechanism_ptr,
                                                                 public_key_template_ptr,
                                                                 public_key_attribute_count,
                                                                 private_key_template_ptr,
                                                                 private_key_attribute_count,
                                                                 public_key_ptr,
                                                                 private_key_ptr),
                              return_value);
}

bool LowLevel::C_WrapKey(SessionHandle session,
                         Mechanism* mechanism_ptr,
                         ObjectHandle wrapping_key,
                         ObjectHandle key,
                         Byte* wrapped_key_ptr,
                         Ulong* wrapped_key_len_ptr,
                         ReturnValue* return_value) const {
   return handle_return_value(
      m_func_list_ptr->C_WrapKey(session, mechanism_ptr, wrapping_key, key, wrapped_key_ptr, wrapped_key_len_ptr),
      return_value);
}

bool LowLevel::C_UnwrapKey(SessionHandle session,
                           Mechanism* mechanism_ptr,
                           ObjectHandle unwrapping_key,
                           Byte* wrapped_key_ptr,
                           Ulong wrapped_key_len,
                           Attribute* attribute_template_ptr,
                           Ulong attribute_count,
                           ObjectHandle* key_ptr,
                           ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_UnwrapKey(session,
                                                           mechanism_ptr,
                                                           unwrapping_key,
                                                           wrapped_key_ptr,
                                                           wrapped_key_len,
                                                           attribute_template_ptr,
                                                           attribute_count,
                                                           key_ptr),
                              return_value);
}

bool LowLevel::C_DeriveKey(SessionHandle session,
                           Mechanism* mechanism_ptr,
                           ObjectHandle base_key,
                           Attribute* attribute_template_ptr,
                           Ulong attribute_count,
                           ObjectHandle* key_ptr,
                           ReturnValue* return_value) const {
   return handle_return_value(
      m_func_list_ptr->C_DeriveKey(session, mechanism_ptr, base_key, attribute_template_ptr, attribute_count, key_ptr),
      return_value);
}

/****************************** Random number generation functions ******************************/

bool LowLevel::C_SeedRandom(SessionHandle session,
                            const Byte* seed_ptr,
                            Ulong seed_len,
                            ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_SeedRandom(session, const_cast<Byte*>(seed_ptr), seed_len),
                              return_value);
}

bool LowLevel::C_GenerateRandom(SessionHandle session,
                                Byte* random_data_ptr,
                                Ulong random_len,
                                ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_GenerateRandom(session, random_data_ptr, random_len), return_value);
}

/****************************** Parallel function management functions ******************************/

bool LowLevel::C_GetFunctionStatus(SessionHandle session, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_GetFunctionStatus(session), return_value);
}

bool LowLevel::C_CancelFunction(SessionHandle session, ReturnValue* return_value) const {
   return handle_return_value(m_func_list_ptr->C_CancelFunction(session), return_value);
}

}  // namespace Botan::PKCS11
