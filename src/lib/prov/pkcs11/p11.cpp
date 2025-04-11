/*
* PKCS#11
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
* (C) 2025 Fabian Albert, Rohde & Schwarz Cybersecurity GmbH
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/p11.h>

#include <botan/assert.h>
#include <botan/p11_types.h>
#include <botan/internal/dyn_load.h>

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

LowLevel::LowLevel(FunctionList* ptr) {
   BOTAN_ARG_CHECK(ptr != nullptr, "Function list pointer must not be nullptr");
   m_interface_wrapper = std::make_unique<InterfaceWrapper>(Interface{
      .pInterfaceName = InterfaceWrapper::p11_interface_name_ptr(),
      .pFunctionList = ptr,
      .flags = 0,
   });
}

LowLevel::LowLevel(std::unique_ptr<InterfaceWrapper> interface_wrapper) {
   BOTAN_ARG_CHECK(interface_wrapper != nullptr, "Interface wrapper must not be nullptr");
   m_interface_wrapper = std::move(interface_wrapper);
}

/****************************** General purpose functions ******************************/

bool LowLevel::C_Initialize(const void* init_args, ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_Initialize(const_cast<void*>(init_args)),
                              return_value);
}

bool LowLevel::C_Finalize(void* reserved, ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_Finalize(reserved), return_value);
}

bool LowLevel::C_GetInfo(Info* info_ptr, ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_GetInfo(info_ptr), return_value);
}

bool LowLevel::C_GetFunctionList(const Dynamically_Loaded_Library& pkcs11_module,
                                 FunctionList** function_list_ptr_ptr,
                                 ReturnValue* return_value) {
   using get_function_list = CK_RV (*)(FunctionList**);

   get_function_list get_function_list_ptr = pkcs11_module.resolve<get_function_list>("C_GetFunctionList");

   return handle_return_value(get_function_list_ptr(function_list_ptr_ptr), return_value);
}

bool LowLevel::C_GetInterfaceList(const Dynamically_Loaded_Library& pkcs11_module,
                                  Interface* interface_list_ptr,
                                  Ulong* count_ptr,
                                  ReturnValue* return_value) {
   using get_interface_list = CK_RV (*)(Interface*, Ulong*);
   if(auto get_interface_list_ptr = pkcs11_module.try_resolve_symbol<get_interface_list>("C_GetInterfaceList");
      get_interface_list_ptr.has_value()) {
      return handle_return_value(get_interface_list_ptr.value()(interface_list_ptr, count_ptr), return_value);
   }
   // Loading the library function failed. Probably due to a cryptoki library with PKCS #11 < 3.0.
   return handle_return_value(CKR_GENERAL_ERROR, return_value);
}

bool LowLevel::C_GetInterface(const Dynamically_Loaded_Library& pkcs11_module,
                              const Utf8Char* interface_name_ptr,
                              const Version* version_ptr,
                              Interface* interface_ptr_ptr,
                              Flags flags,
                              ReturnValue* return_value) {
   using get_interface =
      CK_RV (*)(Utf8Char* interface_name_ptr, Version* version_ptr, Interface* interface_ptr_ptr, Flags flags);
   if(auto get_interface_ptr = pkcs11_module.try_resolve_symbol<get_interface>("C_GetInterface");
      get_interface_ptr.has_value()) {
      return handle_return_value(
         get_interface_ptr.value()(
            const_cast<Utf8Char*>(interface_name_ptr), const_cast<Version*>(version_ptr), interface_ptr_ptr, flags),
         return_value);
   }
   // Loading the library function failed. Probably due to a cryptoki library with PKCS #11 < 3.0.
   return handle_return_value(CKR_GENERAL_ERROR, return_value);
}

/****************************** Slot and token management functions ******************************/

bool LowLevel::C_GetSlotList(Bbool token_present,
                             SlotId* slot_list_ptr,
                             Ulong* count_ptr,
                             ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_GetSlotList(token_present, slot_list_ptr, count_ptr),
                              return_value);
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
   return handle_return_value(m_interface_wrapper->func_2_40().C_GetSlotInfo(slot_id, info_ptr), return_value);
}

bool LowLevel::C_GetTokenInfo(SlotId slot_id, TokenInfo* info_ptr, ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_GetTokenInfo(slot_id, info_ptr), return_value);
}

bool LowLevel::C_WaitForSlotEvent(Flags flags, SlotId* slot_ptr, void* reserved, ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_WaitForSlotEvent(flags, slot_ptr, reserved),
                              return_value);
}

bool LowLevel::C_GetMechanismList(SlotId slot_id,
                                  MechanismType* mechanism_list_ptr,
                                  Ulong* count_ptr,
                                  ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_GetMechanismList(
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
      m_interface_wrapper->func_2_40().C_GetMechanismInfo(slot_id, static_cast<CK_MECHANISM_TYPE>(type), info_ptr),
      return_value);
}

bool LowLevel::C_InitToken(SlotId slot_id,
                           const Utf8Char* so_pin_ptr,
                           Ulong so_pin_len,
                           const Utf8Char* label_ptr,
                           ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_InitToken(
         slot_id, const_cast<Utf8Char*>(so_pin_ptr), so_pin_len, const_cast<Utf8Char*>(label_ptr)),
      return_value);
}

bool LowLevel::C_InitPIN(SessionHandle session,
                         const Utf8Char* pin_ptr,
                         Ulong pin_len,
                         ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_InitPIN(session, const_cast<Utf8Char*>(pin_ptr), pin_len), return_value);
}

bool LowLevel::C_SetPIN(SessionHandle session,
                        const Utf8Char* old_pin_ptr,
                        Ulong old_len,
                        const Utf8Char* new_pin_ptr,
                        Ulong new_len,
                        ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_SetPIN(
         session, const_cast<Utf8Char*>(old_pin_ptr), old_len, const_cast<Utf8Char*>(new_pin_ptr), new_len),
      return_value);
}

/****************************** Session management ******************************/

bool LowLevel::C_OpenSession(SlotId slot_id,
                             Flags flags,
                             void* application,
                             Notify notify,
                             SessionHandle* session_ptr,
                             ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_OpenSession(slot_id, flags, application, notify, session_ptr), return_value);
}

bool LowLevel::C_CloseSession(SessionHandle session, ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_CloseSession(session), return_value);
}

bool LowLevel::C_CloseAllSessions(SlotId slot_id, ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_CloseAllSessions(slot_id), return_value);
}

bool LowLevel::C_GetSessionInfo(SessionHandle session, SessionInfo* info_ptr, ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_GetSessionInfo(session, info_ptr), return_value);
}

bool LowLevel::C_SessionCancel(SessionHandle session, Flags flags, ReturnValue* return_value) {
   return handle_return_value(m_interface_wrapper->func_3_0().C_SessionCancel(session, flags), return_value);
}

bool LowLevel::C_GetOperationState(SessionHandle session,
                                   Byte* operation_state_ptr,
                                   Ulong* operation_state_len_ptr,
                                   ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_GetOperationState(session, operation_state_ptr, operation_state_len_ptr),
      return_value);
}

bool LowLevel::C_SetOperationState(SessionHandle session,
                                   const Byte* operation_state_ptr,
                                   Ulong operation_state_len,
                                   ObjectHandle encryption_key,
                                   ObjectHandle authentication_key,
                                   ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_SetOperationState(
         session, const_cast<Byte*>(operation_state_ptr), operation_state_len, encryption_key, authentication_key),
      return_value);
}

bool LowLevel::C_Login(
   SessionHandle session, UserType user_type, const Utf8Char* pin_ptr, Ulong pin_len, ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_Login(
         session, static_cast<CK_USER_TYPE>(user_type), const_cast<Utf8Char*>(pin_ptr), pin_len),
      return_value);
}

bool LowLevel::C_LoginUser(SessionHandle session,
                           UserType user_type,
                           const Utf8Char* pin_ptr,
                           Ulong pin_len,
                           const Utf8Char* username_ptr,
                           Ulong username_len,
                           ReturnValue* return_value) {
   return handle_return_value(m_interface_wrapper->func_3_0().C_LoginUser(session,
                                                                          static_cast<CK_USER_TYPE>(user_type),
                                                                          const_cast<Utf8Char*>(pin_ptr),
                                                                          pin_len,
                                                                          const_cast<Utf8Char*>(username_ptr),
                                                                          username_len),
                              return_value);
}

bool LowLevel::C_Logout(SessionHandle session, ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_Logout(session), return_value);
}

bool LowLevel::C_GetSessionValidationFlags(SessionHandle session,
                                           Ulong type,
                                           Flags* flags_ptr,
                                           ReturnValue* return_value) {
   return handle_return_value(m_interface_wrapper->func_3_2().C_GetSessionValidationFlags(session, type, flags_ptr),
                              return_value);
}

/****************************** Object management functions ******************************/

bool LowLevel::C_CreateObject(SessionHandle session,
                              Attribute* attribute_template_ptr,
                              Ulong count,
                              ObjectHandle* object_ptr,
                              ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_CreateObject(session, attribute_template_ptr, count, object_ptr),
      return_value);
}

bool LowLevel::C_CopyObject(SessionHandle session,
                            ObjectHandle object,
                            Attribute* attribute_template_ptr,
                            Ulong count,
                            ObjectHandle* new_object_ptr,
                            ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_CopyObject(session, object, attribute_template_ptr, count, new_object_ptr),
      return_value);
}

bool LowLevel::C_DestroyObject(SessionHandle session, ObjectHandle object, ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_DestroyObject(session, object), return_value);
}

bool LowLevel::C_GetObjectSize(SessionHandle session,
                               ObjectHandle object,
                               Ulong* size_ptr,
                               ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_GetObjectSize(session, object, size_ptr),
                              return_value);
}

bool LowLevel::C_GetAttributeValue(SessionHandle session,
                                   ObjectHandle object,
                                   Attribute* attribute_template_ptr,
                                   Ulong count,
                                   ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_GetAttributeValue(session, object, attribute_template_ptr, count),
      return_value);
}

bool LowLevel::C_SetAttributeValue(SessionHandle session,
                                   ObjectHandle object,
                                   Attribute* attribute_template_ptr,
                                   Ulong count,
                                   ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_SetAttributeValue(session, object, attribute_template_ptr, count),
      return_value);
}

bool LowLevel::C_FindObjectsInit(SessionHandle session,
                                 Attribute* attribute_template_ptr,
                                 Ulong count,
                                 ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_FindObjectsInit(session, attribute_template_ptr, count), return_value);
}

bool LowLevel::C_FindObjects(SessionHandle session,
                             ObjectHandle* object_ptr,
                             Ulong max_object_count,
                             Ulong* object_count_ptr,
                             ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_FindObjects(session, object_ptr, max_object_count, object_count_ptr),
      return_value);
}

bool LowLevel::C_FindObjectsFinal(SessionHandle session, ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_FindObjectsFinal(session), return_value);
}

/****************************** Encryption functions ******************************/

bool LowLevel::C_EncryptInit(SessionHandle session,
                             const Mechanism* mechanism_ptr,
                             ObjectHandle key,
                             ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_EncryptInit(session, const_cast<Mechanism*>(mechanism_ptr), key),
      return_value);
}

bool LowLevel::C_Encrypt(SessionHandle session,
                         const Byte* data_ptr,
                         Ulong data_len,
                         Byte* encrypted_data_ptr,
                         Ulong* encrypted_data_len_ptr,
                         ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_Encrypt(
         session, const_cast<Byte*>(data_ptr), data_len, encrypted_data_ptr, encrypted_data_len_ptr),
      return_value);
}

bool LowLevel::C_EncryptUpdate(SessionHandle session,
                               const Byte* part_ptr,
                               Ulong part_len,
                               Byte* encrypted_part_ptr,
                               Ulong* encrypted_part_len_ptr,
                               ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_EncryptUpdate(
         session, const_cast<Byte*>(part_ptr), part_len, encrypted_part_ptr, encrypted_part_len_ptr),
      return_value);
}

bool LowLevel::C_EncryptFinal(SessionHandle session,
                              Byte* last_encrypted_part_ptr,
                              Ulong* last_encrypted_part_len_ptr,
                              ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_EncryptFinal(session, last_encrypted_part_ptr, last_encrypted_part_len_ptr),
      return_value);
}

/*********************** Message-based encryption functions ***********************/

bool LowLevel::C_MessageEncryptInit(SessionHandle session,
                                    const Mechanism* mechanism_ptr,
                                    ObjectHandle key,
                                    ReturnValue* return_value) {
   return handle_return_value(
      m_interface_wrapper->func_3_0().C_MessageEncryptInit(session, const_cast<Mechanism*>(mechanism_ptr), key),
      return_value);
}

bool LowLevel::C_EncryptMessage(SessionHandle session,
                                const void* parameter_ptr,
                                Ulong parameter_len,
                                const Byte* associated_data_ptr,
                                Ulong associated_data_len,
                                const Byte* plaintext_ptr,
                                Ulong plaintext_len,
                                Byte* ciphertext_ptr,
                                Ulong* ciphertext_len_ptr,
                                ReturnValue* return_value) {
   return handle_return_value(m_interface_wrapper->func_3_0().C_EncryptMessage(session,
                                                                               const_cast<void*>(parameter_ptr),
                                                                               parameter_len,
                                                                               const_cast<Byte*>(associated_data_ptr),
                                                                               associated_data_len,
                                                                               const_cast<Byte*>(plaintext_ptr),
                                                                               plaintext_len,
                                                                               ciphertext_ptr,
                                                                               ciphertext_len_ptr),
                              return_value);
}

bool LowLevel::C_EncryptMessageBegin(SessionHandle session,
                                     const void* parameter_ptr,
                                     Ulong parameter_len,
                                     const Byte* associated_data_ptr,
                                     Ulong associated_data_len,
                                     ReturnValue* return_value) {
   return handle_return_value(
      m_interface_wrapper->func_3_0().C_EncryptMessageBegin(session,
                                                            const_cast<void*>(parameter_ptr),
                                                            parameter_len,
                                                            const_cast<Byte*>(associated_data_ptr),
                                                            associated_data_len),
      return_value);
}

bool LowLevel::C_EncryptMessageNext(SessionHandle session,
                                    const void* parameter_ptr,
                                    Ulong parameter_len,
                                    const Byte* plaintext_part_ptr,
                                    Ulong plaintext_part_len,
                                    Byte* ciphertext_ptr,
                                    Ulong* ciphertext_part_len_ptr,
                                    Flags flags,
                                    ReturnValue* return_value) {
   return handle_return_value(
      m_interface_wrapper->func_3_0().C_EncryptMessageNext(session,
                                                           const_cast<void*>(parameter_ptr),
                                                           parameter_len,
                                                           const_cast<Byte*>(plaintext_part_ptr),
                                                           plaintext_part_len,
                                                           ciphertext_ptr,
                                                           ciphertext_part_len_ptr,
                                                           flags),
      return_value);
}

bool LowLevel::C_MessageEncryptFinal(SessionHandle session, ReturnValue* return_value) {
   return handle_return_value(m_interface_wrapper->func_3_0().C_MessageEncryptFinal(session), return_value);
}

/****************************** Decryption functions ******************************/

bool LowLevel::C_DecryptInit(SessionHandle session,
                             const Mechanism* mechanism_ptr,
                             ObjectHandle key,
                             ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_DecryptInit(session, const_cast<Mechanism*>(mechanism_ptr), key),
      return_value);
}

bool LowLevel::C_Decrypt(SessionHandle session,
                         const Byte* encrypted_data_ptr,
                         Ulong encrypted_data_len,
                         Byte* data_ptr,
                         Ulong* data_len_ptr,
                         ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_Decrypt(
         session, const_cast<Byte*>(encrypted_data_ptr), encrypted_data_len, data_ptr, data_len_ptr),
      return_value);
}

bool LowLevel::C_DecryptUpdate(SessionHandle session,
                               const Byte* encrypted_part_ptr,
                               Ulong encrypted_part_len,
                               Byte* part_ptr,
                               Ulong* part_len_ptr,
                               ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_DecryptUpdate(
         session, const_cast<Byte*>(encrypted_part_ptr), encrypted_part_len, part_ptr, part_len_ptr),
      return_value);
}

bool LowLevel::C_DecryptFinal(SessionHandle session,
                              Byte* last_part_ptr,
                              Ulong* last_part_len_ptr,
                              ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_DecryptFinal(session, last_part_ptr, last_part_len_ptr), return_value);
}

/*********************** Message-based decryption functions ***********************/

bool LowLevel::C_MessageDecryptInit(SessionHandle session,
                                    const Mechanism* mechanism_ptr,
                                    ObjectHandle key,
                                    ReturnValue* return_value) {
   return handle_return_value(
      m_interface_wrapper->func_3_0().C_MessageDecryptInit(session, const_cast<Mechanism*>(mechanism_ptr), key),
      return_value);
}

bool LowLevel::C_DecryptMessage(SessionHandle session,
                                const void* parameter_ptr,
                                Ulong parameter_len,
                                const Byte* associated_data_ptr,
                                Ulong associated_data_len,
                                const Byte* ciphertext_ptr,
                                Ulong ciphertext_len,
                                Byte* plaintext_ptr,
                                Ulong* plaintext_len_ptr,
                                ReturnValue* return_value) {
   return handle_return_value(m_interface_wrapper->func_3_0().C_DecryptMessage(session,
                                                                               const_cast<void*>(parameter_ptr),
                                                                               parameter_len,
                                                                               const_cast<Byte*>(associated_data_ptr),
                                                                               associated_data_len,
                                                                               const_cast<Byte*>(ciphertext_ptr),
                                                                               ciphertext_len,
                                                                               plaintext_ptr,
                                                                               plaintext_len_ptr),
                              return_value);
}

bool LowLevel::C_DecryptMessageBegin(SessionHandle session,
                                     const void* parameter_ptr,
                                     Ulong parameter_len,
                                     const Byte* associated_data_ptr,
                                     Ulong associated_data_len,
                                     ReturnValue* return_value) {
   return handle_return_value(
      m_interface_wrapper->func_3_0().C_DecryptMessageBegin(session,
                                                            const_cast<void*>(parameter_ptr),
                                                            parameter_len,
                                                            const_cast<Byte*>(associated_data_ptr),
                                                            associated_data_len),
      return_value);
}

bool LowLevel::C_DecryptMessageNext(SessionHandle session,
                                    const void* parameter_ptr,
                                    Ulong parameter_len,
                                    const Byte* ciphertext_part_ptr,
                                    Ulong ciphertext_part_len,
                                    Byte* plaintext_ptr,
                                    Ulong* plaintext_part_len_ptr,
                                    Flags flags,
                                    ReturnValue* return_value) {
   return handle_return_value(
      m_interface_wrapper->func_3_0().C_DecryptMessageNext(session,
                                                           const_cast<void*>(parameter_ptr),
                                                           parameter_len,
                                                           const_cast<Byte*>(ciphertext_part_ptr),
                                                           ciphertext_part_len,
                                                           plaintext_ptr,
                                                           plaintext_part_len_ptr,
                                                           flags),
      return_value);
}

bool LowLevel::C_MessageDecryptFinal(SessionHandle session, ReturnValue* return_value) {
   return handle_return_value(m_interface_wrapper->func_3_0().C_MessageDecryptFinal(session), return_value);
}

/****************************** Message digesting functions ******************************/

bool LowLevel::C_DigestInit(SessionHandle session, const Mechanism* mechanism, ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_DigestInit(session, const_cast<Mechanism*>(mechanism)),
                              return_value);
}

bool LowLevel::C_Digest(SessionHandle session,
                        const Byte* data_ptr,
                        Ulong data_len,
                        Byte* digest_ptr,
                        Ulong* digest_len_ptr,
                        ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_Digest(
                                 session, const_cast<Byte*>(data_ptr), data_len, digest_ptr, digest_len_ptr),
                              return_value);
}

bool LowLevel::C_DigestUpdate(SessionHandle session,
                              const Byte* part_ptr,
                              Ulong part_len,
                              ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_DigestUpdate(session, const_cast<Byte*>(part_ptr), part_len), return_value);
}

bool LowLevel::C_DigestKey(SessionHandle session, ObjectHandle key, ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_DigestKey(session, key), return_value);
}

bool LowLevel::C_DigestFinal(SessionHandle session,
                             Byte* digest_ptr,
                             Ulong* digest_len_ptr,
                             ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_DigestFinal(session, digest_ptr, digest_len_ptr),
                              return_value);
}

/****************************** Signing and MACing functions ******************************/

bool LowLevel::C_SignInit(SessionHandle session,
                          const Mechanism* mechanism_ptr,
                          ObjectHandle key,
                          ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_SignInit(session, const_cast<Mechanism*>(mechanism_ptr), key), return_value);
}

bool LowLevel::C_Sign(SessionHandle session,
                      const Byte* data_ptr,
                      Ulong data_len,
                      Byte* signature_ptr,
                      Ulong* signature_len_ptr,
                      ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_Sign(
                                 session, const_cast<Byte*>(data_ptr), data_len, signature_ptr, signature_len_ptr),
                              return_value);
}

bool LowLevel::C_SignUpdate(SessionHandle session,
                            const Byte* part_ptr,
                            Ulong part_len,
                            ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_SignUpdate(session, const_cast<Byte*>(part_ptr), part_len), return_value);
}

bool LowLevel::C_SignFinal(SessionHandle session,
                           Byte* signature_ptr,
                           Ulong* signature_len_ptr,
                           ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_SignFinal(session, signature_ptr, signature_len_ptr),
                              return_value);
}

bool LowLevel::C_SignRecoverInit(SessionHandle session,
                                 const Mechanism* mechanism_ptr,
                                 ObjectHandle key,
                                 ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_SignRecoverInit(session, const_cast<Mechanism*>(mechanism_ptr), key),
      return_value);
}

bool LowLevel::C_SignRecover(SessionHandle session,
                             const Byte* data,
                             Ulong data_len,
                             Byte* signature,
                             Ulong* signature_len,
                             ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_SignRecover(
                                 session, const_cast<Byte*>(data), data_len, signature, signature_len),
                              return_value);
}

/******************* Message-based signing and MACing functions *******************/

bool LowLevel::C_MessageSignInit(SessionHandle session,
                                 const Mechanism* mechanism_ptr,
                                 ObjectHandle key,
                                 ReturnValue* return_value) {
   return handle_return_value(
      m_interface_wrapper->func_3_0().C_MessageSignInit(session, const_cast<Mechanism*>(mechanism_ptr), key),
      return_value);
}

bool LowLevel::C_SignMessage(SessionHandle session,
                             const void* parameter_ptr,
                             Ulong parameter_len,
                             const Byte* data_ptr,
                             Ulong data_len,
                             Byte* signature_ptr,
                             Ulong* signature_len_ptr,
                             ReturnValue* return_value) {
   return handle_return_value(m_interface_wrapper->func_3_0().C_SignMessage(session,
                                                                            const_cast<void*>(parameter_ptr),
                                                                            parameter_len,
                                                                            const_cast<Byte*>(data_ptr),
                                                                            data_len,
                                                                            signature_ptr,
                                                                            signature_len_ptr),
                              return_value);
}

bool LowLevel::C_SignMessageBegin(SessionHandle session,
                                  const void* parameter_ptr,
                                  Ulong parameter_len,
                                  ReturnValue* return_value) {
   return handle_return_value(
      m_interface_wrapper->func_3_0().C_SignMessageBegin(session, const_cast<void*>(parameter_ptr), parameter_len),
      return_value);
}

bool LowLevel::C_SignMessageNext(SessionHandle session,
                                 const void* parameter_ptr,
                                 Ulong parameter_len,
                                 const Byte* data_ptr,
                                 Ulong data_len,
                                 Byte* signature_ptr,
                                 Ulong* signature_len_ptr,
                                 ReturnValue* return_value) {
   return handle_return_value(m_interface_wrapper->func_3_0().C_SignMessageNext(session,
                                                                                const_cast<void*>(parameter_ptr),
                                                                                parameter_len,
                                                                                const_cast<Byte*>(data_ptr),
                                                                                data_len,
                                                                                signature_ptr,
                                                                                signature_len_ptr),
                              return_value);
}

bool LowLevel::C_MessageSignFinal(SessionHandle session, ReturnValue* return_value) {
   return handle_return_value(m_interface_wrapper->func_3_0().C_MessageSignFinal(session), return_value);
}

/****************************** Functions for verifying signatures and MACs ******************************/

bool LowLevel::C_VerifyInit(SessionHandle session,
                            const Mechanism* mechanism_ptr,
                            ObjectHandle key,
                            ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_VerifyInit(session, const_cast<Mechanism*>(mechanism_ptr), key), return_value);
}

bool LowLevel::C_Verify(SessionHandle session,
                        const Byte* data_ptr,
                        Ulong data_len,
                        const Byte* signature_ptr,
                        Ulong signature_len,
                        ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_Verify(
         session, const_cast<Byte*>(data_ptr), data_len, const_cast<Byte*>(signature_ptr), signature_len),
      return_value);
}

bool LowLevel::C_VerifyUpdate(SessionHandle session,
                              const Byte* part_ptr,
                              Ulong part_len,
                              ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_VerifyUpdate(session, const_cast<Byte*>(part_ptr), part_len), return_value);
}

bool LowLevel::C_VerifyFinal(SessionHandle session,
                             const Byte* signature_ptr,
                             Ulong signature_len,
                             ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_VerifyFinal(session, const_cast<Byte*>(signature_ptr), signature_len),
      return_value);
}

bool LowLevel::C_VerifyRecoverInit(SessionHandle session,
                                   const Mechanism* mechanism_ptr,
                                   ObjectHandle key,
                                   ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_VerifyRecoverInit(session, const_cast<Mechanism*>(mechanism_ptr), key),
      return_value);
}

bool LowLevel::C_VerifyRecover(SessionHandle session,
                               const Byte* signature_ptr,
                               Ulong signature_len,
                               Byte* data_ptr,
                               Ulong* data_len_ptr,
                               ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_VerifyRecover(
                                 session, const_cast<Byte*>(signature_ptr), signature_len, data_ptr, data_len_ptr),
                              return_value);
}

bool LowLevel::C_VerifySignatureInit(SessionHandle session,
                                     const Mechanism* mechanism_ptr,
                                     ObjectHandle key,
                                     const Byte* signature_ptr,
                                     Ulong signature_len,
                                     ReturnValue* return_value) {
   return handle_return_value(
      m_interface_wrapper->func_3_2().C_VerifySignatureInit(
         session, const_cast<Mechanism*>(mechanism_ptr), key, const_cast<Byte*>(signature_ptr), signature_len),
      return_value);
}

bool LowLevel::C_VerifySignature(SessionHandle session,
                                 const Byte* data_ptr,
                                 Ulong data_len,
                                 ReturnValue* return_value) {
   return handle_return_value(
      m_interface_wrapper->func_3_2().C_VerifySignature(session, const_cast<Byte*>(data_ptr), data_len), return_value);
}

bool LowLevel::C_VerifySignatureUpdate(SessionHandle session,
                                       const Byte* part_ptr,
                                       Ulong part_len,
                                       ReturnValue* return_value) {
   return handle_return_value(
      m_interface_wrapper->func_3_2().C_VerifySignatureUpdate(session, const_cast<Byte*>(part_ptr), part_len),
      return_value);
}

bool LowLevel::C_VerifySignatureFinal(SessionHandle session, ReturnValue* return_value) {
   return handle_return_value(m_interface_wrapper->func_3_2().C_VerifySignatureFinal(session), return_value);
}

/*********** Message-based functions for verifying signatures and MACs ************/

bool LowLevel::C_MessageVerifyInit(SessionHandle session,
                                   const Mechanism* mechanism_ptr,
                                   ObjectHandle key,
                                   ReturnValue* return_value) {
   return handle_return_value(
      m_interface_wrapper->func_3_0().C_MessageVerifyInit(session, const_cast<Mechanism*>(mechanism_ptr), key),
      return_value);
}

bool LowLevel::C_VerifyMessage(SessionHandle session,
                               const void* parameter_ptr,
                               Ulong parameter_len,
                               const Byte* data_ptr,
                               Ulong data_len,
                               const Byte* signature_ptr,
                               Ulong signature_len,
                               ReturnValue* return_value) {
   return handle_return_value(m_interface_wrapper->func_3_0().C_VerifyMessage(session,
                                                                              const_cast<void*>(parameter_ptr),
                                                                              parameter_len,
                                                                              const_cast<Byte*>(data_ptr),
                                                                              data_len,
                                                                              const_cast<Byte*>(signature_ptr),
                                                                              signature_len),
                              return_value);
}

bool LowLevel::C_VerifyMessageBegin(SessionHandle session,
                                    const void* parameter_ptr,
                                    Ulong parameter_len,
                                    ReturnValue* return_value) {
   return handle_return_value(
      m_interface_wrapper->func_3_0().C_VerifyMessageBegin(session, const_cast<void*>(parameter_ptr), parameter_len),
      return_value);
}

bool LowLevel::C_VerifyMessageNext(SessionHandle session,
                                   const void* parameter_ptr,
                                   Ulong parameter_len,
                                   const Byte* data_ptr,
                                   Ulong data_len,
                                   const Byte* signature_ptr,
                                   Ulong signature_len,
                                   ReturnValue* return_value) {
   return handle_return_value(m_interface_wrapper->func_3_0().C_VerifyMessageNext(session,
                                                                                  const_cast<void*>(parameter_ptr),
                                                                                  parameter_len,
                                                                                  const_cast<Byte*>(data_ptr),
                                                                                  data_len,
                                                                                  const_cast<Byte*>(signature_ptr),
                                                                                  signature_len),
                              return_value);
}

bool LowLevel::C_MessageVerifyFinal(SessionHandle session, ReturnValue* return_value) {
   return handle_return_value(m_interface_wrapper->func_3_0().C_MessageVerifyFinal(session), return_value);
}

/****************************** Dual-purpose cryptographic functions ******************************/

bool LowLevel::C_DigestEncryptUpdate(SessionHandle session,
                                     const Byte* part_ptr,
                                     Ulong part_len,
                                     Byte* encrypted_part_ptr,
                                     Ulong* encrypted_part_len_ptr,
                                     ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_DigestEncryptUpdate(
         session, const_cast<Byte*>(part_ptr), part_len, encrypted_part_ptr, encrypted_part_len_ptr),
      return_value);
}

bool LowLevel::C_DecryptDigestUpdate(SessionHandle session,
                                     const Byte* encrypted_part_ptr,
                                     Ulong encrypted_part_len,
                                     Byte* part_ptr,
                                     Ulong* part_len_ptr,
                                     ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_DecryptDigestUpdate(
         session, const_cast<Byte*>(encrypted_part_ptr), encrypted_part_len, part_ptr, part_len_ptr),
      return_value);
}

bool LowLevel::C_SignEncryptUpdate(SessionHandle session,
                                   const Byte* part_ptr,
                                   Ulong part_len,
                                   Byte* encrypted_part_ptr,
                                   Ulong* encrypted_part_len_ptr,
                                   ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_SignEncryptUpdate(
         session, const_cast<Byte*>(part_ptr), part_len, encrypted_part_ptr, encrypted_part_len_ptr),
      return_value);
}

bool LowLevel::C_DecryptVerifyUpdate(SessionHandle session,
                                     const Byte* encrypted_part_ptr,
                                     Ulong encrypted_part_len,
                                     Byte* part_ptr,
                                     Ulong* part_len_ptr,
                                     ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_DecryptVerifyUpdate(
         session, const_cast<Byte*>(encrypted_part_ptr), encrypted_part_len, part_ptr, part_len_ptr),
      return_value);
}

/****************************** Key management functions ******************************/

bool LowLevel::C_GenerateKey(SessionHandle session,
                             const Mechanism* mechanism_ptr,
                             Attribute* attribute_template_ptr,
                             Ulong count,
                             ObjectHandle* key_ptr,
                             ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_GenerateKey(
         session, const_cast<Mechanism*>(mechanism_ptr), attribute_template_ptr, count, key_ptr),
      return_value);
}

bool LowLevel::C_GenerateKeyPair(SessionHandle session,
                                 const Mechanism* mechanism_ptr,
                                 Attribute* public_key_template_ptr,
                                 Ulong public_key_attribute_count,
                                 Attribute* private_key_template_ptr,
                                 Ulong private_key_attribute_count,
                                 ObjectHandle* public_key_ptr,
                                 ObjectHandle* private_key_ptr,
                                 ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_GenerateKeyPair(session,
                                                                                 const_cast<Mechanism*>(mechanism_ptr),
                                                                                 public_key_template_ptr,
                                                                                 public_key_attribute_count,
                                                                                 private_key_template_ptr,
                                                                                 private_key_attribute_count,
                                                                                 public_key_ptr,
                                                                                 private_key_ptr),
                              return_value);
}

bool LowLevel::C_WrapKey(SessionHandle session,
                         const Mechanism* mechanism_ptr,
                         ObjectHandle wrapping_key,
                         ObjectHandle key,
                         Byte* wrapped_key_ptr,
                         Ulong* wrapped_key_len_ptr,
                         ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_WrapKey(
         session, const_cast<Mechanism*>(mechanism_ptr), wrapping_key, key, wrapped_key_ptr, wrapped_key_len_ptr),
      return_value);
}

bool LowLevel::C_UnwrapKey(SessionHandle session,
                           const Mechanism* mechanism_ptr,
                           ObjectHandle unwrapping_key,
                           const Byte* wrapped_key_ptr,
                           Ulong wrapped_key_len,
                           Attribute* attribute_template_ptr,
                           Ulong attribute_count,
                           ObjectHandle* key_ptr,
                           ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_UnwrapKey(session,
                                                                           const_cast<Mechanism*>(mechanism_ptr),
                                                                           unwrapping_key,
                                                                           const_cast<Byte*>(wrapped_key_ptr),
                                                                           wrapped_key_len,
                                                                           attribute_template_ptr,
                                                                           attribute_count,
                                                                           key_ptr),
                              return_value);
}

bool LowLevel::C_DeriveKey(SessionHandle session,
                           const Mechanism* mechanism_ptr,
                           ObjectHandle base_key,
                           Attribute* attribute_template_ptr,
                           Ulong attribute_count,
                           ObjectHandle* key_ptr,
                           ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_DeriveKey(
         session, const_cast<Mechanism*>(mechanism_ptr), base_key, attribute_template_ptr, attribute_count, key_ptr),
      return_value);
}

bool LowLevel::C_EncapsulateKey(SessionHandle session,
                                const Mechanism* mechanism_ptr,
                                ObjectHandle public_key,
                                Attribute* template_ptr,
                                Ulong attribute_count,
                                ObjectHandle* key_ptr,
                                Byte* ciphertext_ptr,
                                Ulong* ciphertext_len_ptr,
                                ReturnValue* return_value) {
   return handle_return_value(m_interface_wrapper->func_3_2().C_EncapsulateKey(session,
                                                                               const_cast<Mechanism*>(mechanism_ptr),
                                                                               public_key,
                                                                               template_ptr,
                                                                               attribute_count,
                                                                               key_ptr,
                                                                               ciphertext_ptr,
                                                                               ciphertext_len_ptr),
                              return_value);
}

bool LowLevel::C_DecapsulateKey(SessionHandle session,
                                const Mechanism* mechanism_ptr,
                                ObjectHandle private_key,
                                const Byte* ciphertext_ptr,
                                Ulong ciphertext_len,
                                Attribute* template_ptr,
                                Ulong attribute_count,
                                ObjectHandle* key_ptr,
                                ReturnValue* return_value) {
   return handle_return_value(m_interface_wrapper->func_3_2().C_DecapsulateKey(session,
                                                                               const_cast<Mechanism*>(mechanism_ptr),
                                                                               private_key,
                                                                               const_cast<Byte*>(ciphertext_ptr),
                                                                               ciphertext_len,
                                                                               template_ptr,
                                                                               attribute_count,
                                                                               key_ptr),
                              return_value);
}

/****************************** Random number generation functions ******************************/

bool LowLevel::C_SeedRandom(SessionHandle session,
                            const Byte* seed_ptr,
                            Ulong seed_len,
                            ReturnValue* return_value) const {
   return handle_return_value(
      m_interface_wrapper->func_2_40().C_SeedRandom(session, const_cast<Byte*>(seed_ptr), seed_len), return_value);
}

bool LowLevel::C_GenerateRandom(SessionHandle session,
                                Byte* random_data_ptr,
                                Ulong random_len,
                                ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_GenerateRandom(session, random_data_ptr, random_len),
                              return_value);
}

/****************************** Parallel function management functions ******************************/

bool LowLevel::C_GetFunctionStatus(SessionHandle session, ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_GetFunctionStatus(session), return_value);
}

bool LowLevel::C_CancelFunction(SessionHandle session, ReturnValue* return_value) const {
   return handle_return_value(m_interface_wrapper->func_2_40().C_CancelFunction(session), return_value);
}

/******************* Asynchronous function management functions *******************/

bool LowLevel::C_AsyncComplete(SessionHandle session,
                               const Utf8Char* function_name_ptr,
                               AsyncData* result_ptr,
                               ReturnValue* return_value) {
   return handle_return_value(
      m_interface_wrapper->func_3_2().C_AsyncComplete(session, const_cast<Utf8Char*>(function_name_ptr), result_ptr),
      return_value);
}

bool LowLevel::C_AsyncGetID(SessionHandle session,
                            const Utf8Char* function_name_ptr,
                            Ulong* id_ptr,
                            ReturnValue* return_value) {
   return handle_return_value(
      m_interface_wrapper->func_3_2().C_AsyncGetID(session, const_cast<Utf8Char*>(function_name_ptr), id_ptr),
      return_value);
}

bool LowLevel::C_AsyncJoin(SessionHandle session,
                           const Utf8Char* function_name_ptr,
                           Ulong id,
                           Byte* data_ptr,
                           Ulong data_len,
                           ReturnValue* return_value) {
   return handle_return_value(m_interface_wrapper->func_3_2().C_AsyncJoin(
                                 session, const_cast<Utf8Char*>(function_name_ptr), id, data_ptr, data_len),
                              return_value);
}

FunctionList* LowLevel::get_functions() const {
   return reinterpret_cast<FunctionList*>(m_interface_wrapper->raw_interface().pFunctionList);
}

}  // namespace Botan::PKCS11
