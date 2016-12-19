/*
* (C) 2016 Daniel Neus
* (C) 2016 Philipp Weber
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include "tests.h"
#include "test_pkcs11.h"

#include <string>
#include <vector>
#include <functional>
#include <memory>
#include <array>
#include <type_traits>
#include <map>

#if defined(BOTAN_HAS_PKCS11)
  #include <botan/p11.h>
#endif

#if defined(BOTAN_HAS_DYNAMIC_LOADER)
  #include <botan/dyn_load.h>
#endif

namespace Botan_Tests {

namespace {

#if defined(BOTAN_HAS_PKCS11)
#if defined(BOTAN_HAS_DYNAMIC_LOADER)

using namespace Botan;
using namespace PKCS11;

class RAII_LowLevel {
public:
  RAII_LowLevel() : m_module(Test::pkcs11_lib()), m_func_list(nullptr), m_low_level(), m_session_handle(0),
    m_is_session_open(false), m_is_logged_in(false) {
    LowLevel::C_GetFunctionList(m_module, &m_func_list);
    m_low_level.reset(new LowLevel(m_func_list));

    C_InitializeArgs init_args = { nullptr, nullptr, nullptr, nullptr, static_cast<CK_FLAGS>(Flag::OsLockingOk), nullptr };

    m_low_level->C_Initialize(&init_args);
  }
  ~RAII_LowLevel() BOTAN_NOEXCEPT {

    if (m_is_session_open) {
      if (m_is_logged_in) {
        m_low_level.get()->C_Logout(m_session_handle, nullptr);
      }

      m_low_level.get()->C_CloseSession(m_session_handle, nullptr);
    }

    m_low_level.get()->C_Finalize(nullptr, nullptr);
  }

  std::vector<SlotId> get_slots(bool token_present) const {
    std::vector<SlotId> slots;
    m_low_level.get()->C_GetSlotList(token_present, slots);

    if (slots.empty()) {
      throw Exception("No slot with attached token found");
    }

    return slots;
  }

  inline SessionHandle open_session(Flags session_flags) {
    std::vector<SlotId> slots = get_slots(true);
    m_low_level.get()->C_OpenSession(slots.at(0), session_flags, nullptr, nullptr, &m_session_handle);
    m_is_session_open = true;
    return m_session_handle;
  }

  inline SessionHandle open_rw_session_with_user_login() {
    Flags session_flags =  PKCS11::flags(Flag::SerialSession | Flag::RwSession);
    SessionHandle handle = open_session(session_flags);
    login(UserType::User, PIN_SECVEC);
    return handle;
  }

  inline SessionHandle get_session_handle() const {
    if (!m_is_session_open) {
      throw Exception("no open session");
    }
    return m_session_handle;
  }

  inline void close_session() {
    if (!m_is_session_open) {
      throw Exception("no open session");
    }

    m_low_level.get()->C_CloseSession(m_session_handle);
    m_is_session_open = false;
  }

  inline void login(UserType user_type, const secure_vector<uint8_t>& pin) {
    if (!m_is_session_open) {
      throw Exception("no open session");
    }

    if (m_is_logged_in) {
      throw Exception("Already logged in");
    }

    m_low_level.get()->C_Login(m_session_handle, user_type, pin);
    m_is_logged_in = true;
  }

  inline void logout() {
    if (!m_is_logged_in) {
      throw Exception("Not logged in");
    }

    m_low_level.get()->C_Logout(m_session_handle);
    m_is_logged_in = false;
  }

  LowLevel* get() const {
    return m_low_level.get();
  }
private:
  Dynamically_Loaded_Library m_module;
  FunctionListPtr m_func_list;
  std::unique_ptr<LowLevel> m_low_level;
  SessionHandle m_session_handle;
  bool m_is_session_open;
  bool m_is_logged_in;
};

bool no_op(ReturnValue*) {
  return true;
}

using PKCS11_BoundTestFunction = std::function<bool(ReturnValue* return_value)>;

// tests all 3 variants
Test::Result test_function(const std::string& name, const PKCS11_BoundTestFunction& test_func,
                           const std::string& revert_fn_name, const PKCS11_BoundTestFunction& revert_func,
                           bool expect_failure, ReturnValue expected_return_value) {
  std::string test_name = revert_fn_name.empty() ? "PKCS 11 low level - " + name : "PKCS 11 low level - " + name + "/" +
                          revert_fn_name;
  Test::Result result(test_name);

  // test throw variant
  if (expect_failure) {
    result.test_throws(name + " fails as expected", [ test_func ]() {
      test_func(ThrowException);
    });
  }
  else {
    test_func(ThrowException);
    result.test_success(name + " did not throw and completed successfully");

    if (!revert_fn_name.empty()) {
      revert_func(ThrowException);
      result.test_success(revert_fn_name + " did not throw and completed successfully");
    }
  }

  // test bool return variant
  bool success = test_func(nullptr);
  result.test_eq(name, success, !expect_failure);
  if (success && !revert_fn_name.empty()) {
    success = revert_func(nullptr);
    result.test_eq(revert_fn_name, success, !expect_failure);
  }

  // test ReturnValue variant
  ReturnValue rv;
  success = test_func(&rv);
  result.test_eq(name, success, !expect_failure);
  if (!expect_failure) {
    result.test_rc_ok(name, static_cast< uint32_t >(rv));
  }
  else {
    result.test_rc_fail(name, "return value should be: " + std::to_string(static_cast< uint32_t >(expected_return_value)),
                        static_cast< uint32_t >(rv));
  }

  if (success && !revert_fn_name.empty()) {
    success = revert_func(&rv);
    result.test_eq(revert_fn_name, success, !expect_failure);
    result.test_rc_ok(revert_fn_name, static_cast< uint32_t >(rv));
  }

  return result;
}

Test::Result test_function(const std::string& name, const PKCS11_BoundTestFunction& test_func,
                           bool expect_failure, ReturnValue expected_return_value) {
  return test_function(name, test_func, std::string(), no_op, expect_failure, expected_return_value);
}

Test::Result test_function(const std::string& name, const PKCS11_BoundTestFunction& test_func) {
  return test_function(name, test_func, std::string(), no_op, false, ReturnValue::OK);
}

Test::Result test_function(const std::string& name, const PKCS11_BoundTestFunction& test_func,
                           const std::string& revert_fn_name, const PKCS11_BoundTestFunction& revert_func) {
  return test_function(name, test_func, revert_fn_name, revert_func, false, ReturnValue::OK);
}

Test::Result test_low_level_ctor() {
  Test::Result result("PKCS 11 low level - LowLevel ctor");

  Dynamically_Loaded_Library pkcs11_module(Test::pkcs11_lib());
  FunctionListPtr func_list(nullptr);
  LowLevel::C_GetFunctionList(pkcs11_module, &func_list);

  LowLevel p11_low_level(func_list);
  result.test_success("LowLevel ctor does complete for valid function list");

  result.test_throws("LowLevel ctor fails for invalid function list pointer", []() {
    LowLevel p11_low_level2(nullptr);
  });

  return result;
}

Test::Result test_c_get_function_list() {
  Dynamically_Loaded_Library pkcs11_module(Test::pkcs11_lib());
  FunctionListPtr func_list = nullptr;
  return test_function("C_GetFunctionList", std::bind(&LowLevel::C_GetFunctionList, std::ref(pkcs11_module), &func_list,
                       std::placeholders::_1));
}

Test::Result test_initialize_finalize() {
  Dynamically_Loaded_Library pkcs11_module(Test::pkcs11_lib());
  FunctionListPtr func_list = nullptr;
  LowLevel::C_GetFunctionList(pkcs11_module, &func_list);

  LowLevel p11_low_level(func_list);

  // setting Flag::OsLockingOk should be the normal use case
  C_InitializeArgs init_args = { nullptr, nullptr, nullptr, nullptr, static_cast<CK_FLAGS>(Flag::OsLockingOk), nullptr };

  auto init_bind = std::bind(&LowLevel::C_Initialize, p11_low_level, &init_args, std::placeholders::_1);
  auto finalize_bind = std::bind(&LowLevel::C_Finalize, p11_low_level, nullptr, std::placeholders::_1);
  return test_function("C_Initialize", init_bind, "C_Finalize", finalize_bind);
}

Test::Result test_c_get_info() {
  RAII_LowLevel p11_low_level;

  Info info = {};
  Test::Result result = test_function("C_GetInfo", std::bind(&LowLevel::C_GetInfo, *p11_low_level.get(), &info,
                                      std::placeholders::_1));
  result.test_ne("C_GetInfo crypto major version", info.cryptokiVersion.major, 0);

  return result;
}

Test::Result test_c_get_slot_list() {
  RAII_LowLevel p11_low_level;

  std::vector<SlotId> slot_vec;

  // assumes at least one smartcard reader is attached
  bool token_present = false;

  auto binder = std::bind(static_cast< bool (LowLevel::*)(bool, std::vector<SlotId>&, ReturnValue*) const>
                          (&LowLevel::C_GetSlotList), *p11_low_level.get(), std::ref(token_present), std::ref(slot_vec), std::placeholders::_1);

  Test::Result result = test_function("C_GetSlotList", binder);
  result.test_ne("C_GetSlotList number of slots without attached token > 0", slot_vec.size(), 0);

  // assumes at least one smartcard reader with connected smartcard is attached
  slot_vec.clear();
  token_present = true;
  result.merge(test_function("C_GetSlotList", binder));
  result.test_ne("C_GetSlotList number of slots with attached token > 0", slot_vec.size(), 0);

  return result;
}

Test::Result test_c_get_slot_info() {
  RAII_LowLevel p11_low_level;
  std::vector<SlotId> slot_vec = p11_low_level.get_slots(false);

  SlotInfo slot_info = {};
  Test::Result result = test_function("C_GetSlotInfo", std::bind(&LowLevel::C_GetSlotInfo, *p11_low_level.get(),
                                      slot_vec.at(0), &slot_info, std::placeholders::_1));

  std::string slot_desc(reinterpret_cast< char* >(slot_info.slotDescription));
  result.test_ne("C_GetSlotInfo returns non empty description", slot_desc.size(), 0);

  return result;
}

Test::Result test_c_get_token_info() {
  RAII_LowLevel p11_low_level;
  std::vector<SlotId> slot_vec = p11_low_level.get_slots(true);

  TokenInfo token_info = {};
  Test::Result result = test_function("C_GetTokenInfo", std::bind(&LowLevel::C_GetTokenInfo, *p11_low_level.get(),
                                      slot_vec.at(0), &token_info, std::placeholders::_1));

  std::string serial(reinterpret_cast< char* >(token_info.serialNumber));
  result.test_ne("C_GetTokenInfo returns non empty serial number", serial.size(), 0);

  return result;
}

Test::Result test_c_wait_for_slot_event() {
  RAII_LowLevel p11_low_level;

  Flags flags = PKCS11::flags(Flag::DontBlock);
  SlotId slot_id = 0;

  return test_function("C_WaitForSlotEvent", std::bind(&LowLevel::C_WaitForSlotEvent, *p11_low_level.get(),
                       flags, &slot_id, nullptr, std::placeholders::_1), true, ReturnValue::NoEvent);
}

Test::Result test_c_get_mechanism_list() {
  RAII_LowLevel p11_low_level;
  std::vector<SlotId> slot_vec = p11_low_level.get_slots(true);

  std::vector<MechanismType> mechanisms;

  auto binder = std::bind(static_cast< bool (LowLevel::*)(SlotId, std::vector<MechanismType>&, ReturnValue*) const>
                          (&LowLevel::C_GetMechanismList), *p11_low_level.get(), slot_vec.at(0), std::ref(mechanisms), std::placeholders::_1);

  Test::Result result = test_function("C_GetMechanismList", binder);
  result.confirm("C_GetMechanismList returns non empty mechanisms list", !mechanisms.empty());

  return result;
}

Test::Result test_c_get_mechanism_info() {
  RAII_LowLevel p11_low_level;
  std::vector<SlotId> slot_vec = p11_low_level.get_slots(true);

  std::vector<MechanismType> mechanisms;
  p11_low_level.get()->C_GetMechanismList(slot_vec.at(0), mechanisms);

  MechanismInfo mechanism_info = {};
  return test_function("C_GetMechanismInfo", std::bind(&LowLevel::C_GetMechanismInfo, *p11_low_level.get(),
                       slot_vec.at(0), mechanisms.at(0), &mechanism_info, std::placeholders::_1));
}

Test::Result test_c_init_token() {
  RAII_LowLevel p11_low_level;
  std::vector<SlotId> slot_vec = p11_low_level.get_slots(true);

  const std::string label = "Botan PKCS#11 tests";

  auto sec_vec_binder = std::bind(
                          static_cast< bool (LowLevel::*)(SlotId, const secure_vector<uint8_t>&, const std::string&, ReturnValue*) const>
                          (&LowLevel::C_InitToken<secure_allocator<uint8_t>>), *p11_low_level.get(), slot_vec.at(0), std::ref(SO_PIN_SECVEC),
                          std::ref(label), std::placeholders::_1);

  return test_function("C_InitToken", sec_vec_binder);
}

Test::Result test_open_close_session() {
  RAII_LowLevel p11_low_level;
  std::vector<SlotId> slot_vec = p11_low_level.get_slots(true);

  // public read only session
  Flags flags = PKCS11::flags(Flag::SerialSession);
  SessionHandle session_handle = 0;

  auto open_session_bind = std::bind(&LowLevel::C_OpenSession, *p11_low_level.get(),
                                     slot_vec.at(0), std::ref(flags), nullptr, nullptr, &session_handle, std::placeholders::_1);

  auto close_session_bind = std::bind(&LowLevel::C_CloseSession, *p11_low_level.get(),
                                      std::ref(session_handle), std::placeholders::_1);

  Test::Result result = test_function("C_OpenSession", open_session_bind, "C_CloseSession", close_session_bind);

  // public read write session
  flags = PKCS11::flags(Flag::SerialSession | Flag::RwSession);
  result.merge(test_function("C_OpenSession", open_session_bind, "C_CloseSession", close_session_bind));

  return result;
}

Test::Result test_c_close_all_sessions() {
  RAII_LowLevel p11_low_level;
  std::vector<SlotId> slot_vec = p11_low_level.get_slots(true);

  auto open_two_sessions = [ &slot_vec, &p11_low_level ]() -> void {
    // public read only session
    Flags flags = PKCS11::flags(Flag::SerialSession);
    SessionHandle first_session_handle = 0, second_session_handle = 0;

    p11_low_level.get()->C_OpenSession(slot_vec.at(0), flags, nullptr, nullptr, &first_session_handle);

    flags = PKCS11::flags(Flag::SerialSession | Flag::RwSession);
    p11_low_level.get()->C_OpenSession(slot_vec.at(0), flags, nullptr, nullptr, &second_session_handle);
  };

  open_two_sessions();

  Test::Result result("PKCS 11 low level - C_CloseAllSessions");

  // test throw variant
  p11_low_level.get()->C_CloseAllSessions(slot_vec.at(0));
  result.test_success("C_CloseAllSessions does not throw");

  // test bool return variant
  open_two_sessions();

  bool success = p11_low_level.get()->C_CloseAllSessions(slot_vec.at(0), nullptr);
  result.test_eq("C_CloseAllSessions", success, true);

  // test ReturnValue variant
  open_two_sessions();

  ReturnValue rv = static_cast< ReturnValue >(-1);
  success = p11_low_level.get()->C_CloseAllSessions(slot_vec.at(0), &rv);
  result.test_eq("C_CloseAllSessions", success, true);
  result.test_rc_ok("C_CloseAllSessions", static_cast< uint32_t >(rv));

  return result;
}

Test::Result test_c_get_session_info() {
  RAII_LowLevel p11_low_level;
  std::vector<SlotId> slot_vec = p11_low_level.get_slots(true);

  // public read only session
  Flags flags = PKCS11::flags(Flag::SerialSession);
  SessionHandle session_handle = p11_low_level.open_session(flags);

  SessionInfo session_info = {};
  Test::Result result = test_function("C_GetSessionInfo", std::bind(&LowLevel::C_GetSessionInfo, *p11_low_level.get(),
                                      session_handle, &session_info, std::placeholders::_1));

  result.confirm("C_GetSessionInfo returns same slot id as during call to C_OpenSession",
                 session_info.slotID == slot_vec.at(0));
  result.confirm("C_GetSessionInfo returns same flags as during call to C_OpenSession", session_info.flags == flags);
  result.confirm("C_GetSessionInfo returns public read only session state",
                 session_info.state == static_cast<CK_FLAGS>(SessionState::RoPublicSession));

  return result;
}

Test::Result login_logout_helper(const RAII_LowLevel& p11_low_level, SessionHandle handle, UserType user_type,
                                 const std::string& pin) {
  secure_vector<uint8_t> pin_as_sec_vec(pin.begin(), pin.end());

  auto login_secvec_binder = std::bind(static_cast< bool (LowLevel::*)(SessionHandle, UserType,
                                       const secure_vector<uint8_t>&, ReturnValue*) const>
                                       (&LowLevel::C_Login<secure_allocator<uint8_t>>), *p11_low_level.get(),
                                       handle, user_type, std::ref(pin_as_sec_vec), std::placeholders::_1);

  auto logout_binder = std::bind(static_cast< bool (LowLevel::*)(SessionHandle, ReturnValue*) const>
                                 (&LowLevel::C_Logout), *p11_low_level.get(), handle, std::placeholders::_1);

  return test_function("C_Login", login_secvec_binder, "C_Logout", logout_binder);
}

Test::Result test_c_login_logout_security_officier() {
  RAII_LowLevel p11_low_level;

  // can only login to R/W session
  Flags session_flags = PKCS11::flags(Flag::SerialSession | Flag::RwSession);
  SessionHandle session_handle = p11_low_level.open_session(session_flags);

  return login_logout_helper(p11_low_level, session_handle, UserType::SO, SO_PIN);
}

Test::Result test_c_login_logout_user() {
  RAII_LowLevel p11_low_level;

  // R/O session
  Flags session_flags = PKCS11::flags(Flag::SerialSession);
  SessionHandle session_handle = p11_low_level.open_session(session_flags);
  Test::Result result = login_logout_helper(p11_low_level, session_handle, UserType::User, PIN);
  p11_low_level.close_session();

  // R/W session
  session_flags = PKCS11::flags(Flag::SerialSession | Flag::RwSession);
  session_handle = p11_low_level.open_session(session_flags);

  result.merge(login_logout_helper(p11_low_level, session_handle, UserType::User, PIN));

  return result;
}

Test::Result test_c_init_pin() {
  RAII_LowLevel p11_low_level;

  // C_InitPIN can only be called in the "R/W SO Functions" state
  Flags session_flags = PKCS11::flags(Flag::SerialSession | Flag::RwSession);
  SessionHandle session_handle = p11_low_level.open_session(session_flags);

  p11_low_level.login(UserType::SO, SO_PIN_SECVEC);

  auto sec_vec_binder = std::bind(
                          static_cast< bool (LowLevel::*)(SessionHandle, const secure_vector<uint8_t>&, ReturnValue*) const>
                          (&LowLevel::C_InitPIN<secure_allocator<uint8_t>>), *p11_low_level.get(), session_handle, std::ref(PIN_SECVEC),
                          std::placeholders::_1);

  return test_function("C_InitPIN", sec_vec_binder);
}

Test::Result test_c_set_pin() {
  RAII_LowLevel p11_low_level;

  // C_SetPIN can only be called in the "R / W Public Session" state, "R / W SO Functions" state, or "R / W User Functions" state
  Flags session_flags = PKCS11::flags(Flag::SerialSession | Flag::RwSession);
  SessionHandle session_handle = p11_low_level.open_session(session_flags);

  // now we are in "R / W Public Session" state: this will change the pin of the user

  auto get_pin_bind = [ &session_handle, &p11_low_level ](const secure_vector<uint8_t>& old_pin,
  const secure_vector<uint8_t>& new_pin) -> PKCS11_BoundTestFunction {
    return std::bind(static_cast< bool (LowLevel::*)(SessionHandle, const secure_vector<uint8_t>&,
    const secure_vector<uint8_t>&, ReturnValue*) const>
    (&LowLevel::C_SetPIN<secure_allocator<uint8_t>>), *p11_low_level.get(), session_handle,
    old_pin, new_pin, std::placeholders::_1);
  };

  const std::string test_pin("654321");
  const auto test_pin_secvec = secure_vector<uint8_t>(test_pin.begin(), test_pin.end());

  PKCS11_BoundTestFunction set_pin_bind = get_pin_bind(PIN_SECVEC, test_pin_secvec);
  PKCS11_BoundTestFunction revert_pin_bind = get_pin_bind(test_pin_secvec, PIN_SECVEC);

  Test::Result result = test_function("C_SetPIN", set_pin_bind, "C_SetPIN", revert_pin_bind);

  // change pin in "R / W User Functions" state
  p11_low_level.login(UserType::User, PIN_SECVEC);

  result.merge(test_function("C_SetPIN", set_pin_bind, "C_SetPIN", revert_pin_bind));
  p11_low_level.logout();

  // change so_pin in "R / W SO Functions" state
  const std::string test_so_pin = "87654321";
  secure_vector<uint8_t> test_so_pin_secvec(test_so_pin.begin(), test_so_pin.end());
  p11_low_level.login(UserType::SO, SO_PIN_SECVEC);

  PKCS11_BoundTestFunction set_so_pin_bind = get_pin_bind(SO_PIN_SECVEC, test_so_pin_secvec);
  PKCS11_BoundTestFunction revert_so_pin_bind = get_pin_bind(test_so_pin_secvec, SO_PIN_SECVEC);

  result.merge(test_function("C_SetPIN", set_so_pin_bind, "C_SetPIN", revert_so_pin_bind));

  return result;
}

// Simple data object
ObjectClass object_class = ObjectClass::Data;
std::string label = "A data object";
std::string data = "Sample data";
Bbool btrue = True;

std::array<Attribute, 4> dtemplate = {
  {
    { static_cast<CK_ATTRIBUTE_TYPE>(AttributeType::Class), &object_class, sizeof(object_class) },
    { static_cast<CK_ATTRIBUTE_TYPE>(AttributeType::Token), &btrue, sizeof(btrue) },
    { static_cast<CK_ATTRIBUTE_TYPE>(AttributeType::Label), const_cast< char* >(label.c_str()), label.size() },
    { static_cast<CK_ATTRIBUTE_TYPE>(AttributeType::Value), const_cast< char* >(data.c_str()), data.size() }
  }
};

ObjectHandle create_simple_data_object(const RAII_LowLevel& p11_low_level) {
  ObjectHandle object_handle;
  p11_low_level.get()->C_CreateObject(p11_low_level.get_session_handle(), dtemplate.data(), dtemplate.size(),
                                      &object_handle);
  return object_handle;
}

Test::Result test_c_create_object_c_destroy_object() {
  RAII_LowLevel p11_low_level;
  SessionHandle session_handle = p11_low_level.open_rw_session_with_user_login();

  ObjectHandle object_handle(0);

  auto create_bind = std::bind(&LowLevel::C_CreateObject, *p11_low_level.get(),
                               session_handle, dtemplate.data(), dtemplate.size(), &object_handle, std::placeholders::_1);

  auto destroy_bind = std::bind(&LowLevel::C_DestroyObject, *p11_low_level.get(), session_handle,
                                std::ref(object_handle), std::placeholders::_1);

  return test_function("C_CreateObject", create_bind, "C_DestroyObject", destroy_bind);
}

Test::Result test_c_get_object_size() {
  RAII_LowLevel p11_low_level;

  Flags session_flags = PKCS11::flags(Flag::SerialSession | Flag::RwSession);
  SessionHandle session_handle = p11_low_level.open_session(session_flags);

  p11_low_level.login(UserType::User, PIN_SECVEC);

  ObjectHandle object_handle = create_simple_data_object(p11_low_level);
  Ulong object_size = 0;

  auto bind = std::bind(&LowLevel::C_GetObjectSize, *p11_low_level.get(),
                        session_handle, object_handle, &object_size, std::placeholders::_1);

  Test::Result result = test_function("C_GetObjectSize", bind);
  result.test_ne("Object size", object_size, 0);

  // cleanup
  p11_low_level.get()->C_DestroyObject(session_handle, object_handle);

  return result;
}

Test::Result test_c_get_attribute_value() {
  RAII_LowLevel p11_low_level;
  SessionHandle session_handle = p11_low_level.open_rw_session_with_user_login();

  ObjectHandle object_handle = create_simple_data_object(p11_low_level);

  std::map < AttributeType, secure_vector<uint8_t>> getter = {
    { AttributeType::Label, secure_vector<uint8_t>() },
    { AttributeType::Value, secure_vector<uint8_t>() }
  };

  auto bind = std::bind(static_cast< bool (LowLevel::*)(SessionHandle, ObjectHandle,
                        std::map<AttributeType, secure_vector<uint8_t>>&, ReturnValue*) const>
                        (&LowLevel::C_GetAttributeValue<secure_allocator<uint8_t>>), *p11_low_level.get(), session_handle,
                        object_handle, std::ref(getter), std::placeholders::_1);

  Test::Result result = test_function("C_GetAttributeValue", bind);

  std::string _label(getter[ AttributeType::Label ].begin(), getter[ AttributeType::Label ].end());
  std::string value(getter[ AttributeType::Value ].begin(), getter[ AttributeType::Value ].end());
  result.test_eq("label", _label, "A data object");
  result.test_eq("value", value, "Sample data");

  // cleanup
  p11_low_level.get()->C_DestroyObject(session_handle, object_handle);

  return result;
}

std::map < AttributeType, std::vector<uint8_t>> get_attribute_values(const RAII_LowLevel& p11_low_level,
    SessionHandle session_handle,
ObjectHandle object_handle, const std::vector<AttributeType>& attribute_types) {
  std::map < AttributeType, std::vector<uint8_t>> received_attributes;

  for (const auto& type : attribute_types) {
    received_attributes.emplace(type, std::vector<uint8_t>());
  }

  p11_low_level.get()->C_GetAttributeValue(session_handle, object_handle, received_attributes);

  return received_attributes;
}

Test::Result test_c_set_attribute_value() {
  RAII_LowLevel p11_low_level;

  Flags session_flags = PKCS11::flags(Flag::SerialSession | Flag::RwSession);
  SessionHandle session_handle = p11_low_level.open_session(session_flags);

  p11_low_level.login(UserType::User, PIN_SECVEC);

  ObjectHandle object_handle = create_simple_data_object(p11_low_level);

  std::string new_label = "A modified data object";

  std::map < AttributeType, secure_vector<uint8_t>> new_attributes = {
    { AttributeType::Label, secure_vector<uint8_t>(new_label.begin(), new_label.end()) }
  };

  auto bind = std::bind(static_cast< bool (LowLevel::*)(SessionHandle, ObjectHandle,
                        std::map<AttributeType, secure_vector<uint8_t>>&, ReturnValue*) const>
                        (&LowLevel::C_SetAttributeValue<secure_allocator<uint8_t>>), *p11_low_level.get(), session_handle,
                        object_handle, std::ref(new_attributes), std::placeholders::_1);

  Test::Result result = test_function("C_SetAttributeValue", bind);

  // get attributes and check if they are changed correctly
  std::vector<AttributeType> types = { AttributeType::Label, AttributeType::Value };
  auto received_attributes = get_attribute_values(p11_low_level, session_handle, object_handle, types);

  std::string retrieved_label(received_attributes[ AttributeType::Label ].begin(),
                              received_attributes[ AttributeType::Label ].end());

  result.test_eq("label", new_label, retrieved_label);

  // cleanup
  p11_low_level.get()->C_DestroyObject(session_handle, object_handle);

  return result;
}

Test::Result test_c_copy_object() {
  RAII_LowLevel p11_low_level;
  SessionHandle session_handle = p11_low_level.open_rw_session_with_user_login();

  ObjectHandle object_handle = create_simple_data_object(p11_low_level);
  ObjectHandle copied_object_handle = 0;

  std::string copied_label = "A copied data object";

  Attribute copy_attribute_values = { static_cast< CK_ATTRIBUTE_TYPE >(AttributeType::Label), const_cast< char* >(copied_label.c_str()), copied_label.size() };

  auto binder = std::bind(&LowLevel::C_CopyObject, *p11_low_level.get(), session_handle, object_handle,
                          &copy_attribute_values, 1, &copied_object_handle, std::placeholders::_1);

  Test::Result result = test_function("C_CopyObject", binder);

  // get attributes and check if its copied correctly
  std::vector<AttributeType> types = { AttributeType::Label, AttributeType::Value };
  auto received_attributes = get_attribute_values(p11_low_level, session_handle, copied_object_handle, types);

  std::string retrieved_label(received_attributes[ AttributeType::Label ].begin(),
                              received_attributes[ AttributeType::Label ].end());

  result.test_eq("label", copied_label, retrieved_label);

  // cleanup
  p11_low_level.get()->C_DestroyObject(session_handle, object_handle);
  p11_low_level.get()->C_DestroyObject(session_handle, copied_object_handle);

  return result;
}

class LowLevelTests : public Test {
public:
  std::vector<Test::Result> run() override {
    std::vector<Test::Result> results;

    std::vector<std::function<Test::Result()>> fns = {
      test_c_get_function_list
      ,test_low_level_ctor
      ,test_initialize_finalize
      ,test_c_get_info
      ,test_c_get_slot_list
      ,test_c_get_slot_info
      ,test_c_get_token_info
      ,test_c_wait_for_slot_event
      ,test_c_get_mechanism_list
      ,test_c_get_mechanism_info
      ,test_open_close_session
      ,test_c_close_all_sessions
      ,test_c_get_session_info
      ,test_c_init_token
      ,test_c_login_logout_security_officier  /* only possible if token is initialized */
      ,test_c_init_pin
      ,test_c_login_logout_user /* only possible if token is initialized and user pin is set */
      ,test_c_set_pin
      ,test_c_create_object_c_destroy_object
      ,test_c_get_object_size
      ,test_c_get_attribute_value
      ,test_c_set_attribute_value
      ,test_c_copy_object
    };

    for (size_t i = 0; i != fns.size(); ++i) {
      try {
        results.push_back(fns[ i ]());
      }
      catch (PKCS11_ReturnError& e) {
        results.push_back(Test::Result::Failure("PKCS11 low level test " + std::to_string(i), e.what()));

        if (e.get_return_value() == ReturnValue::PinIncorrect) {
          break; // Do not continue to not potentially lock the token
        }
      }
      catch (std::exception& e) {
        results.push_back(Test::Result::Failure("PKCS11 low level test " + std::to_string(i), e.what()));
      }
    }

    return results;
  }
};

BOTAN_REGISTER_TEST("pkcs11-lowlevel", LowLevelTests);

#endif
#endif

}
}
