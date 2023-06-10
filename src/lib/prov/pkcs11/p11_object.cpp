/*
* PKCS#11 Object
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/p11_object.h>
#include <map>

namespace Botan::PKCS11 {

AttributeContainer::AttributeContainer(ObjectClass object_class) {
   add_class(object_class);
}

void AttributeContainer::add_class(ObjectClass object_class) {
   m_numerics.emplace_back(static_cast<uint64_t>(object_class));
   add_attribute(
      AttributeType::Class, reinterpret_cast<uint8_t*>(&m_numerics.back()), static_cast<Ulong>(sizeof(ObjectClass)));
}

void AttributeContainer::add_string(AttributeType attribute, std::string_view value) {
   m_strings.push_back(std::string(value));
   add_attribute(
      attribute, reinterpret_cast<const uint8_t*>(m_strings.back().data()), static_cast<Ulong>(value.size()));
}

void AttributeContainer::add_binary(AttributeType attribute, const uint8_t* value, size_t length) {
   m_vectors.push_back(secure_vector<uint8_t>(value, value + length));
   add_attribute(attribute, reinterpret_cast<const uint8_t*>(m_vectors.back().data()), static_cast<Ulong>(length));
}

void AttributeContainer::add_bool(AttributeType attribute, bool value) {
   m_numerics.push_back(value ? True : False);
   add_attribute(attribute, reinterpret_cast<uint8_t*>(&m_numerics.back()), sizeof(Bbool));
}

void AttributeContainer::add_attribute(AttributeType attribute, const uint8_t* value, Ulong size) {
   bool exists = false;
   // check if the attribute has been added already
   for(auto& existing_attribute : m_attributes) {
      if(existing_attribute.type == static_cast<CK_ATTRIBUTE_TYPE>(attribute)) {
         // remove old entries
         m_strings.remove_if(
            [&existing_attribute](std::string_view data) { return data.data() == existing_attribute.pValue; });

         m_numerics.remove_if(
            [&existing_attribute](const uint64_t& data) { return &data == existing_attribute.pValue; });

         m_vectors.remove_if([&existing_attribute](const secure_vector<uint8_t>& data) {
            return data.data() == existing_attribute.pValue;
         });

         existing_attribute.pValue = const_cast<uint8_t*>(value);
         existing_attribute.ulValueLen = size;
         exists = true;
         break;
      }
   }

   if(!exists) {
      m_attributes.push_back(Attribute{static_cast<CK_ATTRIBUTE_TYPE>(attribute), const_cast<uint8_t*>(value), size});
   }
}

// ====================================================================================================

ObjectFinder::ObjectFinder(Session& session, const std::vector<Attribute>& search_template) :
      m_session(session), m_search_terminated(false) {
   module()->C_FindObjectsInit(m_session.get().handle(),
                               const_cast<Attribute*>(search_template.data()),
                               static_cast<Ulong>(search_template.size()));
}

ObjectFinder::~ObjectFinder() noexcept {
   try {
      if(m_search_terminated == false) {
         module()->C_FindObjectsFinal(m_session.get().handle(), nullptr);
      }
   } catch(...) {
      // ignore error during noexcept function
   }
}

std::vector<ObjectHandle> ObjectFinder::find(uint32_t max_count) const {
   std::vector<ObjectHandle> result(max_count);
   Ulong objectCount = 0;
   module()->C_FindObjects(m_session.get().handle(), result.data(), max_count, &objectCount);
   if(objectCount < max_count) {
      result.resize(objectCount);
   }
   return result;
}

void ObjectFinder::finish() {
   module()->C_FindObjectsFinal(m_session.get().handle());
   m_search_terminated = true;
}

// ====================================================================================================

ObjectProperties::ObjectProperties(ObjectClass object_class) :
      AttributeContainer(object_class), m_object_class(object_class) {}

// ====================================================================================================

StorageObjectProperties::StorageObjectProperties(ObjectClass object_class) : ObjectProperties(object_class) {}

// ====================================================================================================

DataObjectProperties::DataObjectProperties() : StorageObjectProperties(ObjectClass::Data) {}

// ====================================================================================================

CertificateProperties::CertificateProperties(CertificateType cert_type) :
      StorageObjectProperties(ObjectClass::Certificate), m_cert_type(cert_type) {
   add_numeric(AttributeType::CertificateType, static_cast<CK_CERTIFICATE_TYPE>(m_cert_type));
}

// ====================================================================================================

KeyProperties::KeyProperties(ObjectClass object_class, KeyType key_type) :
      StorageObjectProperties(object_class), m_key_type(key_type) {
   add_numeric(AttributeType::KeyType, static_cast<CK_ULONG>(m_key_type));
}

// ====================================================================================================

PublicKeyProperties::PublicKeyProperties(KeyType key_type) : KeyProperties(ObjectClass::PublicKey, key_type) {}

// ====================================================================================================

PrivateKeyProperties::PrivateKeyProperties(KeyType key_type) : KeyProperties(ObjectClass::PrivateKey, key_type) {}

// ====================================================================================================

SecretKeyProperties::SecretKeyProperties(KeyType key_type) : KeyProperties(ObjectClass::SecretKey, key_type) {}

// ====================================================================================================

DomainParameterProperties::DomainParameterProperties(KeyType key_type) :
      StorageObjectProperties(ObjectClass::DomainParameters), m_key_type(key_type) {
   add_numeric(AttributeType::KeyType, static_cast<CK_ULONG>(m_key_type));
}

// ====================================================================================================

Object::Object(Session& session, ObjectHandle handle) : m_session(session), m_handle(handle) {}

Object::Object(Session& session, const ObjectProperties& obj_props) : m_session(session), m_handle(0) {
   m_session.get().module()->C_CreateObject(
      m_session.get().handle(), obj_props.data(), static_cast<Ulong>(obj_props.count()), &m_handle);
}

secure_vector<uint8_t> Object::get_attribute_value(AttributeType attribute) const {
   std::map<AttributeType, secure_vector<uint8_t>> attribute_map = {{attribute, secure_vector<uint8_t>()}};
   module()->C_GetAttributeValue(m_session.get().handle(), m_handle, attribute_map);
   return attribute_map.at(attribute);
}

void Object::set_attribute_value(AttributeType attribute, const secure_vector<uint8_t>& value) const {
   std::map<AttributeType, secure_vector<uint8_t>> attribute_map = {{attribute, value}};
   module()->C_SetAttributeValue(m_session.get().handle(), m_handle, attribute_map);
}

void Object::destroy() const {
   module()->C_DestroyObject(m_session.get().handle(), m_handle);
}

ObjectHandle Object::copy(const AttributeContainer& modified_attributes) const {
   ObjectHandle copied_handle;
   module()->C_CopyObject(m_session.get().handle(),
                          m_handle,
                          modified_attributes.data(),
                          static_cast<Ulong>(modified_attributes.count()),
                          &copied_handle);
   return copied_handle;
}
}  // namespace Botan::PKCS11
