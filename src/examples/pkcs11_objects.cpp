#include <botan/der_enc.h>
#include <botan/p11.h>
#include <botan/p11_object.h>
#include <botan/p11_types.h>
#include <botan/secmem.h>

#include <cstddef>
#include <string>
#include <vector>

int main() {
   Botan::PKCS11::Module module("C:\\pkcs11-middleware\\library.dll");
   // open write session to first slot with connected token
   std::vector<Botan::PKCS11::SlotId> slots = Botan::PKCS11::Slot::get_available_slots(module, true);
   Botan::PKCS11::Slot slot(module, slots.at(0));
   Botan::PKCS11::Session session(slot, false);

   // create an simple data object
   Botan::secure_vector<uint8_t> value = {0x00, 0x01, 0x02, 0x03};
   std::size_t id = 1337;
   std::string label = "test data object";

   // set properties of the new object
   Botan::PKCS11::DataObjectProperties data_obj_props;
   data_obj_props.set_label(label);
   data_obj_props.set_value(value);
   data_obj_props.set_token(true);
   data_obj_props.set_modifiable(true);
   std::vector<uint8_t> encoded_id;
   Botan::DER_Encoder(encoded_id).encode(id);
   data_obj_props.set_object_id(encoded_id);

   // create the object
   Botan::PKCS11::Object data_obj(session, data_obj_props);

   // get label of this object
   Botan::PKCS11::secure_string retrieved_label = data_obj.get_attribute_value(Botan::PKCS11::AttributeType::Label);

   // set a new label
   Botan::PKCS11::secure_string new_label = {'B', 'o', 't', 'a', 'n'};
   data_obj.set_attribute_value(Botan::PKCS11::AttributeType::Label, new_label);

   // copy the object
   Botan::PKCS11::AttributeContainer copy_attributes;
   copy_attributes.add_string(Botan::PKCS11::AttributeType::Label, "copied object");
   [[maybe_unused]] Botan::PKCS11::ObjectHandle copied_obj_handle = data_obj.copy(copy_attributes);

   // search for an object
   Botan::PKCS11::AttributeContainer search_template;
   search_template.add_string(Botan::PKCS11::AttributeType::Label, "Botan");
   auto found_objs = Botan::PKCS11::Object::search<Botan::PKCS11::Object>(session, search_template.attributes());

   // destroy the object
   data_obj.destroy();

   return 0;
}
