/*
* PKCS#11 Slot
* (C) 2016 Daniel Neus, Sirrix AG
* (C) 2016 Philipp Weber, Sirrix AG
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/p11_types.h>

namespace Botan {

namespace PKCS11 {

Slot::Slot(Module& module, SlotId slot_id)
   : m_module(module), m_slot_id(slot_id)
   {}

SlotInfo Slot::get_slot_info() const
   {
   SlotInfo slot_info = {};
   m_module.get()->C_GetSlotInfo(m_slot_id, &slot_info);
   return slot_info;
   }

std::vector<MechanismType> Slot::get_mechanism_list() const
   {
   std::vector<MechanismType> mechanism_list;
   m_module.get()->C_GetMechanismList(m_slot_id, mechanism_list);
   return mechanism_list;
   }

MechanismInfo Slot::get_mechanism_info(MechanismType mechanism_type) const
   {
   MechanismInfo mechanism_info = {};
   m_module.get()->C_GetMechanismInfo(m_slot_id, mechanism_type, &mechanism_info);
   return mechanism_info;
   }

std::vector<SlotId> Slot::get_available_slots(Module& module, bool token_present)
   {
   std::vector<SlotId> slot_vec;
   module->C_GetSlotList(token_present, slot_vec);
   return slot_vec;
   }

TokenInfo Slot::get_token_info() const
   {
   TokenInfo token_info;
   m_module.get()->C_GetTokenInfo(m_slot_id, &token_info);
   return token_info;
   }

void Slot::initialize(const std::string& label, const secure_string& so_pin) const
   {
   m_module.get()->C_InitToken(m_slot_id, so_pin, label);
   }
}

}
