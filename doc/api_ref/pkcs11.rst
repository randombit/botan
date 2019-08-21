.. _pkcs11:

PKCS#11
========================================

.. versionadded:: 1.11.31

|

PKCS#11 is a platform-independent interface for accessing smart cards and
hardware security modules (HSM). Vendors of PKCS#11 compatible devices usually
provide a so called middleware or "PKCS#11 module" which implements the PKCS#11
standard. This middleware translates calls from the platform-independent PKCS#11
API to device specific calls. So application developers don't have to write smart card
or HSM specific code for each device they want to support.

   .. note::

     The Botan PKCS#11 interface is implemented against version v2.40 of the standard.

Botan wraps the C PKCS#11 API to provide a C++ PKCS#11 interface. This is done
in two levels of abstraction: a low level API (see :ref:`pkcs11_low_level`) and
a high level API (see :ref:`pkcs11_high_level`). The low level API provides
access to all functions that are specified by the standard. The high level API
represents an object oriented approach to use PKCS#11 compatible devices but
only provides a subset of the functions described in the standard.

To use the PKCS#11 implementation the ``pkcs11`` module has to be enabled.

   .. note::

      Both PKCS#11 APIs live in the namespace ``Botan::PKCS11``

.. _pkcs11_low_level:

Low Level API
----------------------------------------

The PKCS#11 standards committee provides header files (``pkcs11.h``, ``pkcs11f.h`` and
``pkcs11t.h``) which define the PKCS#11 API in the C programming language. These
header files could be used directly to access PKCS#11 compatible smart cards or
HSMs. The external header files are shipped with Botan in version v2.4 of the standard. The PKCS#11 low
level API wraps the original PKCS#11 API, but still allows to access all functions described in the
standard and has the advantage that it is a C++ interface with features like RAII, exceptions
and automatic memory management.

The low level API is implemented by the :cpp:class:`LowLevel` class and can be accessed by
including the header ``botan/p11.h``.

Preface
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

All constants that belong together in the PKCS#11 standard are grouped into C++
enum classes. For example the different user types are grouped in the
:cpp:enum:`UserType` enumeration:

.. cpp:enum-class:: UserType : CK_USER_TYPE

   .. cpp:enumerator:: UserType::SO = CKU_SO
   .. cpp:enumerator:: UserType::User = CKU_USER
   .. cpp:enumerator:: UserType::ContextSpecific = CKU_CONTEXT_SPECIFIC

Additionally, all types that are used by the low or high level API are mapped by
type aliases to more C++ like names. For instance:

.. cpp:type:: FunctionListPtr = CK_FUNCTION_LIST_PTR

.. rubric:: C-API Wrapping

There is at least one method in the :cpp:class:`LowLevel` class that corresponds to a PKCS#11
function. For example the :cpp:func:`C_GetSlotList` method in the :cpp:class:`LowLevel` class is defined as follows:

.. cpp:class:: LowLevel

   .. cpp:function:: bool C_GetSlotList(Bbool token_present, SlotId* slot_list_ptr, Ulong* count_ptr, ReturnValue* return_value = ThrowException) const

The :cpp:class:`LowLevel` class calls the PKCS#11 function from the function list of the PKCS#11 module:

   .. code-block:: c

      CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)( CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
                                                CK_ULONG_PTR pulCount )

Where it makes sense there is also an overload of the :cpp:class:`LowLevel` method to make usage easier and safer:

   .. cpp:function:: bool C_GetSlotList( bool token_present, std::vector<SlotId>& slot_ids, ReturnValue* return_value = ThrowException ) const

With this overload the user of this API just has to pass a vector of :cpp:type:`SlotId` instead of pointers
to preallocated memory for the slot list and the number of elements. Additionally, there is no need
to call the method twice in order to determine the number of elements first.

Another example is the :cpp:func:`C_InitPIN` overload:

   .. cpp:function:: template<typename Talloc> bool C_InitPIN( SessionHandle session, const std::vector<uint8_t, TAlloc>& pin, ReturnValue* return_value = ThrowException ) const

The templated ``pin`` parameter allows to pass the PIN as a ``std::vector<uint8_t>`` or a ``secure_vector<uint8_t>``.
If used with a ``secure_vector`` it is assured that the memory is securely erased when the ``pin`` object is no longer needed.

Error Handling
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All possible PKCS#11 return values are represented by the enum class:

.. cpp:enum-class:: ReturnValue : CK_RV

All methods of the :cpp:class:`LowLevel` class have a default parameter ``ReturnValue* return_value = ThrowException``.
This parameter controls the error handling of all :cpp:class:`LowLevel` methods. The default
behavior ``return_value = ThrowException`` is to throw an exception if the method does
not complete successfully. If a non-``NULL`` pointer is passed, ``return_value`` receives the
return value of the PKCS#11 function and no exception is thrown. In case ``nullptr`` is
passed as ``return_value``, the exact return value is ignored and the method just returns
``true`` if the function succeeds and ``false`` otherwise.

Getting started
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

An object of this class can be instantiated by providing a :cpp:type:`FunctionListPtr` to the :cpp:class:`LowLevel` constructor:

   .. cpp:function:: explicit LowLevel(FunctionListPtr ptr)

The :cpp:class:`LowLevel` class provides a static method to retrieve a :cpp:type:`FunctionListPtr`
from a PKCS#11 module file:

   .. cpp:function:: static bool C_GetFunctionList(Dynamically_Loaded_Library& pkcs11_module, FunctionListPtr* function_list_ptr_ptr, ReturnValue* return_value = ThrowException)

----------

Code Example: Object Instantiation

   .. code-block:: cpp

      Botan::Dynamically_Loaded_Library pkcs11_module( "C:\\pkcs11-middleware\\library.dll" );
      Botan::PKCS11::FunctionListPtr func_list = nullptr;
      Botan::PKCS11::LowLevel::C_GetFunctionList( pkcs11_module, &func_list );
      Botan::PKCS11::LowLevel p11_low_level( func_list );

----------

Code Example: PKCS#11 Module Initialization

   .. code-block:: cpp

      Botan::PKCS11::LowLevel p11_low_level(func_list);

      Botan::PKCS11::C_InitializeArgs init_args = { nullptr, nullptr, nullptr, nullptr,
              static_cast<CK_FLAGS>(Botan::PKCS11::Flag::OsLockingOk), nullptr };

      p11_low_level.C_Initialize(&init_args);

      // work with the token

      p11_low_level.C_Finalize(nullptr);

More code examples can be found in the test suite in the ``test_pkcs11_low_level.cpp`` file.

.. _pkcs11_high_level:

High Level API
----------------------------------------

The high level API provides access to the most commonly used PKCS#11 functionality in an
object oriented manner. Functionality of the high level API includes:

* Loading/unloading of PKCS#11 modules
* Initialization of tokens
* Change of PIN/SO-PIN
* Session management
* Random number generation
* Enumeration of objects on the token (certificates, public keys, private keys)
* Import/export/deletion of certificates
* Generation/import/export/deletion of RSA and EC public and private keys
* Encryption/decryption using RSA with support for OAEP and PKCS1-v1_5 (and raw)
* Signature generation/verification using RSA with support for PSS and PKCS1-v1_5 (and raw)
* Signature generation/verification using ECDSA
* Key derivation using ECDH

Module
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The :cpp:class:`Module` class represents a PKCS#11 shared library (module) and is defined in
``botan/p11_module.h``.

It is constructed from a a file path to a PKCS#11 module and optional :cpp:type:`C_InitializeArgs`:

.. cpp:class:: Module

   .. code-block:: cpp

      Module(const std::string& file_path, C_InitializeArgs init_args =
         { nullptr, nullptr, nullptr, nullptr, static_cast<CK_FLAGS>(Flag::OsLockingOk), nullptr })

   It loads the shared library and calls :cpp:func:`C_Initialize` with the provided :cpp:type:`C_InitializeArgs`.
   On destruction of the object :cpp:func:`C_Finalize` is called.

There are two more methods in this class. One is for reloading the shared library
and reinitializing the PKCS#11 module:

   .. code-block:: cpp

      void reload(C_InitializeArgs init_args =
         { nullptr, nullptr, nullptr, nullptr, static_cast< CK_FLAGS >(Flag::OsLockingOk), nullptr });

The other one is for getting general information about the PKCS#11 module:

   .. cpp:function:: Info get_info() const

      This function calls :cpp:func:`C_GetInfo` internally.

----------

Code example:

   .. code-block:: cpp

      Botan::PKCS11::Module module( "C:\\pkcs11-middleware\\library.dll" );

      // Sometimes useful if a newly connected token is not detected by the PKCS#11 module
      module.reload();

      Botan::PKCS11::Info info = module.get_info();

      // print library version
      std::cout << std::to_string( info.libraryVersion.major ) << "."
         << std::to_string( info.libraryVersion.minor ) << std::endl;

Slot
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The :cpp:class:`Slot` class represents a PKCS#11 slot and is defined in
``botan/p11_slot.h``.

A PKCS#11 slot is usually a smart card reader that potentially contains a token.

.. cpp:class:: Slot

   .. cpp:function:: Slot(Module& module, SlotId slot_id)

      To instantiate this class a reference to a :cpp:class:`Module` object and a ``slot_id`` have to be passed
      to the constructor.

   .. cpp:function:: static std::vector<SlotId> get_available_slots(Module& module, bool token_present)

      Retrieve available slot ids by calling this static method.

      The parameter ``token_present`` controls whether all slots or only slots with a
      token attached are returned by this method. This method calls :cpp:func:`C_GetSlotList()`.

   .. cpp:function:: SlotInfo get_slot_info() const

      Returns information about the slot. Calls :cpp:func:`C_GetSlotInfo`.

   .. cpp:function:: TokenInfo get_token_info() const

      Obtains information about a particular token in the system. Calls :cpp:func:`C_GetTokenInfo`.

   .. cpp:function:: std::vector<MechanismType> get_mechanism_list() const

      Obtains a list of mechanism types supported by the slot. Calls :cpp:func:`C_GetMechanismList`.

   .. cpp:function:: MechanismInfo get_mechanism_info(MechanismType mechanism_type) const

      Obtains information about a particular mechanism possibly supported by a slot.
      Calls :cpp:func:`C_GetMechanismInfo`.

   .. cpp:function:: void initialize(const std::string& label, const secure_string& so_pin) const

      Calls :cpp:func:`C_InitToken` to initialize the token. The ``label`` must not exceed 32 bytes.
      The current PIN of the security officer must be passed in ``so_pin`` if the token
      is reinitialized or if it's a factory new token, the ``so_pin`` that is passed will initially be set.

----------

Code example:

   .. code-block:: cpp

      // only slots with connected token
      std::vector<Botan::PKCS11::SlotId> slots = Botan::PKCS11::Slot::get_available_slots( module, true );

      // use first slot
      Botan::PKCS11::Slot slot( module, slots.at( 0 ) );

      // print firmware version of the slot
      Botan::PKCS11::SlotInfo slot_info = slot.get_slot_info();
      std::cout << std::to_string( slot_info.firmwareVersion.major ) << "."
         << std::to_string( slot_info.firmwareVersion.minor ) << std::endl;

      // print firmware version of the token
      Botan::PKCS11::TokenInfo token_info = slot.get_token_info();
      std::cout << std::to_string( token_info.firmwareVersion.major ) << "."
         << std::to_string( token_info.firmwareVersion.minor ) << std::endl;

      // retrieve all mechanisms supported by the token
      std::vector<Botan::PKCS11::MechanismType> mechanisms = slot.get_mechanism_list();

      // retrieve information about a particular mechanism
      Botan::PKCS11::MechanismInfo mech_info =
         slot.get_mechanism_info( Botan::PKCS11::MechanismType::RsaPkcsOaep );

      // maximum RSA key length supported:
      std::cout << mech_info.ulMaxKeySize << std::endl;

      // initialize the token
      Botan::PKCS11::secure_string so_pin( 8, '0' );
      slot.initialize( "Botan PKCS11 documentation test label", so_pin );

Session
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The :cpp:class:`Session` class represents a PKCS#11 session and is defined in ``botan/p11_session.h``.

A session is a logical connection between an application and a token.

.. cpp:class:: Session

   There are two constructors to create a new session and one constructor to
   take ownership of an existing session. The destructor calls
   :cpp:func:`C_Logout` if a user is logged in to this session and always
   :cpp:func:`C_CloseSession`.

   .. cpp:function:: Session(Slot& slot, bool read_only)

      To initialize a session object a :cpp:class:`Slot` has to be specified on which the session
      should operate. ``read_only`` specifies whether the session should be read only or read write.
      Calls :cpp:func:`C_OpenSession`.

   .. cpp:function:: Session(Slot& slot, Flags flags, VoidPtr callback_data, Notify notify_callback)

      Creates a new session by passing a :cpp:class:`Slot`, session ``flags``, ``callback_data`` and a
      ``notify_callback``. Calls :cpp:func:`C_OpenSession`.

   .. cpp:function:: Session(Slot& slot, SessionHandle handle)

      Takes ownership of an existing session by passing :cpp:class:`Slot` and a session ``handle``.

   .. cpp:function:: SessionHandle release()

      Returns the released :cpp:type:`SessionHandle`

   .. cpp:function:: void login(UserType userType, const secure_string& pin)

      Login to this session by passing :cpp:enum:`UserType` and ``pin``. Calls :cpp:func:`C_Login`.

   .. cpp:function:: void logoff()

      Logout from this session. Not mandatory because on destruction of the :cpp:class:`Session` object
      this is done automatically.

   .. cpp:function:: SessionInfo get_info() const

      Returns information about this session. Calls :cpp:func:`C_GetSessionInfo`.

   .. cpp:function:: void set_pin(const secure_string& old_pin, const secure_string& new_pin) const

      Calls :cpp:func:`C_SetPIN` to change the PIN of the logged in user using the ``old_pin``.

   .. cpp:function:: void init_pin(const secure_string& new_pin)

      Calls :cpp:func:`C_InitPIN` to change or initialize the PIN using the SO_PIN (requires a logged in session).

----------

Code example:

   .. code-block:: cpp

      // open read only session
      {
      Botan::PKCS11::Session read_only_session( slot, true );
      }

      // open read write session
      {
      Botan::PKCS11::Session read_write_session( slot, false );
      }

      // open read write session by passing flags
      {
      Botan::PKCS11::Flags flags =
         Botan::PKCS11::flags( Botan::PKCS11::Flag::SerialSession | Botan::PKCS11::Flag::RwSession );

      Botan::PKCS11::Session read_write_session( slot, flags, nullptr, nullptr );
      }

      // move ownership of a session
      {
      Botan::PKCS11::Session session( slot, false );
      Botan::PKCS11::SessionHandle handle = session.release();

      Botan::PKCS11::Session session2( slot, handle );
      }

      Botan::PKCS11::Session session( slot, false );

      // get session info
      Botan::PKCS11::SessionInfo info = session.get_info();
      std::cout << info.slotID << std::endl;

      // login
      Botan::PKCS11::secure_string pin = { '1', '2', '3', '4', '5', '6' };
      session.login( Botan::PKCS11::UserType::User, pin );

      // set pin
      Botan::PKCS11::secure_string new_pin = { '6', '5', '4', '3', '2', '1' };
      session.set_pin( pin, new_pin );

      // logoff
      session.logoff();

      // log in as security officer
      Botan::PKCS11::secure_string so_pin = { '0', '0', '0', '0', '0', '0', '0', '0' };
      session.login( Botan::PKCS11::UserType::SO, so_pin );

      // change pin to old pin
      session.init_pin( pin );

Objects
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

PKCS#11 objects consist of various attributes (:c:type:`CK_ATTRIBUTE`). For example :c:macro:`CKA_TOKEN`
describes if a PKCS#11 object is a session object or a token object. The helper class :cpp:class:`AttributeContainer`
helps with storing these attributes. The class is defined in ``botan/p11_object.h``.

.. cpp:class:: AttributeContainer

Attributes can be set in an :cpp:class:`AttributeContainer` by various ``add_`` methods:

   .. cpp:function:: void add_class(ObjectClass object_class)

      Add a class attribute (:c:macro:`CKA_CLASS` / :cpp:enumerator:`AttributeType::Class`)

   .. cpp:function:: void add_string(AttributeType attribute, const std::string& value)

      Add a string attribute (e.g. :c:macro:`CKA_LABEL` / :cpp:enumerator:`AttributeType::Label`).

   .. cpp:function:: void AttributeContainer::add_binary(AttributeType attribute, const uint8_t* value, size_t length)

      Add a binary attribute (e.g. :c:macro:`CKA_ID` / :cpp:enumerator:`AttributeType::Id`).

   .. cpp:function:: template<typename TAlloc> void AttributeContainer::add_binary(AttributeType attribute, const std::vector<uint8_t, TAlloc>& binary)

      Add a binary attribute by passing a ``vector``/``secure_vector`` (e.g. :c:macro:`CKA_ID` / :cpp:enumerator:`AttributeType::Id`).

   .. cpp:function:: void AttributeContainer::add_bool(AttributeType attribute, bool value)

      Add a bool attribute (e.g. :c:macro:`CKA_SENSITIVE` / :cpp:enumerator:`AttributeType::Sensitive`).

   .. cpp:function:: template<typename T> void AttributeContainer::add_numeric(AttributeType attribute, T value)

       Add a numeric attribute (e.g. :c:macro:`CKA_MODULUS_BITS` / :cpp:enumerator:`AttributeType::ModulusBits`).

.. rubric:: Object Properties

The PKCS#11 standard defines the mandatory and optional attributes for each object class.
The mandatory and optional attribute requirements are mapped in so called property classes.
Mandatory attributes are set in the constructor, optional attributes can be set via ``set_`` methods.

In the top hierarchy is the :cpp:class:`ObjectProperties` class which inherits from the :cpp:class:`AttributeContainer`.
This class represents the common attributes of all PKCS#11 objects.

.. cpp:class:: ObjectProperties : public AttributeContainer

The constructor is defined as follows:

   .. cpp:function:: ObjectProperties(ObjectClass object_class)

      Every PKCS#11 object needs an object class attribute.

The next level defines the :cpp:class:`StorageObjectProperties` class which inherits from
:cpp:class:`ObjectProperties`.

.. cpp:class:: StorageObjectProperties : public ObjectProperties

The only mandatory attribute is the object class, so the constructor is
defined as follows:

   .. cpp:function:: StorageObjectProperties(ObjectClass object_class)

But in contrast to the :cpp:class:`ObjectProperties` class there are various setter methods. For example to
set the :cpp:enumerator:`AttributeType::Label`:

   .. cpp:function:: void set_label(const std::string& label)

      Sets the label description of the object (RFC2279 string).

The remaining hierarchy is defined as follows:

* :cpp:class:`DataObjectProperties` inherits from :cpp:class:`StorageObjectProperties`
* :cpp:class:`CertificateProperties` inherits from :cpp:class:`StorageObjectProperties`
* :cpp:class:`DomainParameterProperties` inherits from :cpp:class:`StorageObjectProperties`
* :cpp:class:`KeyProperties` inherits from :cpp:class:`StorageObjectProperties`
* :cpp:class:`PublicKeyProperties` inherits from :cpp:class:`KeyProperties`
* :cpp:class:`PrivateKeyProperties` inherits from :cpp:class:`KeyProperties`
* :cpp:class:`SecretKeyProperties` inherits from :cpp:class:`KeyProperties`

PKCS#11 objects themselves are represented by the :cpp:class:`Object` class.

.. cpp:class:: Object

Following constructors are defined:

   .. cpp:function:: Object(Session& session, ObjectHandle handle)

      Takes ownership over an existing object.

   .. cpp:function:: Object(Session& session, const ObjectProperties& obj_props)

      Creates a new object with the :cpp:class:`ObjectProperties` provided in ``obj_props``.

The other methods are:

   .. cpp:function:: secure_vector<uint8_t> get_attribute_value(AttributeType attribute) const

      Returns the value of the given attribute (using :cpp:func:`C_GetAttributeValue`)

   .. cpp:function:: void set_attribute_value(AttributeType attribute, const secure_vector<uint8_t>& value) const

      Sets the given value for the attribute (using :cpp:func:`C_SetAttributeValue`)

   .. cpp:function:: void destroy() const

      Destroys the object.

   .. cpp:function:: ObjectHandle copy(const AttributeContainer& modified_attributes) const

      Allows to copy the object with modified attributes.

And static methods to search for objects:

   .. cpp:function:: template<typename T> static std::vector<T> search(Session& session, const std::vector<Attribute>& search_template)

      Searches for all objects of the given type that match ``search_template``.

   .. cpp:function:: template<typename T> static std::vector<T> search(Session& session, const std::string& label)

      Searches for all objects of the given type using the label (:c:macro:`CKA_LABEL`).

   .. cpp:function:: template<typename T> static std::vector<T> search(Session& session, const std::vector<uint8_t>& id)

      Searches for all objects of the given type using the id (:c:macro:`CKA_ID`).

   .. cpp:function:: template<typename T> static std::vector<T> search(Session& session, const std::string& label, const std::vector<uint8_t>& id)

      Searches for all objects of the given type using the label (:c:macro:`CKA_LABEL`) and id (:c:macro:`CKA_ID`).

   .. cpp:function:: template<typename T> static std::vector<T> search(Session& session)

      Searches for all objects of the given type.

.. rubric:: The ObjectFinder

Another way for searching objects is to use the :cpp:class:`ObjectFinder` class. This class
manages calls to the ``C_FindObjects*`` functions: :cpp:func:`C_FindObjectsInit`, :cpp:func:`C_FindObjects`
and :cpp:func:`C_FindObjectsFinal`.

.. cpp:class:: ObjectFinder

The constructor has the following signature:

   .. cpp:function:: ObjectFinder(Session& session, const std::vector<Attribute>& search_template)

      A search can be prepared with an :cpp:class:`ObjectSearcher` by passing a :cpp:class:`Session` and a ``search_template``.

The actual search operation is started by calling the :cpp:func:`find` method:

   .. cpp:function:: std::vector<ObjectHandle> find(std::uint32_t max_count = 100) const

      Starts or continues a search for token and session objects that match a template. ``max_count``
      specifies the maximum number of search results (object handles) that are returned.

   .. cpp:function:: void finish()

      Finishes the search operation manually to allow a new :cpp:class:`ObjectFinder` to exist.
      Otherwise the search is finished by the destructor.

----------

Code example:

   .. code-block:: cpp

      // create an simple data object
      Botan::secure_vector<uint8_t> value = { 0x00, 0x01 ,0x02, 0x03 };
      std::size_t id = 1337;
      std::string label = "test data object";

      // set properties of the new object
      Botan::PKCS11::DataObjectProperties data_obj_props;
      data_obj_props.set_label( label );
      data_obj_props.set_value( value );
      data_obj_props.set_token( true );
      data_obj_props.set_modifiable( true );
      data_obj_props.set_object_id( Botan::DER_Encoder().encode( id ).get_contents_unlocked() );

      // create the object
      Botan::PKCS11::Object data_obj( session, data_obj_props );

      // get label of this object
      Botan::PKCS11::secure_string retrieved_label =
         data_obj.get_attribute_value( Botan::PKCS11::AttributeType::Label );

      // set a new label
      Botan::PKCS11::secure_string new_label = { 'B', 'o', 't', 'a', 'n' };
      data_obj.set_attribute_value( Botan::PKCS11::AttributeType::Label, new_label );

      // copy the object
      Botan::PKCS11::AttributeContainer copy_attributes;
      copy_attributes.add_string( Botan::PKCS11::AttributeType::Label, "copied object" );
      Botan::PKCS11::ObjectHandle copied_obj_handle = data_obj.copy( copy_attributes );

      // search for an object
      Botan::PKCS11::AttributeContainer search_template;
      search_template.add_string( Botan::PKCS11::AttributeType::Label, "Botan" );
      auto found_objs =
         Botan::PKCS11::Object::search<Botan::PKCS11::Object>( session, search_template.attributes() );

      // destroy the object
      data_obj.destroy();

RSA
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

PKCS#11 RSA support is implemented in ``<botan/p11_rsa.h>``.

.. rubric:: RSA Public Keys

PKCS#11 RSA public keys are provided by the class :cpp:class:`PKCS11_RSA_PublicKey`. This class
inherits from :cpp:class:`RSA_PublicKey` and :cpp:class:`Object`. Furthermore there are two property classes defined
to generate and import RSA public keys analogous to the other property classes described
before: :cpp:class:`RSA_PublicKeyGenerationProperties` and :cpp:class:`RSA_PublicKeyImportProperties`.

.. cpp:class:: PKCS11_RSA_PublicKey : public RSA_PublicKey, public Object

   .. cpp:function:: PKCS11_RSA_PublicKey(Session& session, ObjectHandle handle)

      Existing PKCS#11 RSA public keys can be used by providing an :cpp:type:`ObjectHandle` to the
      constructor.

   .. cpp:function:: PKCS11_RSA_PublicKey(Session& session, const RSA_PublicKeyImportProperties& pubkey_props)

      This constructor can be used to import an existing RSA public key with the :cpp:class:`RSA_PublicKeyImportProperties`
      passed in ``pubkey_props`` to the token.

.. rubric:: RSA Private Keys

The support for PKCS#11 RSA private keys is implemented in a similar way. There are two property
classes: :cpp:class:`RSA_PrivateKeyGenerationProperties` and :cpp:class:`RSA_PrivateKeyImportProperties`. The :cpp:class:`PKCS11_RSA_PrivateKey`
class implements the actual support for PKCS#11 RSA private keys. This class inherits from :cpp:class:`Private_Key`,
:cpp:class:`RSA_PublicKey` and :cpp:class:`Object`. In contrast to the public key class there is a third constructor
to generate private keys directly on the token or in the session and one method to export private keys.

.. cpp:class:: PKCS11_RSA_PrivateKey : public Private_Key, public RSA_PublicKey, public Object

   .. cpp:function:: PKCS11_RSA_PrivateKey(Session& session, ObjectHandle handle)

      Existing PKCS#11 RSA private keys can be used by providing an :cpp:type:`ObjectHandle` to the
      constructor.

   .. cpp:function:: PKCS11_RSA_PrivateKey(Session& session, const RSA_PrivateKeyImportProperties& priv_key_props)

      This constructor can be used to import an existing RSA private key with the :cpp:class:`RSA_PrivateKeyImportProperties`
      passed in ``priv_key_props`` to the token.

   .. cpp:function:: PKCS11_RSA_PrivateKey(Session& session, uint32_t bits, const RSA_PrivateKeyGenerationProperties& priv_key_props)

      Generates a new PKCS#11 RSA private key with bit length provided in ``bits`` and the :cpp:class:`RSA_PrivateKeyGenerationProperties`
      passed in ``priv_key_props``.

   .. cpp:function:: RSA_PrivateKey export_key() const

      Returns the exported :cpp:class:`RSA_PrivateKey`.

PKCS#11 RSA key pairs can be generated with the following free function:

   .. cpp:function:: PKCS11_RSA_KeyPair PKCS11::generate_rsa_keypair(Session& session, const RSA_PublicKeyGenerationProperties& pub_props, const RSA_PrivateKeyGenerationProperties& priv_props)

----------

Code example:

   .. code-block:: cpp

      Botan::PKCS11::secure_string pin = { '1', '2', '3', '4', '5', '6' };
      session.login( Botan::PKCS11::UserType::User, pin );

      /************ import RSA private key *************/

      // create private key in software
      Botan::AutoSeeded_RNG rng;
      Botan::RSA_PrivateKey priv_key_sw( rng, 2048 );

      // set the private key import properties
      Botan::PKCS11::RSA_PrivateKeyImportProperties
         priv_import_props( priv_key_sw.get_n(), priv_key_sw.get_d() );

      priv_import_props.set_pub_exponent( priv_key_sw.get_e() );
      priv_import_props.set_prime_1( priv_key_sw.get_p() );
      priv_import_props.set_prime_2( priv_key_sw.get_q() );
      priv_import_props.set_coefficient( priv_key_sw.get_c() );
      priv_import_props.set_exponent_1( priv_key_sw.get_d1() );
      priv_import_props.set_exponent_2( priv_key_sw.get_d2() );

      priv_import_props.set_token( true );
      priv_import_props.set_private( true );
      priv_import_props.set_decrypt( true );
      priv_import_props.set_sign( true );

      // import
      Botan::PKCS11::PKCS11_RSA_PrivateKey priv_key( session, priv_import_props );

      /************ export PKCS#11 RSA private key *************/
      Botan::RSA_PrivateKey exported = priv_key.export_key();

      /************ import RSA public key *************/

      // set the public key import properties
      Botan::PKCS11::RSA_PublicKeyImportProperties pub_import_props( priv_key.get_n(), priv_key.get_e() );
      pub_import_props.set_token( true );
      pub_import_props.set_encrypt( true );
      pub_import_props.set_private( false );

      // import
      Botan::PKCS11::PKCS11_RSA_PublicKey public_key( session, pub_import_props );

      /************ generate RSA private key *************/

      Botan::PKCS11::RSA_PrivateKeyGenerationProperties priv_generate_props;
      priv_generate_props.set_token( true );
      priv_generate_props.set_private( true );
      priv_generate_props.set_sign( true );
      priv_generate_props.set_decrypt( true );
      priv_generate_props.set_label( "BOTAN_TEST_RSA_PRIV_KEY" );

      Botan::PKCS11::PKCS11_RSA_PrivateKey private_key2( session, 2048, priv_generate_props );

      /************ generate RSA key pair *************/

      Botan::PKCS11::RSA_PublicKeyGenerationProperties pub_generate_props( 2048UL );
      pub_generate_props.set_pub_exponent();
      pub_generate_props.set_label( "BOTAN_TEST_RSA_PUB_KEY" );
      pub_generate_props.set_token( true );
      pub_generate_props.set_encrypt( true );
      pub_generate_props.set_verify( true );
      pub_generate_props.set_private( false );

      Botan::PKCS11::PKCS11_RSA_KeyPair rsa_keypair =
         Botan::PKCS11::generate_rsa_keypair( session, pub_generate_props, priv_generate_props );

      /************ RSA encrypt *************/

      Botan::secure_vector<uint8_t> plaintext = { 0x00, 0x01, 0x02, 0x03 };
      Botan::PK_Encryptor_EME encryptor( rsa_keypair.first, rng, "Raw" );
      auto ciphertext = encryptor.encrypt( plaintext, rng );

      /************ RSA decrypt *************/

      Botan::PK_Decryptor_EME decryptor( rsa_keypair.second, rng, "Raw" );
      plaintext = decryptor.decrypt( ciphertext );

      /************ RSA sign *************/

      Botan::PK_Signer signer( rsa_keypair.second, rng, "EMSA4(SHA-256)", Botan::IEEE_1363 );
      auto signature = signer.sign_message( plaintext, rng );

      /************ RSA verify *************/

      Botan::PK_Verifier verifier( rsa_keypair.first, "EMSA4(SHA-256)", Botan::IEEE_1363 );
      auto ok = verifier.verify_message( plaintext, signature );

ECDSA
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

PKCS#11 ECDSA support is implemented in ``<botan/p11_ecdsa.h>``.

.. rubric:: ECDSA Public Keys

PKCS#11 ECDSA public keys are provided by the class :cpp:class:`PKCS11_ECDSA_PublicKey`. This class
inherits from :cpp:class:`PKCS11_EC_PublicKey` and :cpp:class:`ECDSA_PublicKey`. The necessary property classes
are defined in ``<botan/p11_ecc_key.h>``. For public keys there are :cpp:class:`EC_PublicKeyGenerationProperties`
and :cpp:class:`EC_PublicKeyImportProperties`.

.. cpp:class:: PKCS11_ECDSA_PublicKey : public PKCS11_EC_PublicKey, public virtual ECDSA_PublicKey

   .. cpp:function:: PKCS11_ECDSA_PublicKey(Session& session, ObjectHandle handle)

      Existing PKCS#11 ECDSA private keys can be used by providing an :cpp:type:`ObjectHandle` to the
      constructor.

   .. cpp:function:: PKCS11_ECDSA_PublicKey(Session& session, const EC_PublicKeyImportProperties& props)

      This constructor can be used to import an existing ECDSA public key with the :cpp:class:`EC_PublicKeyImportProperties`
      passed in ``props`` to the token.

   .. cpp:function:: ECDSA_PublicKey PKCS11_ECDSA_PublicKey::export_key() const

      Returns the exported :cpp:class:`ECDSA_PublicKey`.

.. rubric:: ECDSA Private Keys

The class :cpp:class:`PKCS11_ECDSA_PrivateKey` inherits from :cpp:class:`PKCS11_EC_PrivateKey` and implements support
for PKCS#11 ECDSA private keys. There are two property classes for key generation
and import: :cpp:class:`EC_PrivateKeyGenerationProperties` and :cpp:class:`EC_PrivateKeyImportProperties`.

.. cpp:class:: PKCS11_ECDSA_PrivateKey : public PKCS11_EC_PrivateKey

   .. cpp:function:: PKCS11_ECDSA_PrivateKey(Session& session, ObjectHandle handle)

      Existing PKCS#11 ECDSA private keys can be used by providing an :cpp:type:`ObjectHandle` to the
      constructor.

   .. cpp:function:: PKCS11_ECDSA_PrivateKey(Session& session, const EC_PrivateKeyImportProperties& props)

      This constructor can be used to import an existing ECDSA private key with the :cpp:class:`EC_PrivateKeyImportProperties`
      passed in ``props`` to the token.

   .. cpp:function:: PKCS11_ECDSA_PrivateKey(Session& session, const std::vector<uint8_t>& ec_params, const EC_PrivateKeyGenerationProperties& props)

      This constructor can be used to generate a new ECDSA private key with the :cpp:class:`EC_PrivateKeyGenerationProperties`
      passed in ``props`` on the token. The ``ec_params`` parameter is the DER-encoding of an
      ANSI X9.62 Parameters value.

   .. cpp:function:: ECDSA_PrivateKey export_key() const

      Returns the exported :cpp:class:`ECDSA_PrivateKey`.

PKCS#11 ECDSA key pairs can be generated with the following free function:

   .. cpp:function:: PKCS11_ECDSA_KeyPair PKCS11::generate_ecdsa_keypair(Session& session, const EC_PublicKeyGenerationProperties& pub_props, const EC_PrivateKeyGenerationProperties& priv_props)

----------

Code example:

   .. code-block:: cpp

      Botan::PKCS11::secure_string pin = { '1', '2', '3', '4', '5', '6' };
      session.login( Botan::PKCS11::UserType::User, pin );

      /************ import ECDSA private key *************/

      // create private key in software
      Botan::AutoSeeded_RNG rng;

      Botan::ECDSA_PrivateKey priv_key_sw( rng, Botan::EC_Group( "secp256r1" ) );
      priv_key_sw.set_parameter_encoding( Botan::EC_Group_Encoding::EC_DOMPAR_ENC_OID );

      // set the private key import properties
      Botan::PKCS11::EC_PrivateKeyImportProperties priv_import_props(
         priv_key_sw.DER_domain(), priv_key_sw.private_value() );

      priv_import_props.set_token( true );
      priv_import_props.set_private( true );
      priv_import_props.set_sign( true );
      priv_import_props.set_extractable( true );

      // label
      std::string label = "test ECDSA key";
      priv_import_props.set_label( label );

      // import to card
      Botan::PKCS11::PKCS11_ECDSA_PrivateKey priv_key( session, priv_import_props );

      /************ export PKCS#11 ECDSA private key *************/
      Botan::ECDSA_PrivateKey priv_exported = priv_key.export_key();

      /************ import ECDSA public key *************/

      // import to card
      Botan::PKCS11::EC_PublicKeyImportProperties pub_import_props( priv_key_sw.DER_domain(),
         Botan::DER_Encoder().encode( EC2OSP( priv_key_sw.public_point(), Botan::PointGFp::UNCOMPRESSED ),
         Botan::OCTET_STRING ).get_contents_unlocked() );

      pub_import_props.set_token( true );
      pub_import_props.set_verify( true );
      pub_import_props.set_private( false );

      // label
      label = "test ECDSA pub key";
      pub_import_props.set_label( label );

      Botan::PKCS11::PKCS11_ECDSA_PublicKey public_key( session, pub_import_props );

      /************ export PKCS#11 ECDSA public key *************/
      Botan::ECDSA_PublicKey pub_exported = public_key.export_key();

      /************ generate PKCS#11 ECDSA private key *************/
      Botan::PKCS11::EC_PrivateKeyGenerationProperties priv_generate_props;
      priv_generate_props.set_token( true );
      priv_generate_props.set_private( true );
      priv_generate_props.set_sign( true );

      Botan::PKCS11::PKCS11_ECDSA_PrivateKey pk( session,
         Botan::EC_Group( "secp256r1" ).DER_encode( Botan::EC_Group_Encoding::EC_DOMPAR_ENC_OID ),
         priv_generate_props );

      /************ generate PKCS#11 ECDSA key pair *************/

      Botan::PKCS11::EC_PublicKeyGenerationProperties pub_generate_props(
         Botan::EC_Group( "secp256r1" ).DER_encode(Botan::EC_Group_Encoding::EC_DOMPAR_ENC_OID ) );

      pub_generate_props.set_label( "BOTAN_TEST_ECDSA_PUB_KEY" );
      pub_generate_props.set_token( true );
      pub_generate_props.set_verify( true );
      pub_generate_props.set_private( false );
      pub_generate_props.set_modifiable( true );

      Botan::PKCS11::PKCS11_ECDSA_KeyPair key_pair = Botan::PKCS11::generate_ecdsa_keypair( session,
         pub_generate_props, priv_generate_props );

      /************ PKCS#11 ECDSA sign and verify *************/

      std::vector<uint8_t> plaintext( 20, 0x01 );

      Botan::PK_Signer signer( key_pair.second, rng, "Raw", Botan::IEEE_1363, "pkcs11" );
      auto signature = signer.sign_message( plaintext, rng );

      Botan::PK_Verifier token_verifier( key_pair.first, "Raw", Botan::IEEE_1363, "pkcs11" );
      bool ecdsa_ok = token_verifier.verify_message( plaintext, signature );

ECDH
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

PKCS#11 ECDH support is implemented in ``<botan/p11_ecdh.h>``.

.. rubric:: ECDH Public Keys

PKCS#11 ECDH public keys are provided by the class :cpp:class:`PKCS11_ECDH_PublicKey`. This class
inherits from :cpp:class:`PKCS11_EC_PublicKey`. The necessary property classes
are defined in ``<botan/p11_ecc_key.h>``. For public keys there are :cpp:class:`EC_PublicKeyGenerationProperties`
and :cpp:class:`EC_PublicKeyImportProperties`.

.. cpp:class:: PKCS11_ECDH_PublicKey : public PKCS11_EC_PublicKey

   .. cpp:function:: PKCS11_ECDH_PublicKey(Session& session, ObjectHandle handle)

      Existing PKCS#11 ECDH private keys can be used by providing an :cpp:type:`ObjectHandle` to the
      constructor.

   .. cpp:function:: PKCS11_ECDH_PublicKey(Session& session, const EC_PublicKeyImportProperties& props)

      This constructor can be used to import an existing ECDH public key with the :cpp:class:`EC_PublicKeyImportProperties`
      passed in ``props`` to the token.

   .. cpp:function:: ECDH_PublicKey export_key() const

      Returns the exported :cpp:class:`ECDH_PublicKey`.

.. rubric:: ECDH Private Keys

The class :cpp:class:`PKCS11_ECDH_PrivateKey` inherits from :cpp:class:`PKCS11_EC_PrivateKey` and :cpp:class:`PK_Key_Agreement_Key`
and implements support for PKCS#11 ECDH private keys. There are two
property classes. One for key generation and one for import: :cpp:class:`EC_PrivateKeyGenerationProperties` and
:cpp:class:`EC_PrivateKeyImportProperties`.

.. cpp:class:: PKCS11_ECDH_PrivateKey : public virtual PKCS11_EC_PrivateKey, public virtual PK_Key_Agreement_Key

   .. cpp:function:: PKCS11_ECDH_PrivateKey(Session& session, ObjectHandle handle)

      Existing PKCS#11 ECDH private keys can be used by providing an :cpp:type:`ObjectHandle` to the
      constructor.

   .. cpp:function:: PKCS11_ECDH_PrivateKey(Session& session, const EC_PrivateKeyImportProperties& props)

      This constructor can be used to import an existing ECDH private key with the :cpp:class:`EC_PrivateKeyImportProperties`
      passed in ``props`` to the token.

   .. cpp:function:: PKCS11_ECDH_PrivateKey(Session& session, const std::vector<uint8_t>& ec_params, const EC_PrivateKeyGenerationProperties& props)

      This constructor can be used to generate a new ECDH private key with the :cpp:class:`EC_PrivateKeyGenerationProperties`
      passed in ``props`` on the token. The ``ec_params`` parameter is the DER-encoding of an
      ANSI X9.62 Parameters value.

   .. cpp:function:: ECDH_PrivateKey export_key() const

      Returns the exported :cpp:class:`ECDH_PrivateKey`.

PKCS#11 ECDH key pairs can be generated with the following free function:

.. cpp:function:: PKCS11_ECDH_KeyPair PKCS11::generate_ecdh_keypair(Session& session, const EC_PublicKeyGenerationProperties& pub_props, const EC_PrivateKeyGenerationProperties& priv_props)

----------

Code example:

   .. code-block:: cpp

      Botan::PKCS11::secure_string pin = { '1', '2', '3', '4', '5', '6' };
      session.login( Botan::PKCS11::UserType::User, pin );

      /************ import ECDH private key *************/

      Botan::AutoSeeded_RNG rng;

      // create private key in software
      Botan::ECDH_PrivateKey priv_key_sw( rng, Botan::EC_Group( "secp256r1" ) );
      priv_key_sw.set_parameter_encoding( Botan::EC_Group_Encoding::EC_DOMPAR_ENC_OID );

      // set import properties
      Botan::PKCS11::EC_PrivateKeyImportProperties priv_import_props(
         priv_key_sw.DER_domain(), priv_key_sw.private_value() );

      priv_import_props.set_token( true );
      priv_import_props.set_private( true );
      priv_import_props.set_derive( true );
      priv_import_props.set_extractable( true );

      // label
      std::string label = "test ECDH key";
      priv_import_props.set_label( label );

      // import to card
      Botan::PKCS11::PKCS11_ECDH_PrivateKey priv_key( session, priv_import_props );

      /************ export ECDH private key *************/
      Botan::ECDH_PrivateKey exported = priv_key.export_key();

      /************ import ECDH public key *************/

      // set import properties
      Botan::PKCS11::EC_PublicKeyImportProperties pub_import_props( priv_key_sw.DER_domain(),
         Botan::DER_Encoder().encode( EC2OSP( priv_key_sw.public_point(), Botan::PointGFp::UNCOMPRESSED ),
         Botan::OCTET_STRING ).get_contents_unlocked() );

      pub_import_props.set_token( true );
      pub_import_props.set_private( false );
      pub_import_props.set_derive( true );

      // label
      label = "test ECDH pub key";
      pub_import_props.set_label( label );

      // import
      Botan::PKCS11::PKCS11_ECDH_PublicKey pub_key( session, pub_import_props );

      /************ export ECDH private key *************/
      Botan::ECDH_PublicKey exported_pub = pub_key.export_key();

      /************ generate ECDH private key *************/

      Botan::PKCS11::EC_PrivateKeyGenerationProperties priv_generate_props;
      priv_generate_props.set_token( true );
      priv_generate_props.set_private( true );
      priv_generate_props.set_derive( true );

      Botan::PKCS11::PKCS11_ECDH_PrivateKey priv_key2( session,
         Botan::EC_Group( "secp256r1" ).DER_encode( Botan::EC_Group_Encoding::EC_DOMPAR_ENC_OID ),
         priv_generate_props );

      /************ generate ECDH key pair *************/

      Botan::PKCS11::EC_PublicKeyGenerationProperties pub_generate_props(
         Botan::EC_Group( "secp256r1" ).DER_encode( Botan::EC_Group_Encoding::EC_DOMPAR_ENC_OID ) );

      pub_generate_props.set_label( label + "_PUB_KEY" );
      pub_generate_props.set_token( true );
      pub_generate_props.set_derive( true );
      pub_generate_props.set_private( false );
      pub_generate_props.set_modifiable( true );

      Botan::PKCS11::PKCS11_ECDH_KeyPair key_pair = Botan::PKCS11::generate_ecdh_keypair(
         session, pub_generate_props, priv_generate_props );

      /************ ECDH derive *************/

      Botan::PKCS11::PKCS11_ECDH_KeyPair key_pair_other = Botan::PKCS11::generate_ecdh_keypair(
         session, pub_generate_props, priv_generate_props );

      Botan::PK_Key_Agreement ka( key_pair.second, rng, "Raw", "pkcs11" );
      Botan::PK_Key_Agreement kb( key_pair_other.second, rng, "Raw", "pkcs11" );

      Botan::SymmetricKey alice_key = ka.derive_key( 32,
         Botan::unlock( Botan::EC2OSP( key_pair_other.first.public_point(),
         Botan::PointGFp::UNCOMPRESSED ) ) );

      Botan::SymmetricKey bob_key = kb.derive_key( 32,
         Botan::unlock( Botan::EC2OSP( key_pair.first.public_point(),
         Botan::PointGFp::UNCOMPRESSED ) ) );

      bool eq = alice_key == bob_key;

RNG
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The PKCS#11 RNG is defined in ``<botan/p11_randomgenerator.h>``. The class :cpp:class:`PKCS11_RNG`
implements the :cpp:class:`Hardware_RNG` interface.

.. cpp:class:: PKCS11_RNG : public Hardware_RNG

   .. cpp:function:: PKCS11_RNG(Session& session)

      A PKCS#11 :cpp:class:`Session` must be passed to instantiate a ``PKCS11_RNG``.

   .. cpp:function:: void randomize(uint8_t output[], std::size_t length) override

      Calls :cpp:func:`C_GenerateRandom` to generate random data.

   .. cpp:function:: void add_entropy(const uint8_t in[], std::size_t length) override

      Calls :cpp:func:`C_SeedRandom` to add entropy to the random generation function of the token/middleware.

----------

Code example:

   .. code-block:: cpp

      Botan::PKCS11::PKCS11_RNG p11_rng( session );

      /************ generate random data *************/
      std::vector<uint8_t> random( 20 );
      p11_rng.randomize( random.data(), random.size() );

      /************ add entropy *************/
      Botan::AutoSeeded_RNG auto_rng;
      auto auto_rng_random = auto_rng.random_vec( 20 );
      p11_rng.add_entropy( auto_rng_random.data(), auto_rng_random.size() );

      /************ use PKCS#11 RNG to seed HMAC_DRBG *************/
      Botan::HMAC_DRBG drbg( Botan::MessageAuthenticationCode::create( "HMAC(SHA-512)" ), p11_rng );
      drbg.randomize( random.data(), random.size() );

Token Management Functions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The header file ``<botan/p11.h>`` also defines some free functions for token management:

   .. cpp:function:: void initialize_token(Slot& slot, const std::string& label, const secure_string& so_pin, const secure_string& pin)

      Initializes a token by passing a :cpp:class:`Slot`, a ``label`` and the ``so_pin`` of the security officer.

   .. cpp:function:: void change_pin(Slot& slot, const secure_string& old_pin, const secure_string& new_pin)

      Change PIN with ``old_pin`` to ``new_pin``.

   .. cpp:function:: void change_so_pin(Slot& slot, const secure_string& old_so_pin, const secure_string& new_so_pin)

      Change SO_PIN with ``old_so_pin`` to new ``new_so_pin``.

   .. cpp:function:: void set_pin(Slot& slot, const secure_string& so_pin, const secure_string& pin)

      Sets user ``pin`` with ``so_pin``.

----------

Code example:

   .. code-block:: cpp

      /************ set pin *************/

      Botan::PKCS11::Module module( Middleware_path );

      // only slots with connected token
      std::vector<Botan::PKCS11::SlotId> slots = Botan::PKCS11::Slot::get_available_slots( module, true );

      // use first slot
      Botan::PKCS11::Slot slot( module, slots.at( 0 ) );

      Botan::PKCS11::secure_string so_pin = { '1', '2', '3', '4', '5', '6', '7', '8' };
      Botan::PKCS11::secure_string pin = { '1', '2', '3', '4', '5', '6' };
      Botan::PKCS11::secure_string test_pin = { '6', '5', '4', '3', '2', '1' };

      // set pin
      Botan::PKCS11::set_pin( slot, so_pin, test_pin );

      // change back
      Botan::PKCS11::set_pin( slot, so_pin, pin );

      /************ initialize *************/
      Botan::PKCS11::initialize_token( slot, "Botan handbook example", so_pin, pin );

      /************ change pin *************/
      Botan::PKCS11::change_pin( slot, pin, test_pin );

      // change back
      Botan::PKCS11::change_pin( slot, test_pin, pin );

      /************ change security officer pin *************/
      Botan::PKCS11::change_so_pin( slot, so_pin, test_pin );

      // change back
      Botan::PKCS11::change_so_pin( slot, test_pin, so_pin );

X.509
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The header file ``<botan/p11_x509.h>`` defines the property class :cpp:class:`X509_CertificateProperties`
and the class :cpp:class:`PKCS11_X509_Certificate`.

.. cpp:class:: PKCS11_X509_Certificate : public Object, public X509_Certificate

   .. cpp:function:: PKCS11_X509_Certificate(Session& session, ObjectHandle handle)

      Allows to use existing certificates on the token by passing a valid :cpp:type:`ObjectHandle`.

   .. cpp:function:: PKCS11_X509_Certificate(Session& session, const X509_CertificateProperties& props)

      Allows to import an existing X.509 certificate to the token with the :cpp:class:`X509_CertificateProperties`
      passed in ``props``.

----------

Code example:

   .. code-block:: cpp

      // load existing certificate
      Botan::X509_Certificate root( "test.crt" );

      // set props
      Botan::PKCS11::X509_CertificateProperties props(
         Botan::DER_Encoder().encode( root.subject_dn() ).get_contents_unlocked(), root.BER_encode() );

      props.set_label( "Botan PKCS#11 test certificate" );
      props.set_private( false );
      props.set_token( true );

      // import
      Botan::PKCS11::PKCS11_X509_Certificate pkcs11_cert( session, props );

      // load by handle
      Botan::PKCS11::PKCS11_X509_Certificate pkcs11_cert2( session, pkcs11_cert.handle() );

Tests
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The PKCS#11 tests are not executed automatically because the depend on an external
PKCS#11 module/middleware. The test tool has to be executed with ``--pkcs11-lib=``
followed with the path of the PKCS#11 module and a second argument which controls the
PKCS#11 tests that are executed. Passing ``pkcs11`` will execute all PKCS#11 tests but it's
also possible to execute only a subset with the following arguments:

- pkcs11-ecdh
- pkcs11-ecdsa
- pkcs11-lowlevel
- pkcs11-manage
- pkcs11-module
- pkcs11-object
- pkcs11-rng
- pkcs11-rsa
- pkcs11-session
- pkcs11-slot
- pkcs11-x509

The following PIN and SO-PIN/PUK values are used in tests:

- PIN 123456
- SO-PIN/PUK 12345678

 .. warning::

   Unlike the CardOS (4.4, 5.0, 5.3), the aforementioned SO-PIN/PUK is
   inappropriate for Gemalto (IDPrime MD 3840) cards, as it must be a byte array
   of length 24. For this reason some of the tests for Gemalto card involving
   SO-PIN will fail.  You run into a risk of exceding login attempts and as a
   result locking your card!  Currently, specifying pin via command-line option
   is not implemented, and therefore the desired PIN must be modified in the
   header src/tests/test_pkcs11.h:

   .. code-block:: cpp

      // SO PIN is expected to be set to "12345678" prior to running the tests
      const std::string SO_PIN = "12345678";
      const auto SO_PIN_SECVEC = Botan::PKCS11::secure_string(SO_PIN.begin(), SO_PIN.end());


Tested/Supported Smartcards
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You are very welcome to contribute your own test results for other testing environments or other cards.


Test results

+-------------------------------------+-------------------------------------------+---------------------------------------------------+---------------------------------------------------+---------------------------------------------------+---------------------------------------------------+
|  Smartcard                          | Status                                    | OS                                                | Midleware                                         |   Botan                                           | Errors                                            |
+=====================================+===========================================+===================================================+===================================================+===================================================+===================================================+
| CardOS 4.4                          | mostly works                              | Windows 10, 64-bit, version 1709                  | API Version 5.4.9.77 (Cryptoki v2.11)             |  2.4.0, Cryptoki v2.40                            | [50]_                                             |
+-------------------------------------+-------------------------------------------+---------------------------------------------------+---------------------------------------------------+---------------------------------------------------+---------------------------------------------------+
| CardOS 5.0                          | mostly works                              | Windows 10, 64-bit, version 1709                  | API Version 5.4.9.77 (Cryptoki v2.11)             |  2.4.0, Cryptoki v2.40                            | [51]_                                             |
+-------------------------------------+-------------------------------------------+---------------------------------------------------+---------------------------------------------------+---------------------------------------------------+---------------------------------------------------+
| CardOS 5.3                          | mostly works                              | Windows 10, 64-bit, version 1709                  | API Version 5.4.9.77 (Cryptoki v2.11)             |  2.4.0, Cryptoki v2.40                            | [52]_                                             |
+-------------------------------------+-------------------------------------------+---------------------------------------------------+---------------------------------------------------+---------------------------------------------------+---------------------------------------------------+
| CardOS 5.3                          | mostly works                              | Windows 10, 64-bit, version 1903                  | API Version 5.5.1 (Cryptoki v2.11)                |  2.12.0 unreleased, Cryptoki v2.40                | [53]_                                             |
+-------------------------------------+-------------------------------------------+---------------------------------------------------+---------------------------------------------------+---------------------------------------------------+---------------------------------------------------+
| Gemalto IDPrime MD 3840             | mostly works                              | Windows 10, 64-bit, version 1709                  | IDGo 800, v1.2.4 (Cryptoki v2.20)                 |  2.4.0, Cryptoki v2.40                            | [54]_                                             |
+-------------------------------------+-------------------------------------------+---------------------------------------------------+---------------------------------------------------+---------------------------------------------------+---------------------------------------------------+
| SoftHSM 2.3.0 (OpenSSL 1.0.2g)      | works                                     | Windows 10, 64-bit, version 1709                  | Cryptoki v2.40                                    |  2.4.0, Cryptoki v2.40                            |                                                   |
+-------------------------------------+-------------------------------------------+---------------------------------------------------+---------------------------------------------------+---------------------------------------------------+---------------------------------------------------+
| SoftHSM 2.5.0 (OpenSSL 1.1.1)       | works                                     | Windows 10, 64-bit, version 1803                  | Cryptoki v2.40                                    |  2.11.0, Cryptoki v2.40                           |                                                   |
+-------------------------------------+-------------------------------------------+---------------------------------------------------+---------------------------------------------------+---------------------------------------------------+---------------------------------------------------+

.. [50] Failing operations for CardOS 4.4:

 - object_copy [20]_

 - rsa_privkey_export [21]_
 - rsa_generate_private_key [22]_
 - rsa_sign_verify [23]_

 - ecdh_privkey_import [3]_
 - ecdh_privkey_export [2]_
 - ecdh_pubkey_import [4]_
 - ecdh_pubkey_export [4]_
 - ecdh_generate_private_key [3]_
 - ecdh_generate_keypair [3]_
 - ecdh_derive [3]_

 - ecdsa_privkey_import [3]_
 - ecdsa_privkey_export [2]_
 - ecdsa_pubkey_import [4]_
 - ecdsa_pubkey_export [4]_
 - ecdsa_generate_private_key  [3]_
 - ecdsa_generate_keypair  [3]_
 - ecdsa_sign_verify  [3]_

 - rng_add_entropy [5]_


.. [51] Failing operations for CardOS 5.0

 - object_copy [20]_

 - rsa_privkey_export [21]_
 - rsa_generate_private_key [22]_
 - rsa_sign_verify [23]_

 - ecdh_privkey_export [2]_
 - ecdh_pubkey_import [4]_
 - ecdh_generate_private_key [32]_
 - ecdh_generate_keypair [3]_
 - ecdh_derive [33]_

 - ecdsa_privkey_export [2]_
 - ecdsa_generate_private_key  [30]_
 - ecdsa_generate_keypair  [30]_
 - ecdsa_sign_verify  [30]_

 - rng_add_entropy [5]_

.. [52] Failing operations for CardOS 5.3

 - object_copy [20]_

 - rsa_privkey_export [21]_
 - rsa_generate_private_key [22]_
 - rsa_sign_verify [23]_

 - ecdh_privkey_export [2]_
 - ecdh_pubkey_import [6]_
 - ecdh_pubkey_export [6]_
 - ecdh_generate_private_key [30]_
 - ecdh_generate_keypair [31]_
 - ecdh_derive [30]_

 - ecdsa_privkey_export [2]_
 - ecdsa_pubkey_import [6]_
 - ecdsa_pubkey_export [6]_
 - ecdsa_generate_private_key  [31]_
 - ecdsa_generate_keypair  [31]_
 - ecdsa_sign_verify  [34]_

 - rng_add_entropy [5]_

.. [53] Failing operations for CardOS 5.3 (middelware 5.5.1)

 - ecdh_privkey_export [2]_
 - ecdh_generate_private_key [35]_
 - ecdsa_privkey_export [2]_
 - ecdsa_generate_private_key [36]_
 - c_copy_object [4]_

 - object_copy [4]_

 - rng_add_entropy [5]_

 - rsa_sign_verify [3]_
 - rsa_privkey_export [2]_
 - rsa_generate_private_key [9]_

.. [54] Failing operations for Gemalto IDPrime MD 3840

 - session_login_logout [2]_
 - session_info [2]_
 - set_pin [2]_
 - initialize [2]_
 - change_so_pin [2]_

 - object_copy [20]_

 - rsa_generate_private_key [7]_
 - rsa_encrypt_decrypt [8]_
 - rsa_sign_verify [2]_

 - rng_add_entropy [5]_

Error descriptions

.. [2] CKR_ARGUMENTS_BAD (0x7=7)
.. [3] CKR_MECHANISM_INVALID (0x70=112)
.. [4] CKR_FUNCTION_NOT_SUPPORTED (0x54=84)
.. [5] CKR_RANDOM_SEED_NOT_SUPPORTED (0x120=288)
.. [6] CKM_X9_42_DH_KEY_PAIR_GEN | CKR_DEVICE_ERROR (0x30=48)
.. [7] CKR_TEMPLATE_INCONSISTENT (0xD1=209)
.. [8] CKR_ENCRYPTED_DATA_INVALID | CKM_SHA256_RSA_PKCS (0x40=64)
.. [9] CKR_TEMPLATE_INCOMPLETE (0xD0=208)

.. [20] Test fails due to unsupported copy function (CKR_FUNCTION_NOT_SUPPORTED)
.. [21] Generating private key for extraction with property extractable fails (CKR_ARGUMENTS_BAD)
.. [22] Generate rsa private key operation fails (CKR_TEMPLATE_INCOMPLETE)
.. [23] Raw RSA sign-verify fails (CKR_MECHANISM_INVALID)

.. [30] Invalid argument Decoding error: BER: Value truncated
.. [31] Invalid argument Decoding error: BER: Length field is to large
.. [32] Invalid argument OS2ECP: Unknown format type 155
.. [33] Invalid argument OS2ECP: Unknown format type 92
.. [34] Invalid argument OS2ECP: Unknown format type 57
.. [35] Invalid argument OS2ECP: Unknown format type 82
.. [36] Invalid argument OS2ECP: Unknown format type 102
