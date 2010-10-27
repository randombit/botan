#ifdef __cplusplus
extern "C" {
#endif

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#ifdef __cplusplus
}
#endif

#include <botan/asn1_obj.h>
#include <botan/asn1_oid.h>
#include <botan/filters.h>
#include <botan/init.h>
#include <botan/oids.h>
#include <botan/x509cert.h>
#include <botan/x509_ext.h>


/* xsubpp converts ':' to '_' in typemap. We create our types without ':' */
 
typedef Botan::ASN1_String		Botan__ASN1_String;
typedef Botan::AlgorithmIdentifier	Botan__AlgorithmIdentifier;
typedef Botan::AlternativeName		Botan__AlternativeName;
typedef Botan::Attribute		Botan__Attribute;
typedef Botan::Base64_Decoder		Botan__Base64_Decoder;
typedef Botan::Base64_Encoder		Botan__Base64_Encoder;
typedef Botan::Chain			Botan__Chain;
typedef Botan::Certificate_Extension	Botan__Extension;
typedef Botan::Filter			Botan__Filter;
typedef Botan::Fork			Botan__Fork;
typedef Botan::Hex_Decoder		Botan__Hex_Decoder;
typedef Botan::Hex_Encoder		Botan__Hex_Encoder;
typedef Botan::OID			Botan__OID;
typedef Botan::Pipe			Botan__Pipe;
typedef Botan::X509_Certificate		Botan__X509_Certificate;
typedef Botan::X509_DN			Botan__X509_DN;
typedef Botan::X509_Time		Botan__X509_Time;
typedef Botan::u32bit			Botan__u32bit;


/* Types to keep track of destruction C++ objects passed
 * into other objects...
 * An Botan object is deleted by his parent object into which is passed,
 * e.g. some Filter is deleted when his Pipe is destructed. We must
 * track this and not to delete object again in Perls destructor.
 */

class ObjectInfo
{
private:
    I32	    d_signature;
    bool    d_del;
public:
    static I32 const SIGNVAL = 0x696a626f;
    ObjectInfo() : d_signature(SIGNVAL),
		    d_del(true)		    {};
    ~ObjectInfo()			    {};
    void    set_delete(bool del = true)	    { d_del = del; };
    void    set_delete_no()		    { set_delete(false); };
    void    set_delete_yes()		    { set_delete(true); };
    bool    should_delete() const	    { return d_del; };
};

/* Constant object in initial state - template */

ObjectInfo const oi_init;


/* Botan library initializer ... */

Botan::LibraryInitializer botan_init;



/*============================================================================*/

MODULE = Botan				    PACKAGE = Botan

PROTOTYPES: ENABLE

void
constant(char *name)
    CODE:
	using namespace Botan;
	errno = 0;
	switch (name[0])
	{
	    case 'F':
	        if ( strEQ(name, "FULL_CHECK") )
		    XSRETURN_IV( FULL_CHECK );	    // Decoder_Checking enum
		break;
	    case 'I':
	        if ( strEQ(name, "IGNORE_WS") )
		    XSRETURN_IV( IGNORE_WS );	    // Decoder_Checking enum
		break;
	    case 'N':
	        if ( strEQ(name, "NONE") )
		    XSRETURN_IV( NONE );	    // Decoder_Checking enum
		break;
	}
	errno = EINVAL;
	XSRETURN_UNDEF;


# =========================== Botan::Chain ==========================

MODULE = Botan				    PACKAGE = Botan::Chain

Botan__Chain *
Botan__Chain::new(f1 = 0, f2 = 0, f3 = 0, f4 = 0)
	Botan__Filter	*f1;
	Botan__Filter	*f2;
	Botan__Filter	*f3;
	Botan__Filter	*f4;
    PREINIT:
	ObjectInfo	*f1_oi;
	ObjectInfo	*f2_oi;
	ObjectInfo	*f3_oi;
	ObjectInfo	*f4_oi;
    CODE:
	try {
	    RETVAL = new Botan__Chain(f1, f2, f3, f4);
	    if ( f1 ) f1_oi->set_delete_no();
	    if ( f2 ) f2_oi->set_delete_no();
	    if ( f3 ) f3_oi->set_delete_no();
	    if ( f4 ) f4_oi->set_delete_no();
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

void
Botan__Chain::DESTROY()
    PREINIT:
	ObjectInfo	*THIS_oi;
    CODE:
	if ( THIS_oi->should_delete() )
	    try {
		delete THIS;
	    }
	    catch (const std::exception &e) {
		croak(e.what());
	    }


# =========================== Botan::Fork ==========================

MODULE = Botan				    PACKAGE = Botan::Fork

Botan__Fork *
Botan__Fork::new(f1 = 0, f2 = 0, f3 = 0, f4 = 0)
	Botan__Filter	*f1;
	Botan__Filter	*f2;
	Botan__Filter	*f3;
	Botan__Filter	*f4;
    PREINIT:
	ObjectInfo	*f1_oi;
	ObjectInfo	*f2_oi;
	ObjectInfo	*f3_oi;
	ObjectInfo	*f4_oi;
    CODE:
	try {
	    RETVAL = new Botan__Fork(f1, f2, f3, f4);
	    if ( f1 ) f1_oi->set_delete_no();
	    if ( f2 ) f2_oi->set_delete_no();
	    if ( f3 ) f3_oi->set_delete_no();
	    if ( f4 ) f4_oi->set_delete_no();
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

void
Botan__Fork::DESTROY()
    PREINIT:
	ObjectInfo	*THIS_oi;
    CODE:
	if ( THIS_oi->should_delete() )
	    try {
		delete THIS;
	    }
	    catch (const std::exception &e) {
		croak(e.what());
	    }


# ============================ Botan::Base64_Decoder ============================

MODULE = Botan				    PACKAGE = Botan::Base64_Decoder

Botan__Base64_Decoder *
Botan__Base64_Decoder::new(checking = Botan::NONE)
	int	checking;
    CODE:
	try {
	    using namespace Botan;
	    RETVAL = new Base64_Decoder((Decoder_Checking)checking);
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

void
Botan__Base64_Decoder::DESTROY()
    PREINIT:
	ObjectInfo	*THIS_oi;
    CODE:
	if ( THIS_oi->should_delete() )
	    try {
		delete THIS;
	    }
	    catch (const std::exception &e) {
		croak(e.what());
	    }


# =========================== Botan::Base64_Encoder ==========================

MODULE = Botan				    PACKAGE = Botan::Base64_Encoder

Botan__Base64_Encoder *
Botan__Base64_Encoder::new(breaks = false, length = 72)
	bool		breaks;
       	Botan__u32bit	length;
    CODE:
	try {
	    RETVAL = new Botan__Base64_Encoder(breaks, length);
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

void
Botan__Base64_Encoder::DESTROY()
    PREINIT:
	ObjectInfo	*THIS_oi;
    CODE:
	if ( THIS_oi->should_delete() )
	    try {
		delete THIS;
	    }
	    catch (const std::exception &e) {
		croak(e.what());
	    }


# ============================ Botan::Hex_Decoder ============================

MODULE = Botan				    PACKAGE = Botan::Hex_Decoder

Botan__Hex_Decoder *
Botan__Hex_Decoder::new(checking = Botan::NONE)
	int	checking;
    CODE:
	try {
	    using namespace Botan;
	    RETVAL = new Hex_Decoder((Decoder_Checking)checking);
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

void
Botan__Hex_Decoder::DESTROY()
    PREINIT:
	ObjectInfo	*THIS_oi;
    CODE:
	if ( THIS_oi->should_delete() )
	    try {
		delete THIS;
	    }
	    catch (const std::exception &e) {
		croak(e.what());
	    }


# ============================ Botan::Hex_Encoder ============================

MODULE = Botan				    PACKAGE = Botan::Hex_Encoder

Botan__Hex_Encoder *
Botan__Hex_Encoder::new(breaks = false, length = 72, lcase = false)
	bool		breaks;
       	Botan__u32bit	length;
	bool		lcase;
    CODE:
	try {
	    using Botan::Hex_Encoder;
	    RETVAL = new Hex_Encoder(breaks, length,
		    lcase ? Hex_Encoder::Lowercase : Hex_Encoder::Uppercase);
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

void
Botan__Hex_Encoder::DESTROY()
    PREINIT:
	ObjectInfo	*THIS_oi;
    CODE:
	if ( THIS_oi->should_delete() )
	    try {
		delete THIS;
	    }
	    catch (const std::exception &e) {
		croak(e.what());
	    }


# ================================ Botan::OID ================================

MODULE = Botan				    PACKAGE = Botan::OID

Botan__OID *
Botan__OID::new(s)
	char *s;
    CODE:
	try {
	    RETVAL = new Botan__OID(s);
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

void
Botan__OID::DESTROY()
    CODE:
	try {
	    delete THIS;
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}

char *
Botan__OID::as_string()
    CODE:
	try {
	    RETVAL = const_cast<char *>(THIS->as_string().c_str());
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL


# ================================ Botan::OIDS ================================

MODULE = Botan				    PACKAGE = Botan::OIDS

void
add_oid(oid, name)
	Botan__OID  *oid;
       	char	    *name;
    CODE:
	try {
	    Botan::OIDS::add_oid(*oid, name);
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}

char *
lookup_by_oid(oid)
	Botan__OID *oid;
    CODE:
	try {
	    RETVAL = const_cast<char *>(Botan::OIDS::lookup(*oid).c_str());
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

Botan__OID *
lookup_by_name(name)
	char *name;
    CODE:
	try {
	    RETVAL = new Botan__OID(Botan::OIDS::lookup(name));
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
	char const * CLASS = "Botan::OID";
    OUTPUT:
	RETVAL

int
have_oid(name)
	char *name;
    CODE:
	try {
	    RETVAL = Botan::OIDS::have_oid(name);
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL


# ================================ Botan::Pipe ================================

MODULE = Botan				    PACKAGE = Botan::Pipe

Botan__Pipe *
Botan__Pipe::new(...)
    CODE:
	for (I32 i = 1; i < items; i++)
	{
	    if ( !sv_isobject(ST(i)) || (SvTYPE(SvRV(ST(i))) != SVt_PVMG) )
		croak("Botan::Pipe::new() -- arg %u is not "
			"a blessed SV reference", i +1);
	    if ( !sv_derived_from(ST(i), "Botan::Filter") )
		croak("Botan::Pipe::new() -- arg %u is not "
			"an object derived from Botan::Filter", i +1);
	    MAGIC *mg = mg_find(SvRV(ST(i)), '~');
	    if ( mg == 0
		    || mg->mg_len != sizeof(ObjectInfo)
		    || *(I32 *)(mg->mg_ptr) != ObjectInfo::SIGNVAL )
		croak("Botan::Pipe::new() -- arg %u has no "
			"valid private magic data (ObjectInfo)", i +1);
	}
	try {
	    RETVAL = new Botan__Pipe();
	    for (I32 i = 1; i < items; i++)
	    {
		SV *osv = (SV *)SvRV(ST(i));
		ObjectInfo *oi = (ObjectInfo *)(mg_find(osv, '~')->mg_ptr);
		RETVAL->append((Botan__Filter *)(SvIV(osv)));
		oi->set_delete_no();
	    }
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

void
Botan__Pipe::DESTROY()
    PREINIT:
	ObjectInfo	*THIS_oi;
    CODE:
	try {
	    delete THIS;
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}

void
Botan__Pipe::write(s)
	SV *s;
    PREINIT:
	ObjectInfo	*THIS_oi;
    CODE:
	STRLEN len;
	char *ptr = SvPV(s, len);
	try {
	    THIS->write((unsigned char *)ptr, len);
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}

void
Botan__Pipe::process_msg(s)
	SV *s;
    PREINIT:
	ObjectInfo	*THIS_oi;
    CODE:
	STRLEN len;
	char *ptr = SvPV(s, len);
	try {
	    THIS->process_msg((unsigned char *)ptr, len);
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}

Botan__u32bit
Botan__Pipe::remaining(msgno = Botan::Pipe::DEFAULT_MESSAGE)
	Botan__u32bit msgno;
    PREINIT:
	ObjectInfo	*THIS_oi;
    CODE:
	try {
	    RETVAL = THIS->remaining(msgno);
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

SV *
Botan__Pipe::read(len = 0xFFFFFFFF, msgno = Botan::Pipe::DEFAULT_MESSAGE)
	Botan__u32bit len;
	Botan__u32bit msgno;
    PREINIT:
	ObjectInfo	*THIS_oi;
    CODE:
	try {
	    if ( len > THIS->remaining(msgno) )
		len = THIS->remaining(msgno);
	    RETVAL = NEWSV(0, len);
	    SvPOK_on(RETVAL);
	    if ( len > 0 )
		SvCUR_set(RETVAL, THIS->read((unsigned char *)SvPVX(RETVAL),
			    len, msgno));
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

SV *
Botan__Pipe::peek(len = 0xFFFFFFFF, offset = 0, \
		msgno = Botan::Pipe::DEFAULT_MESSAGE)
	Botan__u32bit len;
	Botan__u32bit offset;
	Botan__u32bit msgno;
    PREINIT:
	ObjectInfo	*THIS_oi;
    CODE:
	try {
	    if ( len > THIS->remaining(msgno) )
		len = THIS->remaining(msgno);
	    RETVAL = NEWSV(0, len);
	    SvPOK_on(RETVAL);
	    if ( len > 0 )
		SvCUR_set(RETVAL, THIS->peek((unsigned char *)SvPVX(RETVAL),
			    len, offset, msgno));
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

Botan__u32bit
Botan__Pipe::default_msg()
    PREINIT:
	ObjectInfo	*THIS_oi;
    CODE:
	try {
	    RETVAL = THIS->default_msg();
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

void
Botan__Pipe::set_default_msg(msgno)
	Botan__u32bit msgno;
    PREINIT:
	ObjectInfo	*THIS_oi;
    CODE:
	try {
	    THIS->set_default_msg(msgno);
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}

Botan__u32bit
Botan__Pipe::message_count()
    PREINIT:
	ObjectInfo	*THIS_oi;
    CODE:
	try {
	    RETVAL = THIS->message_count();
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

bool
Botan__Pipe::end_of_data()
    PREINIT:
	ObjectInfo	*THIS_oi;
    CODE:
	try {
	    RETVAL = THIS->end_of_data();
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

void
Botan__Pipe::start_msg()
    PREINIT:
	ObjectInfo	*THIS_oi;
    CODE:
	try {
	    THIS->start_msg();
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}

void
Botan__Pipe::end_msg()
    PREINIT:
	ObjectInfo	*THIS_oi;
    CODE:
	try {
	    THIS->end_msg();
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}

void
Botan__Pipe::reset()
    PREINIT:
	ObjectInfo	*THIS_oi;
    CODE:
	try {
	    THIS->reset();
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}


# ========================== Botan::X509_Certificate ==========================

MODULE = Botan				    PACKAGE = Botan::X509_Certificate

Botan__X509_Certificate *
Botan__X509_Certificate::new(char *fn)
    CODE:
	try {
	    RETVAL = new Botan__X509_Certificate(fn);
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

void
Botan__X509_Certificate::DESTROY()
    CODE:
	try {
	    delete THIS;
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}

unsigned int
Botan__X509_Certificate::x509_version()
    CODE:
	try {
	    RETVAL = THIS->x509_version();
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

char *
Botan__X509_Certificate::start_time()
    CODE:
	try {
	    RETVAL = const_cast<char *>(THIS->start_time().c_str());
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

char *
Botan__X509_Certificate::end_time()
    CODE:
	try {
	    RETVAL = const_cast<char *>(THIS->end_time().c_str());
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

char *
Botan__X509_Certificate::subject_info(char *info)
    CODE:
	try {
            std::vector<std::string> s = THIS->subject_info(info);

            if(s.size() > 0)
                RETVAL = const_cast<char *>(s[0].c_str());
            else
                RETVAL = "err";
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

char *
Botan__X509_Certificate::issuer_info(char *info)
    CODE:
	try {
            std::vector<std::string> s = THIS->subject_info(info);

            if(s.size() > 0)
                RETVAL = const_cast<char *>(s[0].c_str());
            else
                RETVAL = "err";
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

Botan__X509_DN *
Botan__X509_Certificate::subject_dn()
    CODE:
	try {
	    RETVAL = new Botan__X509_DN(THIS->subject_dn());
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
	char const * CLASS = "Botan::X509_DN";
    OUTPUT:
	RETVAL

Botan__X509_DN *
Botan__X509_Certificate::issuer_dn()
    CODE:
	try {
	    RETVAL = new Botan__X509_DN(THIS->issuer_dn());
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
	char const * CLASS = "Botan::X509_DN";
    OUTPUT:
	RETVAL


# ============================== Botan::X509_DN ==============================

MODULE = Botan				    PACKAGE = Botan::X509_DN

Botan__X509_DN *
Botan__X509_DN::new()
    CODE:
	try {
	    RETVAL = new Botan__X509_DN();
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL

void
Botan__X509_DN::DESTROY()
    CODE:
	try {
	    delete THIS;
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}

AV *
Botan__X509_DN::get_attributes()
    CODE:
	try {
	    using namespace std;
	    using namespace Botan;

	    typedef multimap<OID, string>::const_iterator rdn_iter;

	    multimap<OID, string> const &atrmmap = THIS->get_attributes();
	    RETVAL = newAV();
	    for(rdn_iter i = atrmmap.begin(); i != atrmmap.end(); i++)
	    {
		string const &atr = i->first.as_string();
		string const &val = i->second;
		av_push(RETVAL, newSVpvn(atr.c_str(), atr.length()));
		av_push(RETVAL, newSVpvn(val.c_str(), val.length()));
	    }
	}
	catch (const std::exception &e) {
	    croak(e.what());
	}
    OUTPUT:
	RETVAL
