#include <stdio.h>
#include <pthread.h>

void *thread_1 (void*);
void *thread_2 (void*);

//pthread_mutex_t mux;

//char ch;
bool ver1;
bool ver2;

const Botan::u32bit numo_runs = 20;

BOOST_AUTO_TEST_CASE( threads_tests)
{
  cout << "." << flush;
  ver1 = true;
  ver2 = true;
  Botan::InitializerOptions init_options("thread_safe");
  Botan::LibraryInitializer init(init_options);

  pthread_t p1, p2;
//	pthread_mutex_init (&mux, NULL);

  pthread_create (&p1, NULL, thread_1, NULL);
  pthread_create (&p2, NULL, thread_1, NULL);

  pthread_join (p1, NULL);
  pthread_join (p2, NULL);
  BOOST_CHECK(ver1);
  BOOST_CHECK(ver2);
}

bool sign_and_ver()
{
  cout << "." << flush;
  /*string g_secp("024a96b5688ef573284664698968c38bb913cbfc82");
  Botan::SecureVector<Botan::byte> sv_g_secp = decode_hex(g_secp);
  BigInt bi_p_secp("0xffffffffffffffffffffffffffffffff7fffffff");
  BigInt bi_a_secp("0xffffffffffffffffffffffffffffffff7ffffffc");
  BigInt bi_b_secp("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
  BigInt order = BigInt("0x0100000000000000000001f4c8f927aed3ca752257");
  CurveGFp curve(gf::GFpElement(bi_p_secp,bi_a_secp), gf::GFpElement(bi_p_secp, bi_b_secp), bi_p_secp);
  BigInt cofactor = BigInt(1);
  PointGFp p_G = OS2ECP ( sv_g_secp, curve );*/

  //Botan::EC_Domain_Params dom_pars = Botan::EC_Domain_Params(curve, p_G, order, cofactor);
  Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid("1.3.132.0.8"));
  Botan::ECDSA_PrivateKey my_priv_key(dom_pars);

  string str_message = ("12345678901234567890abcdef12");
  Botan::SecureVector<Botan::byte> sv_message = decode_hex(str_message);
  Botan::SecureVector<Botan::byte> signature = my_priv_key.sign(sv_message.begin(), sv_message.size());
  //cout << "signature = " << hex_encode(signature.begin(), signature.size()) << "\n";
  bool ver_success = my_priv_key.verify(sv_message.begin(), sv_message.size(), signature.begin(), signature.size());
  return ver_success;
}

void *thread_1 (void* )
{
  for (unsigned i=0; i<numo_runs; i++)
    {
        //cout << "." << flush;
      if (!sign_and_ver())
        {
          ver1 = false;
        }
    }
    return NULL;
}
//	pthread_mutex_lock (&mux);
//
//	ch = '1';
//	Sleep (1);	//unix: sleep(1);
//	for(int j=100;j>=0;j--)
//		printf ("thread1: %c\n", ch);
//
//	pthread_mutex_unlock (&mux);
//
//	return NULL;


/*void *thread_2 (void* )
{
  for (unsigned i=0; i<numo_runs; i++)
    {
      if (!sign_and_ver())
        {
          ver2 = false;
        }
    }
    return NULL;
}*/

