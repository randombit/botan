//#include <iostream>
//#include <fstream>
//
//#include <botan/ec.h>
//#include <botan/math/bigint.h>
//#include <botan/math/ec/point_gfp.h>
//#include <time.h>

using namespace Botan::math::gf;

#if( CM_RAND_EXP != 1 && CM_AADA == 1)
BOOST_AUTO_TEST_CASE(test_cm_aada)
{
	cout << "." << flush;
    //#ifdef CM_AADA
    // init the lib
    Botan::InitializerOptions init_options("");
    Botan::LibraryInitializer init(init_options);

    Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid("1.3.132.0.8"));
    PointGFp p(dom_pars.get_base_point());
    BigInt key1("0xffffffffffffffff");
    BigInt key2("0x8000000000000000");
    BigInt pointorder = dom_pars.get_order() * dom_pars.get_cofactor();

    unsigned int repetitions = 100;
    long long unsigned int start_time;
    long long unsigned int end_time;
    int result_time_1;
    int result_time_2;

    start_time = clock();
    for(unsigned int i = 0; i < repetitions; i++)
    {
        p.mult_this_secure(key1, pointorder, key1);
    }
    end_time = clock();

    result_time_1 = end_time - start_time;
    p = dom_pars.get_base_point();

    start_time = clock();
    for(unsigned int i = 0; i < repetitions; i++)
    {
        p.mult_this_secure(key2, pointorder, key1);
    }
    end_time = clock();
    result_time_2 = end_time - start_time;

    //	cout << "time Key 1: " << result_time_1 << endl;
    //	cout << "time Key 2: " << result_time_2 << endl;

    double diff_time_ratio = ((double)(result_time_1 - result_time_2)) / (double)result_time_1;
    std::abs(diff_time_ratio);
    BOOST_CHECK_MESSAGE(diff_time_ratio < 0.25,
     "Diffenrenz with AADA between \"min. 64bit\" and \"max. 64bit\" is to much. Should be smaller than 25%! Was: " << diff_time_ratio);
    //#else //CM_AADA
    //    cout << "CM-AADA (Countermeasure \"add and double always\") not activated. Test skiped!" << endl;
    //    BOOST_CHECK(true);
    //#endif //CM_AADA
}
#endif
#ifdef TA_COLL_T
/**
* doesn´t make sure that the timings are "equal", only that it works in general
*/
BOOST_AUTO_TEST_CASE(test_repeatable_rand_exp_measurements)
{
	cout << "." << flush;
	Botan::InitializerOptions init_options("");
    Botan::LibraryInitializer init(init_options);

    Botan::EC_Domain_Params dom_pars(Botan::get_EC_Dom_Pars_by_oid("1.3.132.0.8"));
    PointGFp p1(dom_pars.get_base_point());
    PointGFp p2(p1);

    BigInt scalar("2305432045823");
    PointGFp q1 = p1.mult_this_secure(scalar, dom_pars.get_order(), scalar, false);
    PointGFp q2 = p2.mult_this_secure(scalar, dom_pars.get_order(), scalar, true);

    BOOST_CHECK(q1 == q2);
}
#endif // TA_COLL_T
