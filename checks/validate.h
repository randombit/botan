
#ifndef BOTAN_TEST_VALIDATE_H__
#define BOTAN_TEST_VALIDATE_H__

u32bit do_validation_tests(const std::string&, bool = true);
u32bit do_bigint_tests(const std::string&);
u32bit do_pk_validation_tests(const std::string&);
void do_x509_tests();

#endif
