
import org.junit.Assert;
import org.junit.Test;

import java.security.NoSuchAlgorithmException;
import net.randombit.Botan.mac.HMac;
public class HMacUnitTest {
    @Test
    public void Should_Initialize_CorrectlyWithCorrectName() {
        boolean throwed = false;
        HMac mac = null;
        try {

            mac = new HMac("SHA-256");

        } catch (NoSuchAlgorithmException ex) {
            throwed = true;
        }
        Assert.assertFalse("Throwd init exception", throwed);
        Assert.assertNotNull("Mac shall be not null",mac);

    }

}



    /*
     Test::Result ffi_test_mac()
         {
         Test::Result result("FFI MAC");

         const char* input_str = "ABC";

         // MAC test
         botan_mac_t mac;
         TEST_FFI_FAIL("bad flag", botan_mac_init, (&mac, "HMAC(SHA-256)", 1));
         TEST_FFI_FAIL("bad name", botan_mac_init, (&mac, "HMAC(SHA-259)", 0));

         if(TEST_FFI_OK(botan_mac_init, (&mac, "HMAC(SHA-256)", 0)))
            {
            char namebuf[16];
            size_t name_len = 13;
            TEST_FFI_FAIL("output buffer too short", botan_mac_name, (mac, namebuf, &name_len));
            result.test_eq("name len", name_len, 14);

            name_len = sizeof(namebuf);
            if(TEST_FFI_OK(botan_mac_name, (mac, namebuf, &name_len)))
               {
               result.test_eq("name len", name_len, 14);
               result.test_eq("name", std::string(namebuf), "HMAC(SHA-256)");
               }

            size_t min_keylen = 0, max_keylen = 0, mod_keylen = 0;
            TEST_FFI_RC(0, botan_mac_get_keyspec, (mac, nullptr, nullptr, nullptr));
            TEST_FFI_RC(0, botan_mac_get_keyspec, (mac, &min_keylen, nullptr, nullptr));
            TEST_FFI_RC(0, botan_mac_get_keyspec, (mac, nullptr, &max_keylen, nullptr));
            TEST_FFI_RC(0, botan_mac_get_keyspec, (mac, nullptr, nullptr, &mod_keylen));

            result.test_eq("Expected min keylen", min_keylen, 0);
            result.test_eq("Expected max keylen", max_keylen, 4096);
            result.test_eq("Expected mod keylen", mod_keylen, 1);

            size_t output_len;
            if(TEST_FFI_OK(botan_mac_output_length, (mac, &output_len)))
               {
               result.test_eq("MAC output length", output_len, 32);

               const uint8_t mac_key[] = { 0xAA, 0xBB, 0xCC, 0xDD };
               std::vector<uint8_t> outbuf(output_len);

               // Test that after clear or final the object can be reused
               for(size_t r = 0; r != 2; ++r)
                  {
                  TEST_FFI_OK(botan_mac_set_key, (mac, mac_key, sizeof(mac_key)));
                  TEST_FFI_OK(botan_mac_update, (mac, reinterpret_cast<const uint8_t*>(input_str), std::strlen(input_str)));
                  TEST_FFI_OK(botan_mac_clear, (mac));

                  TEST_FFI_OK(botan_mac_set_key, (mac, mac_key, sizeof(mac_key)));
                  TEST_FFI_OK(botan_mac_update, (mac, reinterpret_cast<const uint8_t*>(input_str), std::strlen(input_str)));
                  TEST_FFI_OK(botan_mac_final, (mac, outbuf.data()));

                  result.test_eq("HMAC output", outbuf, "1A82EEA984BC4A7285617CC0D05F1FE1D6C96675924A81BC965EE8FF7B0697A7");
                  }
               }

            TEST_FFI_OK(botan_mac_destroy, (mac));
            }

         return result;
}
     */


