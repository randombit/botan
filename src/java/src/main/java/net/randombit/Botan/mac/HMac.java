/*
 * Experimental Java suport for Project Panama
 *  Botan is released under the Simplified BSD License (see license.txt)
 *
 */
package  net.randombit.Botan.mac;
import net.randombit.Botan.ffi.botan_mac_struct;
import static net.randombit.Botan.ffi_h.*;
import java.foreign.*;
import java.foreign.memory.Pointer;
import java.foreign.memory.LayoutType;

import java.security.NoSuchAlgorithmException;

/*
* HMac implementation using project panama and JDK 13.
*/
public class HMac
{
    private Pointer<Pointer<botan_mac_struct>> botanMac;

    /**
     * Constructor for the Mac.
     * @param algorithmName               Name of the hash algorithm
     * @throws NoSuchAlgorithmException   Throws of it doesn't exist.
     */
   public HMac(String algorithmName) throws NoSuchAlgorithmException
   {
       try (Scope scope = scope().fork())
       {
           Pointer<Byte> algorithm = scope.allocateCString(algorithmName);
           this.botanMac = scope().allocate(LayoutType.ofStruct(botan_mac_struct.class).pointer());
           if (botan_mac_init(this.botanMac, algorithm, 0) == 0) {
               throw new NoSuchAlgorithmException(algorithmName + "  not supported yet");
           }
       }
  }
}

