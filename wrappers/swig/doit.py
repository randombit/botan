#!/usr/bin/python2

import botan

def hash_it(hash, input):
    f1 = botan.Filter("MD5")
    f2 = botan.Filter("Hex_Encoder")
    pipe = botan.Pipe(f1, f2)

    pipe.start_msg()
    pipe.write_string(input)
    pipe.end_msg()

    print pipe.remaining()

    out = pipe.read(0)

    


def main:
    init = botan.LibraryInitializer

    print hash_it("MD5", "foo")


    key1 = botan.SymmetricKey("ABCD")
    print key1.as_string()
    key2 = botan.SymmetricKey(16)
    print key2.as_string()

    iv1 = botan.InitializationVector(8)
    print iv1.as_string()


    f3 = pipe.read(pipe.remaining())

    size = pipe.remaining()
    out = botan.byte_array(size)
    pipe.read(out.cast,size)

    for i in range (0,size):
        print "%02X" % out[i]

    print pipe.read_all_as_string()

if __name__ == "__main__":
    sys.exit(main())

