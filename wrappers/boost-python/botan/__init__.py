from _botan import *

# Initialize the library when the module is imported
init = LibraryInitializer()

class SymmetricKey(OctetString):
    pass

class InitializationVector(OctetString):
    pass

def Filter(name, key = None, iv = None, dir = None):
    if key != None and iv != None and dir != None:
        return make_filter(name, key, iv, dir)
    elif key != None and dir != None:
        return make_filter(name, key, dir)
    elif key != None:
        return make_filter(name, key)
    else:
        return make_filter(name)

def Pipe(*filters):
    pipe = PipeObj()
    for filter in filters:
        if filter:
            pipe.append(filter)
    return pipe
