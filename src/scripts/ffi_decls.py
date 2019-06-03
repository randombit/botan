#!/usr/bin/python

"""
Automatically generate declarations for the FFI layer

(C) 2019 Jack Lloyd

Botan is released under the Simplified BSD License (see license.txt)
"""

from pycparser import c_ast, parse_file

ffi_header = 'src/lib/ffi/ffi.h'

def to_ctype(typ, is_ptr):

    if typ.startswith('botan_') and typ.endswith('_t'):
        return 'c_void_p'

    if is_ptr is False:
        if typ == 'uint32':
            return 'c_uint32'
        elif typ == 'size_t':
            return 'c_size_t'
        elif typ == 'uint8_t':
            return 'c_uint8'
        elif typ == 'uint32_t':
            return 'c_uint32'
        elif typ == 'uint64_t':
            return 'c_uint64'
        elif typ == 'int':
            return 'c_int'
        elif typ == 'unsigned':
            return 'c_uint'
    else:
        if typ == 'void':
            return 'c_void_p'
        elif typ in ['char', 'uint8_t']: # hack
            return 'c_char_p'
        elif typ == 'size_t':
            return 'POINTER(c_size_t)'
        #elif typ == 'uint8_t':
        #    return 'POINTER(c_uint8)'
        elif typ == 'uint32_t':
            return 'POINTER(c_uint32)'
        elif typ == 'uint64_t':
            return 'POINTER(c_uint64)'
        elif typ == 'int':
            return 'POINTER(c_int)'

    raise Exception("Unknown type %s/%d" % (typ, is_ptr))

GROUP = None

class FuncDefVisitor(c_ast.NodeVisitor):
    def visit_FuncDecl(self, node):

        if not isinstance(node.type, c_ast.TypeDecl):
            #print("ignoring", node.type)
            return

        if node.type.type.names != ['int']:
            #print("ignoring", node.type)
            return

        # all functions returning ints:
        fn_name = node.type.declname

        fn_group = fn_name.split('_')[1]
        if fn_group == 'privkey':
            fn_group = 'pubkey' # hack

        global GROUP

        if fn_group != GROUP:
            if fn_group in ['rng', 'hash', 'mac', 'cipher', 'block', 'mp', 'pubkey', 'pk', 'x509', 'hotp', 'totp', 'fpe']:
                print("\n    # ", fn_group.upper())
            else:
                print("")
            GROUP = fn_group


        fn_args = []

        for param in node.args.params:

            is_ptr = False
            typ = None
            if isinstance(param.type, c_ast.PtrDecl):
                is_ptr = True
                typ = param.type.type.type.names[0]
            elif isinstance(param.type, c_ast.ArrayDecl):
                is_ptr = True
                typ = param.type.type.type.names[0]
            else:
                typ = param.type.type.names[0]

            ctype = to_ctype(typ, is_ptr)
            fn_args.append(ctype)

        decl = "    ffi_api(dll.%s," % (fn_name)
        if len(fn_args) > 4:
            decl += "\n            "
        else:
            decl += ' '

        decl += '[' + ', '.join(fn_args) + '])'

        print(decl)

ast = parse_file(ffi_header, use_cpp=True, cpp_args=['-Ibuild/include', '-std=c89', '-DBOTAN_DLL='])
v = FuncDefVisitor()
v.visit(ast)
