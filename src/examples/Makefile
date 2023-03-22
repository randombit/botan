# Build examples using make
# Target OS: Linux
# Compiler: gcc
# Target processor: x86_64

# Paths to relevant programs
CXX            = g++
LINKER         = $(CXX)

# Compiler Flags
ABI_FLAGS      = -fstack-protector -m64 -pthread
LANG_FLAGS     = -std=c++20 -D_REENTRANT
LANG_EXE_FLAGS =
CXXFLAGS       = -O3
WARN_FLAGS     = -Wall -Wextra -Wpedantic -Wstrict-aliasing -Wcast-align -Wmissing-declarations -Wpointer-arith -Wcast-qual -Wzero-as-null-pointer-constant -Wnon-virtual-dtor -Wold-style-cast -Wsuggest-override -Wshadow -Wextra-semi -Werror -Wno-error=strict-overflow -Wno-error=zero-as-null-pointer-constant -Wno-error=non-virtual-dtor -Wno-unused-parameter
LDFLAGS        =
COMPILE_FLAGS    = -c
OUTPUT_TO_OBJECT = -o
OUTPUT_TO_EXE    = -o

EXE_LINK_CMD   = $(LINKER)

LIB_LINKS_TO        = -ldl -lrt
BUILD_DIR_LINK_PATH =
EXE_LINKS_TO        = -lbotan-3 $(LIB_LINKS_TO)

BUILD_FLAGS    = $(ABI_FLAGS) $(LANG_FLAGS) $(CXXFLAGS) $(WARN_FLAGS)

INCLUDES =

# OS specific suffic
OBJ_SUFFIX = .o


# The primary target
all: examples

# Misc targets

build:
	mkdir -p build

clean:
	rm -rf build

# Executable targets

PKCS11_EXAMPLES = pkcs11_low_level pkcs11_module pkcs11_slot pkcs11_session pkcs11_objects pkcs11_rsa pkcs11_ecdsa pkcs11_ecdh pkcs11_rng pkcs11_token_management pkcs11_x509

EXAMPLES = aes aes_cbc chacha check_key cmac dl_group ecdh ecdsa encrypt_with_pkcs8_key gmac hash hmac tls_client tls_custom_curves_client tls_proxy tls_stream_client xmss $(PKCS11_EXAMPLES)

examples: $(addprefix build/, $(EXAMPLES))

$(addprefix build/, $(addsuffix $(OBJ_SUFFIX),$(EXAMPLES))): build/%$(OBJ_SUFFIX): %.cpp | build
	$(CXX) $(BUILD_FLAGS) $(INCLUDES) $(COMPILE_FLAGS) $< $(OUTPUT_TO_OBJECT)$@
$(addprefix build/, $(EXAMPLES)): build/%: build/%$(OBJ_SUFFIX)
	$(EXE_LINK_CMD) $(ABI_FLAGS) $< $(BUILD_DIR_LINK_PATH) $(LANG_EXE_FLAGS) $(LDFLAGS) $(EXE_LINKS_TO) $(OUTPUT_TO_EXE)$@
