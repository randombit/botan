#!/bin/bash

EXTERNAL_INCLUDEDIR=$1

function android_mk {
	echo 'LOCAL_PATH := $(call my-dir)' > $1
	echo '' >> $1

	# target libbotan
	echo 'include $(CLEAR_VARS)' >> $1
	echo 'LOCAL_CLANG := true' >> $1
	echo 'LOCAL_MODULE := libbotan' >> $1
	echo 'LOCAL_CPP_EXTENSION := .cpp' >> $1
	echo 'LOCAL_CPP_FEATURES := rtti exceptions' >> $1
	echo 'LOCAL_CPPFLAGS := -fvisibility=hidden' >> $1
	echo 'LOCAL_C_INCLUDES := $(LOCAL_PATH)/build/include' $2 >> $1
	echo 'LOCAL_SRC_FILES := \' >> $1
	# - write cpp files for target libbotan
	grep "^build/obj/lib" Makefile  | sed "s/build\/obj\/lib\/[^:]\+: /\t/" | sed "s/$/ \\\\/" >> $1
	echo '' >> $1
	echo 'include $(BUILD_SHARED_LIBRARY)' >> $1
	echo '' >> $1

	# target botan-test
	echo 'include $(CLEAR_VARS)' >> $1
	echo 'LOCAL_CLANG := true' >> $1
	echo 'LOCAL_MODULE := botan-test' >> $1
	echo 'LOCAL_CPP_EXTENSION := .cpp' >> $1
	echo 'LOCAL_CPP_FEATURES := rtti exceptions' >> $1
	echo 'LOCAL_C_INCLUDES := $(LOCAL_PATH)/build/include' $2 >> $1
	echo 'LOCAL_SHARED_LIBRARIES := libbotan' >> $1
	echo 'LOCAL_SRC_FILES := \'  >> $1
	# - write cpp files for target botan-test
	grep "^build/obj/test" Makefile  | sed "s/build\/obj\/test\/[^:]\+: /\t/" | sed "s/$/ \\\\/" >> $1
	echo '' >> $1
	echo 'include $(BUILD_EXECUTABLE)' >> $1
}

function application_mk {
	echo 'NDK_TOOLCHAIN_VERSION := clang' > $1
	echo 'APP_CPPFLAGS := -D_REENTRANT -Wall -Wextra -Wpedantic -Wshadow -Wstrict-aliasing -Wstrict-overflow=5 -Wcast-align -Wmissing-declarations -Wpointer-arith -Wcast-qual -Wunreachable-code -Wno-gnu-include-next' >> $1
	echo 'APP_ABI := armeabi-v7a' >> $1
	echo 'APP_PLATFORM = android-23' >> $1
	echo 'APP_STL := c++_static' >> $1
}

# START

echo "Generating Android.mk"
# Construct Android.mk out of the generated Makefile
android_mk Android.mk $EXTERNAL_INCLUDEDIR

echo "Generating botan.mk for the NDK build"
# Construct Application.mk for NDK build
application_mk botan.mk $EXTERNAL_INCLUDEDIR

# Create link to jni
ln -sfn . jni

