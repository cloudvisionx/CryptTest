LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_SRC_FILES := native-lib.cpp codec.cpp Cryptor.cpp
#不加后面的cpp会undefined reference,因为只是include头文件，并不能使编译器找到cpp
LOCAL_LDLIBS := -llog -lssl -lcrypto
LOCAL_LDFLAGS := -shared
LOCAL_MODULE:= native-lib
#LOCAL_CFLAGS += -pie -fPIE
#LOCAL_LDFLAGS += -pie -fPIE
LOCAL_CPPFLAGS := -std=c++11 -pthread -frtti -fexceptions
LOCAL_DISABLE_FORMAT_STRING_CHECKS := true
include $(BUILD_SHARED_LIBRARY)
#include $(LOCAL_PATH)/prebuilt/Android.mk