LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_SRC_FILES := proxybinder.cpp
LOCAL_LDLIBS := -llog -landroid_runtime -lbinder -lutils
LOCAL_LDFLAGS := -shared
LOCAL_MODULE:= proxybinder
#LOCAL_CFLAGS += -pie -fPIE
#LOCAL_LDFLAGS += -pie -fPIE
include $(BUILD_SHARED_LIBRARY)
#include $(LOCAL_PATH)/prebuilt/Android.mk