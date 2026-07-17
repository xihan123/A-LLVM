LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := ndkp_build_system_smoke
LOCAL_SRC_FILES := smoke.c
include $(BUILD_SHARED_LIBRARY)
