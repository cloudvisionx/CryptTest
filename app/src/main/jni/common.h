//
// Created by thinkpad on 2016/11/27.
//

#ifndef CRYPTTEST_COMMON_H
#define CRYPTTEST_COMMON_H

#include <string>
#include<android/log.h>


#define LOG_TAG "cydia"
#define LOGI(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGW(...)  __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#endif //CRYPTTEST_COMMON_H
