//
// Created by thinkpad on 2016/11/27.
//

#ifndef CRYPTTEST_NATIVE_LIB_H
#define CRYPTTEST_NATIVE_LIB_H
#include <jni.h>
#include "common.h"



/**
 * define
 */

#define JAVA_CLASS "com/oraclex/crypttest/MainActivity"



extern "C" {
/**
 *  Function
 */
jint registerNativeMeth(JNIEnv *env);
static JNIEnv *__getEnv(bool *attached);
std::string simple_decstring(const char *p);
jstring aesEncrypt(JNIEnv *jenv, jclass, jstring rawData);
jstring aesDecrypt(JNIEnv *jenv, jclass, jstring rawData);
jstring decrypt(JNIEnv *jenv, jclass, jint type, jstring rawData);
}
/**
 * Variable
 */


JNINativeMethod method[]={{"aesEncrypt","(Ljava/lang/String;)Ljava/lang/String;",(void*)aesEncrypt}
                          };
static bool __is_attached = false;
static JNIEnv* env =NULL;
static JavaVM* __java_vm = NULL;

#endif //CRYPTTEST_NATIVE_LIB_H
