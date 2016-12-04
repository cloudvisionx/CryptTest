#include "native-lib.h"
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <Cryptor.h>
extern "C" {




jstring aesEncrypt(JNIEnv* jenv,jclass,jstring rawData){
    jboolean isCopy=true;



    const char* rawCstr=env->GetStringUTFChars(rawData,0);
    std::string decrypted;
    AESCryptor cryptor("1234567812345678");
    std::string encryptedStr;
    cryptor.encrypt(rawCstr,encryptedStr);
    LOGI(encryptedStr.c_str());
    cryptor.decrypt(encryptedStr.c_str(),decrypted);
    jstring encryptedJStr=env->NewStringUTF(decrypted.c_str());

    env->ReleaseStringUTFChars(rawData,rawCstr);//记得释放，这个不会自动释放，jni函数生成的j对象才会自动释放
    return encryptedJStr;
}





//jbyteArray
//Java_com_example_openssltest_MainActivity_hmacSha256(JNIEnv *env,
//                                                     jobject obj,
//                                                     jbyteArray content) {
//    unsigned char key[] = {0x6B, 0x65, 0x79};
//
//    unsigned int result_len;
//    unsigned char result[EVP_MAX_MD_SIZE];
//
//    // get data from java array
//    jbyte *data = env->GetByteArrayElements(content, NULL);
//    size_t dataLength = env->GetArrayLength(content);
//
//    HMAC(EVP_sha256(),
//         key, 3,
//         (unsigned char *) data, dataLength,
//         result, &result_len);
//
//    // release the array
//    env->ReleaseByteArrayElements(content, data, JNI_ABORT);
//
//    // the return value
//    jbyteArray return_val = env->NewByteArray(result_len);
//    env->SetByteArrayRegion(return_val, 0, result_len, (jbyte *) result);
//    return return_val;
//}



jint registerNativeMeth(JNIEnv *env){
    jclass cl=env->FindClass(JAVA_CLASS);

    if((env->RegisterNatives(cl,method,sizeof(method)/sizeof(method[0])))<0){
        return -1;
    }
    return 0;
}


static JNIEnv* __getEnv(bool* attached)
{
    *attached = false;
    int ret = __java_vm->GetEnv((void**)&env, JNI_VERSION_1_4);
    if (ret == JNI_EDETACHED)
    {
        if (0 != __java_vm->AttachCurrentThread(&env, NULL)) {
            return NULL;
        }
        *attached = true;
        return env;
    }

    if (ret != JNI_OK) {
        return NULL;
    }

    return env;
}


    jint JNI_OnLoad(JavaVM* vm, void* reserved)
    {
        JNIEnv* env = NULL;
        LOGI("SEC_EGL JNI_OnLoad!");
        __java_vm = vm;
        if ((env = __getEnv(&__is_attached)) == NULL)
        {
            LOGI("getEnv fail");
            return -1;
        }
        int registerResult=registerNativeMeth(env);
        if(registerResult==-1){
            LOGI("register fail");
            return -1;
        }else{
            LOGI("register succeed");
        }
        jint result = JNI_VERSION_1_4;
        return result;
    }

}
