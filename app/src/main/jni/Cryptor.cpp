//
// Created by thinkpad on 2016/11/27.
//

#include "Cryptor.h"
#include "codec.h"

int MD5Cryptor::encrypt(const char *src, std::string& dest) {
    return codec_md5_encode(src,dest);
}


int Base64Cryptor::decrypt(const char *src, std::string &dest) {
    return 1;//应该返回unsigned char[]
//    return codec_base64_decode(src,strlen(src),dest);
}

int Base64Cryptor::encrypt(const char *src, std::string &dest) {
    size_t len=strlen((src));
    codec_base64_encode(src,len,dest);
    return 1;
}

int AESCryptor::encrypt(const char *src, std::string &dest) {
    int len=strlen((src));
    int encryptedLen=(len/16 + 1) * 16;
    char encryptedCStr[encryptedLen*2];
    int result=codec_aes_encrypt(src,mKey,encryptedCStr,encryptedLen);
    if(result=-1){

    }
    codec_base64_encode(encryptedCStr,encryptedLen,dest);
    return 1;
}

int AESCryptor::decrypt(const char *src, std::string &dest) {
    int len=strlen(src);
    size_t decodedLen=calcDecodeLength(src);
    unsigned char decodedCStr[len*2];
    codec_base64_decode(src,len,decodedCStr);
    return codec_aes_decrypt(decodedCStr,decodedLen,mKey,dest);
}

int RSACryptor::decrypt(const char *src, std::string &dest) {
    return codec_rsa_private_decrypt(src,mPrivatePem,dest);
}

int RSACryptor::encrypt(const char *src, std::string &dest) {
    return codec_rsa_public_encrypt(src,mPublicPem,type,dest);
}

int RSACryptor::privateSign(const char *src, std::string &dest) {
    return codec_rsa_private_sign(src,mPrivatePem,dest);
}

int RSACryptor::public_verify(const char *src, const char *sign) {
    return codec_rsa_public_verify(src,sign,mPublicPem,type);
}


int HMACSHA1Cryptor::encrypt(const char *src, std::string &dest) {
    return codec_hmac_sha1_encode(src,mKey,dest);
}