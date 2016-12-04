//
// Created by thinkpad on 2016/11/27.
//

#ifndef CRYPTTEST_CODEC_H
#define CRYPTTEST_CODEC_H

#include "common.h"
#include <string.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/hmac.h>


 int codec_base64_encode(const char *bs,size_t len,std::string& finalDst);//声明 static 又不给定义，肯定找不到
 int codec_base64_decode(const char *cs,size_t decryptedLen,unsigned char* dst);//函数声明时默认带extern，不用显式，也可以
 int calcDecodeLength(const char* b64input);
 int codec_md5_encode(const char *cs,std::string& finalDst);
 int codec_hmac_sha1_encode(const char *cs,const char *key,std::string& finalDst);
 int codec_aes_encrypt(const char *src,char *key,char* dst,size_t encryptedLen);
 int codec_aes_decrypt(const unsigned char *src,size_t len,char *key,std::string& finalDst);
 int codec_rsa_private_sign(const char *src,char *pem,std::string& finalDst);
 int codec_rsa_public_verify(const char *src ,const char *sign,char *pem,int type);
 int codec_rsa_public_encrypt(const char *src,char *pem,int type,std::string& finalDst);
 int codec_rsa_private_decrypt(const char *src,char *pem,std::string& finalDst);
#endif //CRYPTTEST_CODEC_H
