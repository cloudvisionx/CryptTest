//
// Created by thinkpad on 2016/11/27.
//

#include "codec.h"

/**
 * BASE64编码
 *
 */
 int codec_base64_encode(const unsigned char *bs,size_t len ,std::string& finalDst)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);//不换行
    BIO *bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, bs, len);
    BIO_flush(bio);
    BUF_MEM *p;
    BIO_get_mem_ptr(bio, &p);
    int n = p->length;
    char dst[n];
    memcpy(dst, p->data, n);
    dst[n]=0;//这个更简单

    finalDst.assign(dst);//将char*赋予已经定义的string
    BIO_free_all(bio);
    return 1;
}

/*
 * 需自行确保空间足够
 */
void copyVec2array(const vector<unsigned char> &src,unsigned char* a){
    size_t len=src.size();
    auto begin=src.begin();
    auto end=src.end();
    int index=0;
    while(begin!=end){
        a[index]=*begin;
        begin++;
        index++;
    }
}

int codec_base64_encode(const vector<unsigned char> &src,string &dest){
    size_t len=src.size();
    unsigned char tmp[len];
    copyVec2array(src,tmp);
    return codec_base64_encode(tmp,len,dest);
}





int calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
    size_t len = strlen(b64input),
            padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
        padding = 2;
    else if (b64input[len-1] == '=') //last char is =
        padding = 1;

    return (len*3)/4 - padding;
}

/**
 * BASE64解码
 *
 */
 int codec_base64_decode(const char *cs,size_t len,vector<unsigned char> finalDst)
{
    size_t decodedLen=calcDecodeLength(cs);
    unsigned char dst[len];
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO *bio = BIO_new_mem_buf((void *)cs, len);
    bio = BIO_push(b64, bio);
    //int n = BIO_read(bio, dst, len);
    int n = BIO_read(bio, dst, decodedLen);
    BIO_free_all(bio);
    finalDst.insert(finalDst.begin(),dst,dst+decodedLen);
    return 1;
}

/**
 * MD5编码
 *
 */
 int codec_md5_encode(const char *cs,std::string& finalDst)
{
    size_t len=strlen(cs);
    unsigned char bs[16];
    char dst[32];
    MD5((unsigned char *)cs, len, bs);
    for(int i = 0; i < 16; i++) {
        sprintf(dst + i * 2, "%02x", bs[i]);
    }
    finalDst=dst;
    return 1;
}

/**
 * HMAC-SHA1编码
 *
 */
 int codec_hmac_sha1_encode(const char *cs,const char *key,std::string& finalDst)
{
    size_t len=strlen(cs);
    size_t klen=strlen(key);
    unsigned char bs[EVP_MAX_MD_SIZE];
    unsigned int n;

    const EVP_MD *evp = EVP_sha1();
    HMAC(evp, key, klen, (unsigned char *)cs, len, bs, &n);

    int hexn = n * 2;
    char dst[hexn];
    for(int i = 0; i < n; i++) {
        sprintf(dst + i * 2, "%02x", bs[i]);
    }
    finalDst=dst;
    return 1;
}

/**
 * AES-ECB-PKCS5Padding加密
 *
 */
 int codec_aes_encrypt(const char *src,const char *key,vector<unsigned char>& encryptedVec)
{
    size_t len=strlen(src);
    size_t encryptedLen=(len/16 + 1) * 16;
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    int ret = EVP_EncryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, (unsigned char *)key, NULL);
    if(ret != 1)
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        LOGE("EVP encrypt init error");
        return -1;

    }

    int dstn = encryptedLen, n, wn;
    unsigned char* dst=new unsigned char[encryptedLen*2];//分配在堆里，不和栈数据混在一起
    memset(dst, 0, encryptedLen*2);//这里大小千万要注意，要不就清0过头了

    ret = EVP_EncryptUpdate(&ctx, (unsigned char *)dst, &wn, (const unsigned char *)src, len);
    if(ret != 1)
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        LOGE("EVP encrypt update error");
        return -1;
    }
    n = wn;

    ret = EVP_EncryptFinal_ex(&ctx, (unsigned char *)(dst + n), &wn);
    if(ret != 1)
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        LOGE("EVP encrypt final error");
        return -1;
    }

    EVP_CIPHER_CTX_cleanup(&ctx);
    n += wn;
    //dst[encryptedLen]=0;这里不用了，前面都置0了
    encryptedVec.insert(encryptedVec.begin(),dst,dst+n);
    delete[] dst;//删除
    return 1;
}

/**
 * AES-ECB-PKCS5Padding解密
 *
 * LUA示例:
 * local codec = require('codec')
 * local src = [[...]] --BASE64密文
 * local key = [[...]] --16位数字串
 * local bs = codec.base64_decode(src)
 * local dst = codec.aes_decrypt(bs, key)
 */
 int codec_aes_decrypt(vector<unsigned char>& src,size_t len,char *key,std::string& finalDst)
{



    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    int ret = EVP_DecryptInit_ex(&ctx, EVP_aes_128_ecb(), NULL, (unsigned char *)key, NULL);
    if(ret != 1)
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        LOGE("EVP decrypt init error");
        return -1;
    }

    int n, wn;
    char dst[len];
    memset(dst, 0, len);

    ret = EVP_DecryptUpdate(&ctx, (unsigned char *)dst, &wn, (unsigned char *)src, len);
    if(ret != 1)
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        LOGE("EVP decrypt update error");
        return -1;
    }
    n = wn;

    ret = EVP_DecryptFinal_ex(&ctx, (unsigned char *)(dst + n), &wn);
    if(ret != 1)
    {
        EVP_CIPHER_CTX_cleanup(&ctx);
        LOGE("EVP decrypt final error");
        return -1;
    }
    EVP_CIPHER_CTX_cleanup(&ctx);
    n += wn;
    dst[n]=0;
    finalDst.assign(dst);
    return 1;
}

/**
 * SHA1WithRSA私钥签名
 *


 * src = 'something'
 * pem = [[...]] --私钥PEM字符串
 * bs = codec.rsa_private_sign(src, pem)

 */
 int codec_rsa_private_sign(const char *src,char *pem,std::string& finalDst)
{
    size_t len=strlen(src);


    SHA_CTX c;
    unsigned char sha[SHA_DIGEST_LENGTH];
    memset(sha, 0, SHA_DIGEST_LENGTH);
    if(SHA1_Init(&c) != 1)//修改为sha1
    {
        OPENSSL_cleanse(&c, sizeof(c));
        LOGE("SHA init error");
        return -1;
    }
    if(SHA1_Update(&c, src, len) != 1)
    {
        OPENSSL_cleanse(&c, sizeof(c));
        LOGE("SHA update error");
        return -1;
    }
    if(SHA1_Final(sha, &c) != 1)
    {
        OPENSSL_cleanse(&c, sizeof(c));
        LOGE("SHA update error");
        return -1;
    }
    OPENSSL_cleanse(&c, sizeof(c));

    BIO *bio = BIO_new_mem_buf((void *)pem, -1);
    if(bio == NULL)
    {
        BIO_free_all(bio);
        LOGE("PEM error");
        return -1;
    }
    RSA *rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    if(rsa == NULL)
    {
        BIO_free_all(bio);
        LOGE("RSA read private key error");
        return -1;
    }
    BIO_free_all(bio);

    int n = RSA_size(rsa), wn;
    char dst[n];
    memset(dst, 0, n);

    int ret = RSA_sign(NID_sha1, (unsigned char *)sha, SHA_DIGEST_LENGTH, (unsigned char *)dst, (unsigned int *)&wn,
                       rsa);
    if(ret != 1)
    {
        RSA_free(rsa);
        BIO_free_all(bio);
        LOGE("RSA sign error");
        return -1;
    }
    RSA_free(rsa);
    finalDst=dst;
    return 1;
}

/**
 * SHA1WithRSA公钥验签
 *
 * codec = require('codec')
 * src = 'something'
 * sign = [[...]] --BASE64签名
 * bs = codec.base64_decode(sign)
 * pem = [[...]] --公钥PEM字符串
 * type = 1
 * ok = codec.rsa_public_verify(src, bs, pem, type) --true/false
 */
 int codec_rsa_public_verify(const char *src ,const char *sign,char *pem,int type)
{
    size_t srclen=strlen(src);
    size_t signlen=strlen(sign);


    SHA_CTX ctx;
    int ctxlen = sizeof(ctx);
    unsigned char sha[SHA_DIGEST_LENGTH];
    memset(sha, 0, SHA_DIGEST_LENGTH);
    if(SHA1_Init(&ctx) != 1)
    {
        OPENSSL_cleanse(&ctx, ctxlen);
        LOGE("SHA init error");
        return -1;
    }
    if(SHA1_Update(&ctx, src, srclen) != 1)
    {
        OPENSSL_cleanse(&ctx, ctxlen);
        LOGE("SHA update error");
        return -1;
    }
    if(SHA1_Final(sha, &ctx) != 1)
    {
        OPENSSL_cleanse(&ctx, ctxlen);
        LOGE("SHA update error");
        return -1;
    }
    OPENSSL_cleanse(&ctx, ctxlen);

    BIO *bio = BIO_new_mem_buf((void *)pem, -1);
    if(bio == NULL)
    {
        BIO_free_all(bio);
        LOGE("PEM error");
        return -1;
    }
    RSA *rsa = type == 1 ? PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL) : PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if(rsa == NULL)
    {
        BIO_free_all(bio);
        LOGE("RSA read public key error");
        return -1;
    }
    BIO_free_all(bio);

    int ret = RSA_verify(NID_sha1, sha, SHA_DIGEST_LENGTH, (unsigned char *)sign, signlen, rsa);
    RSA_free(rsa);

    return ret;
}

/**
 * RSA公钥加密
 *
    src = 'something'
 * pem = [[...]] --公钥PEM字符串
 * type = 1
 * bs = codec.rsa_public_encrypt(src, pem, type)
 * dst = codec.base64_encode(bs) --BASE64密文
 */
 int codec_rsa_public_encrypt(const char *src,char *pem,int type,std::string& finalDst)
{
    size_t len=strlen(src);


    BIO *bio = BIO_new_mem_buf((void *)pem, -1);
    if(bio == NULL)
    {
        BIO_free_all(bio);
        LOGE("PEM error");
        return -1;
    }
    RSA *rsa = type == 1 ? PEM_read_bio_RSAPublicKey(bio, NULL, NULL, NULL) : PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    if(rsa == NULL)
    {
        BIO_free_all(bio);
        LOGE("RSA read public key error");
        return -1;
    }
    BIO_free_all(bio);

    int n = RSA_size(rsa);
    char dst[n];
    memset(dst, 0, n);

    int ret = RSA_public_encrypt(len, (unsigned char *)src, (unsigned char *)dst, rsa, RSA_PKCS1_PADDING);
    if(ret != n)
    {
        RSA_free(rsa);
        BIO_free_all(bio);
        LOGE("RSA public encrypt error");
        return -1;
    }
    RSA_free(rsa);
    finalDst=dst;
    return 1;
}

/**
 * RSA私钥解密
 *
 *
 * src = [[...]] --BASE64密文
 * bs = codec.base64_decode(src)
 * pem = [[...]] --私钥PEM字符串
 * dst = codec.rsa_private_decrypt(bs, pem)
 */
 int codec_rsa_private_decrypt(const char *src,char *pem,std::string& finalDst)
{


    BIO *bio = BIO_new_mem_buf((void *)pem, -1);
    if(bio == NULL)
    {
        BIO_free_all(bio);
        LOGE("PEM error");
        return -1;
    }
    RSA *rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    if(rsa == NULL)
    {
        BIO_free_all(bio);
        LOGE("RSA read private key error");
        return -1;
    }
    BIO_free_all(bio);

    int n = RSA_size(rsa);
    char dst[n];
    memset(dst, 0, n);

    int ret = RSA_private_decrypt(n, (unsigned char *)src, (unsigned char *)dst, rsa, RSA_PKCS1_PADDING);
    if(ret <= 0)
    {
        RSA_free(rsa);
        BIO_free_all(bio);
        LOGE("RSA private decrypt error");
        return -1;
    }
    RSA_free(rsa);
    finalDst=dst;
    return 1;
}


int vigenere(char* msg,const char* key){
    int lastChar = 0;
    int counter = 0;
    size_t len=strlen(msg);
    for (int i = 0; i < len; i++){
        if (isalpha(msg[i])){
            counter = lastChar % strlen(key);
            // preserve LOWERCASE
            if (islower(msg[i])){
                if (islower(key[counter])){
                    msg[i] = ((msg[i] - 'a' + key[counter] - 97) % 26) + 97;
                }else{
                    msg[i] = ((msg[i] - 'a' + key[counter] - 65) % 26) + 97;
                }
            }

            // preserve UPPERCASE
            if (isupper(msg[i])){
                if (islower(key[lastChar])){
                    msg[i] = ((msg[i] - 'A' + key[counter] - 97) % 26) + 65;
                }else{
                    msg[i] = ((msg[i] - 'A' + key[counter] - 65) % 26) + 65;
                }
            }
            lastChar++;
        }else{
            continue;
        }
    }
    return 0;
}

