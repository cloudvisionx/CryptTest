//
// Created by thinkpad on 2016/11/27.
//

#ifndef CRYPTTEST_CRYPTOR_H
#define CRYPTTEST_CRYPTOR_H

#include "common.h"


class Cryptor {
public:
    virtual  int encrypt(const char* src ,std::string& dest)=0;
    virtual  int decrypt(const char* src ,std::string& dest)=0;
};



class Base64Cryptor: public Cryptor{
public:
    virtual  int encrypt(const char* src ,std::string& dest);
    virtual  int decrypt(const char* src ,std::string& dest);
};



class MD5Cryptor: public Cryptor{
public:
    virtual  int encrypt(const char* src ,std::string& dest);
    virtual  int decrypt(const char* src ,std::string& dest){
        return 1;
    }
};



class HMACSHA1Cryptor: public Cryptor{
public:
    virtual  int encrypt(const char* src ,std::string& dest);
    virtual  int decrypt(const char* src ,std::string& dest){
        return 1;
    }

    HMACSHA1Cryptor( const char* key){//不能简单赋值
        if(key) {
            size_t len = strlen(key);
            mKey = new char[len + 1];
            strcpy(mKey, key);
        }else{
            mKey=new char[1];
            *mKey='\0';
        }
    }

    ~HMACSHA1Cryptor(){
        delete(mKey);
    }
private:
    char* mKey;
};



class AESCryptor: public Cryptor{
public:
    virtual  int encrypt(const char* src ,std::string& dest);
    virtual  int decrypt(const char* src ,std::string& dest);
    AESCryptor(const char* key){
        if(key) {
            size_t len = strlen(key);
            mKey = new char[len + 1];
            strcpy(mKey, key);
        }else{
            mKey=new char[1];
            *mKey='\0';
        }
    }

    ~AESCryptor(){
        delete(mKey);
    }
private:
    char* mKey;
};



class RSACryptor: public Cryptor{
public:
    virtual  int encrypt(const char* src ,std::string& dest);
    virtual  int decrypt(const char* src,std::string& dest);
    int privateSign(const char* src,std::string& dest);
    int public_verify(const char *src ,const char *sign);

    RSACryptor(const char* publicPem,const char* privatePem){
        if(publicPem) {
            size_t len = strlen(publicPem);
            mPublicPem = new char[len + 1];
            strcpy(mPublicPem, publicPem);
        }else{
            mPublicPem=new char[1];
            *mPublicPem='\0';
        }
        if(privatePem) {
            size_t len = strlen(privatePem);
            mPrivatePem = new char[len + 1];
            strcpy(mPrivatePem, privatePem);
        }else{
            mPrivatePem=new char[1];
            *mPrivatePem='\0';
        }
    }

    ~RSACryptor(){
        delete(mPrivatePem);
        delete(mPublicPem);
    }
private:
    char* mPublicPem;
    char* mPrivatePem;
    const int type=1;
};

#endif //CRYPTTEST_CRYPTOR_H
