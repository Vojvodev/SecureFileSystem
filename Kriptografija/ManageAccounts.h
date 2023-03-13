#pragma once

/*
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif                          // Da se ukinu neka upozorenja
*/

#include <iostream>
#include <fstream>
#include <string>
#include <exception>

#include<openssl/x509.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>
#include <openssl/x509_vfy.h>

using std::string;

// For the CA private key
constexpr auto PASSPHRASE = "sigurnost";

int registrate();

EVP_PKEY* generatePkey();
X509* generateCertificate(EVP_PKEY*, char*, char*);
X509* signRequest(X509**, char*, char*);



bool writePkey(EVP_PKEY*, char*);
bool writeCertificate(X509*, char*);


int login(void);
int logout(void);
