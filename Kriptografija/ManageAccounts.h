#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <exception>

#include<openssl/x509.h>
#include<openssl/rsa.h>
#include<openssl/pem.h>


using std::string;

int registrate();
EVP_PKEY* generatePkey();
X509* generateCertificate(EVP_PKEY*, char*, char*);
bool writePkey(EVP_PKEY*, char*);
bool writeCertificate(X509*, char*);


int login(void);
int logout(void);
