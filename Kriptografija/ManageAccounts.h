#pragma once

/*
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif                          // Da se ukinu neka upozorenja
*/

#include "User.h"

#include <iostream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <fstream>
#include <string>
#include <exception>
#include <cstdint>
#include <cassert>


#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/pem.h>
#include <openssl/x509_vfy.h>



using std::string;





class X509Certificate {

	friend class User;

	public:

		EVP_PKEY* generatePkey();

		// Returns a certficate, param. key 
		X509* generateCertificate(User*);
		
		// Returns the issuer name from a certificate, param. filename
		X509_NAME* readCertIssuerName(const char*);

		// Returns a certificate from a file, param. filename
		X509* loadCertificate(const char*);

		// Returns the private key of a certificate, param. filename
		EVP_PKEY* readCertPrivKey(const char*);

};



// Sve ovo dolje bi moglo u drugi heder fajl...


// Friend to 'User' class
int registrate();

// Friend to 'User' class
int getCredentials(User*);


int login(void);
int logout(void);
